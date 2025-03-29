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

static const uint8_t DecoderTable16[] = {
/* 0 */       MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 3 */       MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 17
/* 8 */       MCD_OPC_CheckPredicate, 0, 92, 2, 0, // Skip to: 617
/* 13 */      MCD_OPC_Decode, 237, 8, 0, // Opcode: Bimm16
/* 17 */      MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 31
/* 22 */      MCD_OPC_CheckPredicate, 0, 78, 2, 0, // Skip to: 617
/* 27 */      MCD_OPC_Decode, 235, 8, 1, // Opcode: BeqzRxImm16
/* 31 */      MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 45
/* 36 */      MCD_OPC_CheckPredicate, 0, 64, 2, 0, // Skip to: 617
/* 41 */      MCD_OPC_Decode, 239, 8, 1, // Opcode: BnezRxImm16
/* 45 */      MCD_OPC_FilterValue, 9, 9, 0, 0, // Skip to: 59
/* 50 */      MCD_OPC_CheckPredicate, 0, 50, 2, 0, // Skip to: 617
/* 55 */      MCD_OPC_Decode, 138, 7, 2, // Opcode: AddiuRxRxImm16
/* 59 */      MCD_OPC_FilterValue, 10, 9, 0, 0, // Skip to: 73
/* 64 */      MCD_OPC_CheckPredicate, 0, 36, 2, 0, // Skip to: 617
/* 69 */      MCD_OPC_Decode, 195, 23, 3, // Opcode: SltiRxImm16
/* 73 */      MCD_OPC_FilterValue, 11, 9, 0, 0, // Skip to: 87
/* 78 */      MCD_OPC_CheckPredicate, 0, 22, 2, 0, // Skip to: 617
/* 83 */      MCD_OPC_Decode, 197, 23, 3, // Opcode: SltiuRxImm16
/* 87 */      MCD_OPC_FilterValue, 12, 73, 0, 0, // Skip to: 165
/* 92 */      MCD_OPC_ExtractField, 8, 3,  // Inst{10-8} ...
/* 95 */      MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 109
/* 100 */     MCD_OPC_CheckPredicate, 0, 0, 2, 0, // Skip to: 617
/* 105 */     MCD_OPC_Decode, 242, 8, 4, // Opcode: Bteqz16
/* 109 */     MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 123
/* 114 */     MCD_OPC_CheckPredicate, 0, 242, 1, 0, // Skip to: 617
/* 119 */     MCD_OPC_Decode, 244, 8, 4, // Opcode: Btnez16
/* 123 */     MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 137
/* 128 */     MCD_OPC_CheckPredicate, 0, 228, 1, 0, // Skip to: 617
/* 133 */     MCD_OPC_Decode, 141, 7, 4, // Opcode: AddiuSpImm16
/* 137 */     MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 151
/* 142 */     MCD_OPC_CheckPredicate, 0, 214, 1, 0, // Skip to: 617
/* 147 */     MCD_OPC_Decode, 129, 19, 5, // Opcode: Move32R16
/* 151 */     MCD_OPC_FilterValue, 7, 205, 1, 0, // Skip to: 617
/* 156 */     MCD_OPC_CheckPredicate, 0, 200, 1, 0, // Skip to: 617
/* 161 */     MCD_OPC_Decode, 130, 19, 6, // Opcode: MoveR3216
/* 165 */     MCD_OPC_FilterValue, 13, 9, 0, 0, // Skip to: 179
/* 170 */     MCD_OPC_CheckPredicate, 0, 186, 1, 0, // Skip to: 617
/* 175 */     MCD_OPC_Decode, 188, 16, 3, // Opcode: LiRxImm16
/* 179 */     MCD_OPC_FilterValue, 14, 9, 0, 0, // Skip to: 193
/* 184 */     MCD_OPC_CheckPredicate, 0, 172, 1, 0, // Skip to: 617
/* 189 */     MCD_OPC_Decode, 189, 11, 3, // Opcode: CmpiRxImm16
/* 193 */     MCD_OPC_FilterValue, 22, 9, 0, 0, // Skip to: 207
/* 198 */     MCD_OPC_CheckPredicate, 0, 158, 1, 0, // Skip to: 617
/* 203 */     MCD_OPC_Decode, 191, 16, 7, // Opcode: LwRxPcTcp16
/* 207 */     MCD_OPC_FilterValue, 28, 31, 0, 0, // Skip to: 243
/* 212 */     MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 215 */     MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 229
/* 220 */     MCD_OPC_CheckPredicate, 0, 136, 1, 0, // Skip to: 617
/* 225 */     MCD_OPC_Decode, 143, 7, 8, // Opcode: AdduRxRyRz16
/* 229 */     MCD_OPC_FilterValue, 3, 127, 1, 0, // Skip to: 617
/* 234 */     MCD_OPC_CheckPredicate, 0, 122, 1, 0, // Skip to: 617
/* 239 */     MCD_OPC_Decode, 204, 23, 8, // Opcode: SubuRxRyRz16
/* 243 */     MCD_OPC_FilterValue, 29, 113, 1, 0, // Skip to: 617
/* 248 */     MCD_OPC_ExtractField, 0, 5,  // Inst{4-0} ...
/* 251 */     MCD_OPC_FilterValue, 0, 80, 0, 0, // Skip to: 336
/* 256 */     MCD_OPC_ExtractField, 5, 3,  // Inst{7-5} ...
/* 259 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 273
/* 264 */     MCD_OPC_CheckPredicate, 0, 92, 1, 0, // Skip to: 617
/* 269 */     MCD_OPC_Decode, 151, 15, 9, // Opcode: JumpLinkReg16
/* 273 */     MCD_OPC_FilterValue, 1, 16, 0, 0, // Skip to: 294
/* 278 */     MCD_OPC_CheckPredicate, 0, 78, 1, 0, // Skip to: 617
/* 283 */     MCD_OPC_CheckField, 8, 3, 0, 71, 1, 0, // Skip to: 617
/* 290 */     MCD_OPC_Decode, 148, 15, 10, // Opcode: JrRa16
/* 294 */     MCD_OPC_FilterValue, 6, 16, 0, 0, // Skip to: 315
/* 299 */     MCD_OPC_CheckPredicate, 0, 57, 1, 0, // Skip to: 617
/* 304 */     MCD_OPC_CheckField, 8, 3, 0, 50, 1, 0, // Skip to: 617
/* 311 */     MCD_OPC_Decode, 150, 15, 10, // Opcode: JrcRx16
/* 315 */     MCD_OPC_FilterValue, 5, 41, 1, 0, // Skip to: 617
/* 320 */     MCD_OPC_CheckPredicate, 0, 36, 1, 0, // Skip to: 617
/* 325 */     MCD_OPC_CheckField, 8, 3, 0, 29, 1, 0, // Skip to: 617
/* 332 */     MCD_OPC_Decode, 149, 15, 10, // Opcode: JrcRa16
/* 336 */     MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 350
/* 341 */     MCD_OPC_CheckPredicate, 0, 15, 1, 0, // Skip to: 617
/* 346 */     MCD_OPC_Decode, 194, 23, 11, // Opcode: SltRxRy16
/* 350 */     MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 364
/* 355 */     MCD_OPC_CheckPredicate, 0, 1, 1, 0, // Skip to: 617
/* 360 */     MCD_OPC_Decode, 199, 23, 11, // Opcode: SltuRxRy16
/* 364 */     MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 378
/* 369 */     MCD_OPC_CheckPredicate, 0, 243, 0, 0, // Skip to: 617
/* 374 */     MCD_OPC_Decode, 193, 23, 12, // Opcode: SllvRxRy16
/* 378 */     MCD_OPC_FilterValue, 5, 16, 0, 0, // Skip to: 399
/* 383 */     MCD_OPC_CheckPredicate, 0, 229, 0, 0, // Skip to: 617
/* 388 */     MCD_OPC_CheckField, 5, 6, 0, 222, 0, 0, // Skip to: 617
/* 395 */     MCD_OPC_Decode, 241, 8, 10, // Opcode: Break16
/* 399 */     MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 413
/* 404 */     MCD_OPC_CheckPredicate, 0, 208, 0, 0, // Skip to: 617
/* 409 */     MCD_OPC_Decode, 203, 23, 12, // Opcode: SrlvRxRy16
/* 413 */     MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 427
/* 418 */     MCD_OPC_CheckPredicate, 0, 194, 0, 0, // Skip to: 617
/* 423 */     MCD_OPC_Decode, 201, 23, 12, // Opcode: SravRxRy16
/* 427 */     MCD_OPC_FilterValue, 10, 9, 0, 0, // Skip to: 441
/* 432 */     MCD_OPC_CheckPredicate, 0, 180, 0, 0, // Skip to: 617
/* 437 */     MCD_OPC_Decode, 188, 11, 11, // Opcode: CmpRxRy16
/* 441 */     MCD_OPC_FilterValue, 12, 9, 0, 0, // Skip to: 455
/* 446 */     MCD_OPC_CheckPredicate, 0, 166, 0, 0, // Skip to: 617
/* 451 */     MCD_OPC_Decode, 144, 7, 12, // Opcode: AndRxRxRy16
/* 455 */     MCD_OPC_FilterValue, 13, 9, 0, 0, // Skip to: 469
/* 460 */     MCD_OPC_CheckPredicate, 0, 152, 0, 0, // Skip to: 617
/* 465 */     MCD_OPC_Decode, 178, 19, 12, // Opcode: OrRxRxRy16
/* 469 */     MCD_OPC_FilterValue, 14, 9, 0, 0, // Skip to: 483
/* 474 */     MCD_OPC_CheckPredicate, 0, 138, 0, 0, // Skip to: 617
/* 479 */     MCD_OPC_Decode, 187, 24, 12, // Opcode: XorRxRxRy16
/* 483 */     MCD_OPC_FilterValue, 15, 9, 0, 0, // Skip to: 497
/* 488 */     MCD_OPC_CheckPredicate, 0, 124, 0, 0, // Skip to: 617
/* 493 */     MCD_OPC_Decode, 162, 19, 11, // Opcode: NotRxRy16
/* 497 */     MCD_OPC_FilterValue, 16, 16, 0, 0, // Skip to: 518
/* 502 */     MCD_OPC_CheckPredicate, 0, 110, 0, 0, // Skip to: 617
/* 507 */     MCD_OPC_CheckField, 5, 3, 0, 103, 0, 0, // Skip to: 617
/* 514 */     MCD_OPC_Decode, 255, 18, 9, // Opcode: Mfhi16
/* 518 */     MCD_OPC_FilterValue, 17, 31, 0, 0, // Skip to: 554
/* 523 */     MCD_OPC_ExtractField, 5, 3,  // Inst{7-5} ...
/* 526 */     MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 540
/* 531 */     MCD_OPC_CheckPredicate, 0, 81, 0, 0, // Skip to: 617
/* 536 */     MCD_OPC_Decode, 189, 23, 13, // Opcode: SebRx16
/* 540 */     MCD_OPC_FilterValue, 5, 72, 0, 0, // Skip to: 617
/* 545 */     MCD_OPC_CheckPredicate, 0, 67, 0, 0, // Skip to: 617
/* 550 */     MCD_OPC_Decode, 190, 23, 13, // Opcode: SehRx16
/* 554 */     MCD_OPC_FilterValue, 18, 16, 0, 0, // Skip to: 575
/* 559 */     MCD_OPC_CheckPredicate, 0, 53, 0, 0, // Skip to: 617
/* 564 */     MCD_OPC_CheckField, 5, 3, 0, 46, 0, 0, // Skip to: 617
/* 571 */     MCD_OPC_Decode, 128, 19, 9, // Opcode: Mflo16
/* 575 */     MCD_OPC_FilterValue, 26, 9, 0, 0, // Skip to: 589
/* 580 */     MCD_OPC_CheckPredicate, 0, 32, 0, 0, // Skip to: 617
/* 585 */     MCD_OPC_Decode, 204, 12, 11, // Opcode: DivRxRy16
/* 589 */     MCD_OPC_FilterValue, 27, 9, 0, 0, // Skip to: 603
/* 594 */     MCD_OPC_CheckPredicate, 0, 18, 0, 0, // Skip to: 617
/* 599 */     MCD_OPC_Decode, 205, 12, 11, // Opcode: DivuRxRy16
/* 603 */     MCD_OPC_FilterValue, 29, 9, 0, 0, // Skip to: 617
/* 608 */     MCD_OPC_CheckPredicate, 0, 4, 0, 0, // Skip to: 617
/* 613 */     MCD_OPC_Decode, 161, 19, 11, // Opcode: NegRxRy16
/* 617 */     MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTable32[] = {
/* 0 */       MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 3 */       MCD_OPC_FilterValue, 1, 23, 0, 0, // Skip to: 31
/* 8 */       MCD_OPC_CheckPredicate, 0, 2, 2, 0, // Skip to: 527
/* 13 */      MCD_OPC_CheckField, 27, 5, 30, 251, 1, 0, // Skip to: 527
/* 20 */      MCD_OPC_CheckField, 5, 3, 0, 244, 1, 0, // Skip to: 527
/* 27 */      MCD_OPC_Decode, 137, 7, 14, // Opcode: AddiuRxPcImmX16
/* 31 */      MCD_OPC_FilterValue, 2, 23, 0, 0, // Skip to: 59
/* 36 */      MCD_OPC_CheckPredicate, 0, 230, 1, 0, // Skip to: 527
/* 41 */      MCD_OPC_CheckField, 27, 5, 30, 223, 1, 0, // Skip to: 527
/* 48 */      MCD_OPC_CheckField, 5, 6, 0, 216, 1, 0, // Skip to: 527
/* 55 */      MCD_OPC_Decode, 238, 8, 15, // Opcode: BimmX16
/* 59 */      MCD_OPC_FilterValue, 4, 23, 0, 0, // Skip to: 87
/* 64 */      MCD_OPC_CheckPredicate, 0, 202, 1, 0, // Skip to: 527
/* 69 */      MCD_OPC_CheckField, 27, 5, 30, 195, 1, 0, // Skip to: 527
/* 76 */      MCD_OPC_CheckField, 5, 3, 0, 188, 1, 0, // Skip to: 527
/* 83 */      MCD_OPC_Decode, 236, 8, 16, // Opcode: BeqzRxImmX16
/* 87 */      MCD_OPC_FilterValue, 5, 23, 0, 0, // Skip to: 115
/* 92 */      MCD_OPC_CheckPredicate, 0, 174, 1, 0, // Skip to: 527
/* 97 */      MCD_OPC_CheckField, 27, 5, 30, 167, 1, 0, // Skip to: 527
/* 104 */     MCD_OPC_CheckField, 5, 3, 0, 160, 1, 0, // Skip to: 527
/* 111 */     MCD_OPC_Decode, 240, 8, 16, // Opcode: BnezRxImmX16
/* 115 */     MCD_OPC_FilterValue, 12, 106, 0, 0, // Skip to: 226
/* 120 */     MCD_OPC_ExtractField, 27, 5,  // Inst{31-27} ...
/* 123 */     MCD_OPC_FilterValue, 30, 143, 1, 0, // Skip to: 527
/* 128 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 131 */     MCD_OPC_FilterValue, 0, 45, 0, 0, // Skip to: 181
/* 136 */     MCD_OPC_ExtractField, 0, 5,  // Inst{4-0} ...
/* 139 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 153
/* 144 */     MCD_OPC_CheckPredicate, 0, 32, 0, 0, // Skip to: 181
/* 149 */     MCD_OPC_Decode, 192, 23, 17, // Opcode: SllX16
/* 153 */     MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 167
/* 158 */     MCD_OPC_CheckPredicate, 0, 18, 0, 0, // Skip to: 181
/* 163 */     MCD_OPC_Decode, 202, 23, 17, // Opcode: SrlX16
/* 167 */     MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 181
/* 172 */     MCD_OPC_CheckPredicate, 0, 4, 0, 0, // Skip to: 181
/* 177 */     MCD_OPC_Decode, 200, 23, 17, // Opcode: SraX16
/* 181 */     MCD_OPC_ExtractField, 5, 6,  // Inst{10-5} ...
/* 184 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 198
/* 189 */     MCD_OPC_CheckPredicate, 0, 77, 1, 0, // Skip to: 527
/* 194 */     MCD_OPC_Decode, 243, 8, 18, // Opcode: BteqzX16
/* 198 */     MCD_OPC_FilterValue, 8, 9, 0, 0, // Skip to: 212
/* 203 */     MCD_OPC_CheckPredicate, 0, 63, 1, 0, // Skip to: 527
/* 208 */     MCD_OPC_Decode, 245, 8, 18, // Opcode: BtnezX16
/* 212 */     MCD_OPC_FilterValue, 24, 54, 1, 0, // Skip to: 527
/* 217 */     MCD_OPC_CheckPredicate, 0, 49, 1, 0, // Skip to: 527
/* 222 */     MCD_OPC_Decode, 142, 7, 18, // Opcode: AddiuSpImmX16
/* 226 */     MCD_OPC_FilterValue, 8, 23, 0, 0, // Skip to: 254
/* 231 */     MCD_OPC_CheckPredicate, 0, 35, 1, 0, // Skip to: 527
/* 236 */     MCD_OPC_CheckField, 27, 5, 30, 28, 1, 0, // Skip to: 527
/* 243 */     MCD_OPC_CheckField, 4, 1, 0, 21, 1, 0, // Skip to: 527
/* 250 */     MCD_OPC_Decode, 140, 7, 19, // Opcode: AddiuRxRyOffMemX16
/* 254 */     MCD_OPC_FilterValue, 9, 23, 0, 0, // Skip to: 282
/* 259 */     MCD_OPC_CheckPredicate, 0, 7, 1, 0, // Skip to: 527
/* 264 */     MCD_OPC_CheckField, 27, 5, 30, 0, 1, 0, // Skip to: 527
/* 271 */     MCD_OPC_CheckField, 5, 3, 0, 249, 0, 0, // Skip to: 527
/* 278 */     MCD_OPC_Decode, 136, 7, 14, // Opcode: AddiuRxImmX16
/* 282 */     MCD_OPC_FilterValue, 10, 23, 0, 0, // Skip to: 310
/* 287 */     MCD_OPC_CheckPredicate, 0, 235, 0, 0, // Skip to: 527
/* 292 */     MCD_OPC_CheckField, 27, 5, 30, 228, 0, 0, // Skip to: 527
/* 299 */     MCD_OPC_CheckField, 5, 3, 0, 221, 0, 0, // Skip to: 527
/* 306 */     MCD_OPC_Decode, 196, 23, 14, // Opcode: SltiRxImmX16
/* 310 */     MCD_OPC_FilterValue, 11, 23, 0, 0, // Skip to: 338
/* 315 */     MCD_OPC_CheckPredicate, 0, 207, 0, 0, // Skip to: 527
/* 320 */     MCD_OPC_CheckField, 27, 5, 30, 200, 0, 0, // Skip to: 527
/* 327 */     MCD_OPC_CheckField, 5, 3, 0, 193, 0, 0, // Skip to: 527
/* 334 */     MCD_OPC_Decode, 198, 23, 14, // Opcode: SltiuRxImmX16
/* 338 */     MCD_OPC_FilterValue, 13, 23, 0, 0, // Skip to: 366
/* 343 */     MCD_OPC_CheckPredicate, 0, 179, 0, 0, // Skip to: 527
/* 348 */     MCD_OPC_CheckField, 27, 5, 30, 172, 0, 0, // Skip to: 527
/* 355 */     MCD_OPC_CheckField, 5, 3, 0, 165, 0, 0, // Skip to: 527
/* 362 */     MCD_OPC_Decode, 190, 16, 14, // Opcode: LiRxImmX16
/* 366 */     MCD_OPC_FilterValue, 14, 23, 0, 0, // Skip to: 394
/* 371 */     MCD_OPC_CheckPredicate, 0, 151, 0, 0, // Skip to: 527
/* 376 */     MCD_OPC_CheckField, 27, 5, 30, 144, 0, 0, // Skip to: 527
/* 383 */     MCD_OPC_CheckField, 5, 3, 0, 137, 0, 0, // Skip to: 527
/* 390 */     MCD_OPC_Decode, 190, 11, 14, // Opcode: CmpiRxImmX16
/* 394 */     MCD_OPC_FilterValue, 18, 16, 0, 0, // Skip to: 415
/* 399 */     MCD_OPC_CheckPredicate, 0, 123, 0, 0, // Skip to: 527
/* 404 */     MCD_OPC_CheckField, 27, 5, 30, 116, 0, 0, // Skip to: 527
/* 411 */     MCD_OPC_Decode, 194, 16, 19, // Opcode: LwRxSpImmX16
/* 415 */     MCD_OPC_FilterValue, 22, 23, 0, 0, // Skip to: 443
/* 420 */     MCD_OPC_CheckPredicate, 0, 102, 0, 0, // Skip to: 527
/* 425 */     MCD_OPC_CheckField, 27, 5, 30, 95, 0, 0, // Skip to: 527
/* 432 */     MCD_OPC_CheckField, 5, 3, 0, 88, 0, 0, // Skip to: 527
/* 439 */     MCD_OPC_Decode, 192, 16, 20, // Opcode: LwRxPcTcpX16
/* 443 */     MCD_OPC_FilterValue, 24, 16, 0, 0, // Skip to: 464
/* 448 */     MCD_OPC_CheckPredicate, 0, 74, 0, 0, // Skip to: 527
/* 453 */     MCD_OPC_CheckField, 27, 5, 30, 67, 0, 0, // Skip to: 527
/* 460 */     MCD_OPC_Decode, 188, 23, 19, // Opcode: SbRxRyOffMemX16
/* 464 */     MCD_OPC_FilterValue, 25, 16, 0, 0, // Skip to: 485
/* 469 */     MCD_OPC_CheckPredicate, 0, 53, 0, 0, // Skip to: 527
/* 474 */     MCD_OPC_CheckField, 27, 5, 30, 46, 0, 0, // Skip to: 527
/* 481 */     MCD_OPC_Decode, 191, 23, 19, // Opcode: ShRxRyOffMemX16
/* 485 */     MCD_OPC_FilterValue, 26, 16, 0, 0, // Skip to: 506
/* 490 */     MCD_OPC_CheckPredicate, 0, 32, 0, 0, // Skip to: 527
/* 495 */     MCD_OPC_CheckField, 27, 5, 30, 25, 0, 0, // Skip to: 527
/* 502 */     MCD_OPC_Decode, 206, 23, 19, // Opcode: SwRxSpImmX16
/* 506 */     MCD_OPC_FilterValue, 27, 16, 0, 0, // Skip to: 527
/* 511 */     MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 527
/* 516 */     MCD_OPC_CheckField, 27, 5, 30, 4, 0, 0, // Skip to: 527
/* 523 */     MCD_OPC_Decode, 205, 23, 19, // Opcode: SwRxRyOffMemX16
/* 527 */     MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableCOP3_32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 51, 9, 0, 0, // Skip to: 17
/* 8 */       MCD_OPC_CheckPredicate, 1, 46, 0, 0, // Skip to: 59
/* 13 */      MCD_OPC_Decode, 141, 16, 21, // Opcode: LWC3
/* 17 */      MCD_OPC_FilterValue, 55, 9, 0, 0, // Skip to: 31
/* 22 */      MCD_OPC_CheckPredicate, 2, 32, 0, 0, // Skip to: 59
/* 27 */      MCD_OPC_Decode, 188, 15, 21, // Opcode: LDC3
/* 31 */      MCD_OPC_FilterValue, 59, 9, 0, 0, // Skip to: 45
/* 36 */      MCD_OPC_CheckPredicate, 1, 18, 0, 0, // Skip to: 59
/* 41 */      MCD_OPC_Decode, 139, 23, 21, // Opcode: SWC3
/* 45 */      MCD_OPC_FilterValue, 63, 9, 0, 0, // Skip to: 59
/* 50 */      MCD_OPC_CheckPredicate, 2, 4, 0, 0, // Skip to: 59
/* 55 */      MCD_OPC_Decode, 235, 20, 21, // Opcode: SDC3
/* 59 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableCnMips32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 18, 31, 0, 0, // Skip to: 39
/* 8 */       MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 11 */      MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 25
/* 16 */      MCD_OPC_CheckPredicate, 3, 239, 1, 0, // Skip to: 516
/* 21 */      MCD_OPC_Decode, 240, 11, 22, // Opcode: DMFC2_OCTEON
/* 25 */      MCD_OPC_FilterValue, 5, 230, 1, 0, // Skip to: 516
/* 30 */      MCD_OPC_CheckPredicate, 3, 225, 1, 0, // Skip to: 516
/* 35 */      MCD_OPC_Decode, 248, 11, 22, // Opcode: DMTC2_OCTEON
/* 39 */      MCD_OPC_FilterValue, 28, 160, 1, 0, // Skip to: 460
/* 44 */      MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 47 */      MCD_OPC_FilterValue, 3, 16, 0, 0, // Skip to: 68
/* 52 */      MCD_OPC_CheckPredicate, 3, 203, 1, 0, // Skip to: 516
/* 57 */      MCD_OPC_CheckField, 6, 5, 0, 196, 1, 0, // Skip to: 516
/* 64 */      MCD_OPC_Decode, 253, 11, 23, // Opcode: DMUL
/* 68 */      MCD_OPC_FilterValue, 8, 16, 0, 0, // Skip to: 89
/* 73 */      MCD_OPC_CheckPredicate, 3, 182, 1, 0, // Skip to: 516
/* 78 */      MCD_OPC_CheckField, 6, 15, 0, 175, 1, 0, // Skip to: 516
/* 85 */      MCD_OPC_Decode, 191, 18, 24, // Opcode: MTM0
/* 89 */      MCD_OPC_FilterValue, 9, 16, 0, 0, // Skip to: 110
/* 94 */      MCD_OPC_CheckPredicate, 3, 161, 1, 0, // Skip to: 516
/* 99 */      MCD_OPC_CheckField, 6, 15, 0, 154, 1, 0, // Skip to: 516
/* 106 */     MCD_OPC_Decode, 194, 18, 24, // Opcode: MTP0
/* 110 */     MCD_OPC_FilterValue, 10, 16, 0, 0, // Skip to: 131
/* 115 */     MCD_OPC_CheckPredicate, 3, 140, 1, 0, // Skip to: 516
/* 120 */     MCD_OPC_CheckField, 6, 15, 0, 133, 1, 0, // Skip to: 516
/* 127 */     MCD_OPC_Decode, 195, 18, 24, // Opcode: MTP1
/* 131 */     MCD_OPC_FilterValue, 11, 16, 0, 0, // Skip to: 152
/* 136 */     MCD_OPC_CheckPredicate, 3, 119, 1, 0, // Skip to: 516
/* 141 */     MCD_OPC_CheckField, 6, 15, 0, 112, 1, 0, // Skip to: 516
/* 148 */     MCD_OPC_Decode, 196, 18, 24, // Opcode: MTP2
/* 152 */     MCD_OPC_FilterValue, 12, 16, 0, 0, // Skip to: 173
/* 157 */     MCD_OPC_CheckPredicate, 3, 98, 1, 0, // Skip to: 516
/* 162 */     MCD_OPC_CheckField, 6, 15, 0, 91, 1, 0, // Skip to: 516
/* 169 */     MCD_OPC_Decode, 192, 18, 24, // Opcode: MTM1
/* 173 */     MCD_OPC_FilterValue, 13, 16, 0, 0, // Skip to: 194
/* 178 */     MCD_OPC_CheckPredicate, 3, 77, 1, 0, // Skip to: 516
/* 183 */     MCD_OPC_CheckField, 6, 15, 0, 70, 1, 0, // Skip to: 516
/* 190 */     MCD_OPC_Decode, 193, 18, 24, // Opcode: MTM2
/* 194 */     MCD_OPC_FilterValue, 15, 16, 0, 0, // Skip to: 215
/* 199 */     MCD_OPC_CheckPredicate, 3, 56, 1, 0, // Skip to: 516
/* 204 */     MCD_OPC_CheckField, 6, 5, 0, 49, 1, 0, // Skip to: 516
/* 211 */     MCD_OPC_Decode, 156, 24, 23, // Opcode: VMULU
/* 215 */     MCD_OPC_FilterValue, 16, 16, 0, 0, // Skip to: 236
/* 220 */     MCD_OPC_CheckPredicate, 3, 35, 1, 0, // Skip to: 516
/* 225 */     MCD_OPC_CheckField, 6, 5, 0, 28, 1, 0, // Skip to: 516
/* 232 */     MCD_OPC_Decode, 155, 24, 23, // Opcode: VMM0
/* 236 */     MCD_OPC_FilterValue, 17, 16, 0, 0, // Skip to: 257
/* 241 */     MCD_OPC_CheckPredicate, 3, 14, 1, 0, // Skip to: 516
/* 246 */     MCD_OPC_CheckField, 6, 5, 0, 7, 1, 0, // Skip to: 516
/* 253 */     MCD_OPC_Decode, 154, 24, 23, // Opcode: V3MULU
/* 257 */     MCD_OPC_FilterValue, 40, 16, 0, 0, // Skip to: 278
/* 262 */     MCD_OPC_CheckPredicate, 3, 249, 0, 0, // Skip to: 516
/* 267 */     MCD_OPC_CheckField, 6, 5, 0, 242, 0, 0, // Skip to: 516
/* 274 */     MCD_OPC_Decode, 146, 7, 23, // Opcode: BADDu
/* 278 */     MCD_OPC_FilterValue, 42, 16, 0, 0, // Skip to: 299
/* 283 */     MCD_OPC_CheckPredicate, 3, 228, 0, 0, // Skip to: 516
/* 288 */     MCD_OPC_CheckField, 6, 5, 0, 221, 0, 0, // Skip to: 516
/* 295 */     MCD_OPC_Decode, 140, 21, 23, // Opcode: SEQ
/* 299 */     MCD_OPC_FilterValue, 43, 16, 0, 0, // Skip to: 320
/* 304 */     MCD_OPC_CheckPredicate, 3, 207, 0, 0, // Skip to: 516
/* 309 */     MCD_OPC_CheckField, 6, 5, 0, 200, 0, 0, // Skip to: 516
/* 316 */     MCD_OPC_Decode, 255, 21, 23, // Opcode: SNE
/* 320 */     MCD_OPC_FilterValue, 44, 23, 0, 0, // Skip to: 348
/* 325 */     MCD_OPC_CheckPredicate, 3, 186, 0, 0, // Skip to: 516
/* 330 */     MCD_OPC_CheckField, 16, 5, 0, 179, 0, 0, // Skip to: 516
/* 337 */     MCD_OPC_CheckField, 6, 5, 0, 172, 0, 0, // Skip to: 516
/* 344 */     MCD_OPC_Decode, 203, 19, 25, // Opcode: POP
/* 348 */     MCD_OPC_FilterValue, 45, 23, 0, 0, // Skip to: 376
/* 353 */     MCD_OPC_CheckPredicate, 3, 158, 0, 0, // Skip to: 516
/* 358 */     MCD_OPC_CheckField, 16, 5, 0, 151, 0, 0, // Skip to: 516
/* 365 */     MCD_OPC_CheckField, 6, 5, 0, 144, 0, 0, // Skip to: 516
/* 372 */     MCD_OPC_Decode, 158, 12, 26, // Opcode: DPOP
/* 376 */     MCD_OPC_FilterValue, 46, 9, 0, 0, // Skip to: 390
/* 381 */     MCD_OPC_CheckPredicate, 3, 130, 0, 0, // Skip to: 516
/* 386 */     MCD_OPC_Decode, 142, 21, 27, // Opcode: SEQi
/* 390 */     MCD_OPC_FilterValue, 47, 9, 0, 0, // Skip to: 404
/* 395 */     MCD_OPC_CheckPredicate, 3, 116, 0, 0, // Skip to: 516
/* 400 */     MCD_OPC_Decode, 128, 22, 27, // Opcode: SNEi
/* 404 */     MCD_OPC_FilterValue, 50, 9, 0, 0, // Skip to: 418
/* 409 */     MCD_OPC_CheckPredicate, 4, 102, 0, 0, // Skip to: 516
/* 414 */     MCD_OPC_Decode, 148, 9, 28, // Opcode: CINS
/* 418 */     MCD_OPC_FilterValue, 51, 9, 0, 0, // Skip to: 432
/* 423 */     MCD_OPC_CheckPredicate, 4, 88, 0, 0, // Skip to: 516
/* 428 */     MCD_OPC_Decode, 149, 9, 28, // Opcode: CINS32
/* 432 */     MCD_OPC_FilterValue, 58, 9, 0, 0, // Skip to: 446
/* 437 */     MCD_OPC_CheckPredicate, 4, 74, 0, 0, // Skip to: 516
/* 442 */     MCD_OPC_Decode, 252, 12, 28, // Opcode: EXTS
/* 446 */     MCD_OPC_FilterValue, 59, 65, 0, 0, // Skip to: 516
/* 451 */     MCD_OPC_CheckPredicate, 4, 60, 0, 0, // Skip to: 516
/* 456 */     MCD_OPC_Decode, 253, 12, 28, // Opcode: EXTS32
/* 460 */     MCD_OPC_FilterValue, 50, 9, 0, 0, // Skip to: 474
/* 465 */     MCD_OPC_CheckPredicate, 3, 46, 0, 0, // Skip to: 516
/* 470 */     MCD_OPC_Decode, 156, 7, 29, // Opcode: BBIT0
/* 474 */     MCD_OPC_FilterValue, 54, 9, 0, 0, // Skip to: 488
/* 479 */     MCD_OPC_CheckPredicate, 3, 32, 0, 0, // Skip to: 516
/* 484 */     MCD_OPC_Decode, 157, 7, 29, // Opcode: BBIT032
/* 488 */     MCD_OPC_FilterValue, 58, 9, 0, 0, // Skip to: 502
/* 493 */     MCD_OPC_CheckPredicate, 3, 18, 0, 0, // Skip to: 516
/* 498 */     MCD_OPC_Decode, 158, 7, 29, // Opcode: BBIT1
/* 502 */     MCD_OPC_FilterValue, 62, 9, 0, 0, // Skip to: 516
/* 507 */     MCD_OPC_CheckPredicate, 3, 4, 0, 0, // Skip to: 516
/* 512 */     MCD_OPC_Decode, 159, 7, 29, // Opcode: BBIT132
/* 516 */     MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableCnMipsP32[] = {
/* 0 */       MCD_OPC_ExtractField, 0, 16,  // Inst{15-0} ...
/* 3 */       MCD_OPC_FilterValue, 24, 16, 0, 0, // Skip to: 24
/* 8 */       MCD_OPC_CheckPredicate, 5, 32, 0, 0, // Skip to: 45
/* 13 */      MCD_OPC_CheckField, 26, 6, 28, 25, 0, 0, // Skip to: 45
/* 20 */      MCD_OPC_Decode, 181, 20, 30, // Opcode: SAA
/* 24 */      MCD_OPC_FilterValue, 25, 16, 0, 0, // Skip to: 45
/* 29 */      MCD_OPC_CheckPredicate, 5, 11, 0, 0, // Skip to: 45
/* 34 */      MCD_OPC_CheckField, 26, 6, 28, 4, 0, 0, // Skip to: 45
/* 41 */      MCD_OPC_Decode, 182, 20, 30, // Opcode: SAAD
/* 45 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMicroMips16[] = {
/* 0 */       MCD_OPC_ExtractField, 10, 6,  // Inst{15-10} ...
/* 3 */       MCD_OPC_FilterValue, 1, 31, 0, 0, // Skip to: 39
/* 8 */       MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 11 */      MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 25
/* 16 */      MCD_OPC_CheckPredicate, 6, 114, 2, 0, // Skip to: 647
/* 21 */      MCD_OPC_Decode, 170, 6, 31, // Opcode: ADDU16_MM
/* 25 */      MCD_OPC_FilterValue, 1, 105, 2, 0, // Skip to: 647
/* 30 */      MCD_OPC_CheckPredicate, 6, 100, 2, 0, // Skip to: 647
/* 35 */      MCD_OPC_Decode, 223, 22, 31, // Opcode: SUBU16_MM
/* 39 */      MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 53
/* 44 */      MCD_OPC_CheckPredicate, 7, 86, 2, 0, // Skip to: 647
/* 49 */      MCD_OPC_Decode, 160, 15, 32, // Opcode: LBU16_MM
/* 53 */      MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 67
/* 58 */      MCD_OPC_CheckPredicate, 6, 72, 2, 0, // Skip to: 647
/* 63 */      MCD_OPC_Decode, 208, 17, 33, // Opcode: MOVE16_MM
/* 67 */      MCD_OPC_FilterValue, 9, 31, 0, 0, // Skip to: 103
/* 72 */      MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 75 */      MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 89
/* 80 */      MCD_OPC_CheckPredicate, 6, 50, 2, 0, // Skip to: 647
/* 85 */      MCD_OPC_Decode, 220, 21, 34, // Opcode: SLL16_MM
/* 89 */      MCD_OPC_FilterValue, 1, 41, 2, 0, // Skip to: 647
/* 94 */      MCD_OPC_CheckPredicate, 6, 36, 2, 0, // Skip to: 647
/* 99 */      MCD_OPC_Decode, 161, 22, 34, // Opcode: SRL16_MM
/* 103 */     MCD_OPC_FilterValue, 10, 9, 0, 0, // Skip to: 117
/* 108 */     MCD_OPC_CheckPredicate, 7, 22, 2, 0, // Skip to: 647
/* 113 */     MCD_OPC_Decode, 212, 15, 32, // Opcode: LHU16_MM
/* 117 */     MCD_OPC_FilterValue, 11, 9, 0, 0, // Skip to: 131
/* 122 */     MCD_OPC_CheckPredicate, 6, 8, 2, 0, // Skip to: 647
/* 127 */     MCD_OPC_Decode, 221, 6, 35, // Opcode: ANDI16_MM
/* 131 */     MCD_OPC_FilterValue, 17, 8, 1, 0, // Skip to: 400
/* 136 */     MCD_OPC_ExtractField, 6, 4,  // Inst{9-6} ...
/* 139 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 153
/* 144 */     MCD_OPC_CheckPredicate, 6, 242, 1, 0, // Skip to: 647
/* 149 */     MCD_OPC_Decode, 158, 19, 36, // Opcode: NOT16_MM
/* 153 */     MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 167
/* 158 */     MCD_OPC_CheckPredicate, 6, 228, 1, 0, // Skip to: 647
/* 163 */     MCD_OPC_Decode, 173, 24, 37, // Opcode: XOR16_MM
/* 167 */     MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 181
/* 172 */     MCD_OPC_CheckPredicate, 6, 214, 1, 0, // Skip to: 647
/* 177 */     MCD_OPC_Decode, 217, 6, 37, // Opcode: AND16_MM
/* 181 */     MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 195
/* 186 */     MCD_OPC_CheckPredicate, 6, 200, 1, 0, // Skip to: 647
/* 191 */     MCD_OPC_Decode, 164, 19, 37, // Opcode: OR16_MM
/* 195 */     MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 209
/* 200 */     MCD_OPC_CheckPredicate, 6, 186, 1, 0, // Skip to: 647
/* 205 */     MCD_OPC_Decode, 154, 16, 38, // Opcode: LWM16_MM
/* 209 */     MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 223
/* 214 */     MCD_OPC_CheckPredicate, 6, 172, 1, 0, // Skip to: 647
/* 219 */     MCD_OPC_Decode, 151, 23, 38, // Opcode: SWM16_MM
/* 223 */     MCD_OPC_FilterValue, 6, 31, 0, 0, // Skip to: 259
/* 228 */     MCD_OPC_ExtractField, 5, 1,  // Inst{5} ...
/* 231 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 245
/* 236 */     MCD_OPC_CheckPredicate, 6, 150, 1, 0, // Skip to: 647
/* 241 */     MCD_OPC_Decode, 133, 15, 39, // Opcode: JR16_MM
/* 245 */     MCD_OPC_FilterValue, 1, 141, 1, 0, // Skip to: 647
/* 250 */     MCD_OPC_CheckPredicate, 6, 136, 1, 0, // Skip to: 647
/* 255 */     MCD_OPC_Decode, 136, 15, 39, // Opcode: JRC16_MM
/* 259 */     MCD_OPC_FilterValue, 7, 31, 0, 0, // Skip to: 295
/* 264 */     MCD_OPC_ExtractField, 5, 1,  // Inst{5} ...
/* 267 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 281
/* 272 */     MCD_OPC_CheckPredicate, 6, 114, 1, 0, // Skip to: 647
/* 277 */     MCD_OPC_Decode, 237, 14, 39, // Opcode: JALR16_MM
/* 281 */     MCD_OPC_FilterValue, 1, 105, 1, 0, // Skip to: 647
/* 286 */     MCD_OPC_CheckPredicate, 6, 100, 1, 0, // Skip to: 647
/* 291 */     MCD_OPC_Decode, 245, 14, 39, // Opcode: JALRS16_MM
/* 295 */     MCD_OPC_FilterValue, 8, 16, 0, 0, // Skip to: 316
/* 300 */     MCD_OPC_CheckPredicate, 6, 86, 1, 0, // Skip to: 647
/* 305 */     MCD_OPC_CheckField, 5, 1, 0, 79, 1, 0, // Skip to: 647
/* 312 */     MCD_OPC_Decode, 151, 17, 39, // Opcode: MFHI16_MM
/* 316 */     MCD_OPC_FilterValue, 9, 16, 0, 0, // Skip to: 337
/* 321 */     MCD_OPC_CheckPredicate, 6, 65, 1, 0, // Skip to: 647
/* 326 */     MCD_OPC_CheckField, 5, 1, 0, 58, 1, 0, // Skip to: 647
/* 333 */     MCD_OPC_Decode, 157, 17, 39, // Opcode: MFLO16_MM
/* 337 */     MCD_OPC_FilterValue, 10, 16, 0, 0, // Skip to: 358
/* 342 */     MCD_OPC_CheckPredicate, 6, 44, 1, 0, // Skip to: 647
/* 347 */     MCD_OPC_CheckField, 4, 2, 0, 37, 1, 0, // Skip to: 647
/* 354 */     MCD_OPC_Decode, 212, 8, 40, // Opcode: BREAK16_MM
/* 358 */     MCD_OPC_FilterValue, 11, 16, 0, 0, // Skip to: 379
/* 363 */     MCD_OPC_CheckPredicate, 6, 23, 1, 0, // Skip to: 647
/* 368 */     MCD_OPC_CheckField, 4, 2, 0, 16, 1, 0, // Skip to: 647
/* 375 */     MCD_OPC_Decode, 220, 20, 40, // Opcode: SDBBP16_MM
/* 379 */     MCD_OPC_FilterValue, 12, 7, 1, 0, // Skip to: 647
/* 384 */     MCD_OPC_CheckPredicate, 6, 2, 1, 0, // Skip to: 647
/* 389 */     MCD_OPC_CheckField, 5, 1, 0, 251, 0, 0, // Skip to: 647
/* 396 */     MCD_OPC_Decode, 135, 15, 41, // Opcode: JRADDIUSP
/* 400 */     MCD_OPC_FilterValue, 18, 9, 0, 0, // Skip to: 414
/* 405 */     MCD_OPC_CheckPredicate, 7, 237, 0, 0, // Skip to: 647
/* 410 */     MCD_OPC_Decode, 168, 16, 42, // Opcode: LWSP_MM
/* 414 */     MCD_OPC_FilterValue, 19, 31, 0, 0, // Skip to: 450
/* 419 */     MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 422 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 436
/* 427 */     MCD_OPC_CheckPredicate, 7, 215, 0, 0, // Skip to: 647
/* 432 */     MCD_OPC_Decode, 137, 6, 43, // Opcode: ADDIUS5_MM
/* 436 */     MCD_OPC_FilterValue, 1, 206, 0, 0, // Skip to: 647
/* 441 */     MCD_OPC_CheckPredicate, 7, 201, 0, 0, // Skip to: 647
/* 446 */     MCD_OPC_Decode, 138, 6, 44, // Opcode: ADDIUSP_MM
/* 450 */     MCD_OPC_FilterValue, 25, 9, 0, 0, // Skip to: 464
/* 455 */     MCD_OPC_CheckPredicate, 7, 187, 0, 0, // Skip to: 647
/* 460 */     MCD_OPC_Decode, 147, 16, 45, // Opcode: LWGP_MM
/* 464 */     MCD_OPC_FilterValue, 26, 9, 0, 0, // Skip to: 478
/* 469 */     MCD_OPC_CheckPredicate, 7, 173, 0, 0, // Skip to: 647
/* 474 */     MCD_OPC_Decode, 132, 16, 32, // Opcode: LW16_MM
/* 478 */     MCD_OPC_FilterValue, 27, 31, 0, 0, // Skip to: 514
/* 483 */     MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 486 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 500
/* 491 */     MCD_OPC_CheckPredicate, 7, 151, 0, 0, // Skip to: 647
/* 496 */     MCD_OPC_Decode, 134, 6, 46, // Opcode: ADDIUR2_MM
/* 500 */     MCD_OPC_FilterValue, 1, 142, 0, 0, // Skip to: 647
/* 505 */     MCD_OPC_CheckPredicate, 7, 137, 0, 0, // Skip to: 647
/* 510 */     MCD_OPC_Decode, 132, 6, 47, // Opcode: ADDIUR1SP_MM
/* 514 */     MCD_OPC_FilterValue, 33, 16, 0, 0, // Skip to: 535
/* 519 */     MCD_OPC_CheckPredicate, 6, 123, 0, 0, // Skip to: 647
/* 524 */     MCD_OPC_CheckField, 0, 1, 0, 116, 0, 0, // Skip to: 647
/* 531 */     MCD_OPC_Decode, 212, 17, 48, // Opcode: MOVEP_MM
/* 535 */     MCD_OPC_FilterValue, 34, 9, 0, 0, // Skip to: 549
/* 540 */     MCD_OPC_CheckPredicate, 6, 102, 0, 0, // Skip to: 647
/* 545 */     MCD_OPC_Decode, 194, 20, 32, // Opcode: SB16_MM
/* 549 */     MCD_OPC_FilterValue, 35, 9, 0, 0, // Skip to: 563
/* 554 */     MCD_OPC_CheckPredicate, 6, 88, 0, 0, // Skip to: 647
/* 559 */     MCD_OPC_Decode, 198, 7, 49, // Opcode: BEQZ16_MM
/* 563 */     MCD_OPC_FilterValue, 42, 9, 0, 0, // Skip to: 577
/* 568 */     MCD_OPC_CheckPredicate, 6, 74, 0, 0, // Skip to: 647
/* 573 */     MCD_OPC_Decode, 144, 21, 32, // Opcode: SH16_MM
/* 577 */     MCD_OPC_FilterValue, 43, 9, 0, 0, // Skip to: 591
/* 582 */     MCD_OPC_CheckPredicate, 6, 60, 0, 0, // Skip to: 647
/* 587 */     MCD_OPC_Decode, 188, 8, 49, // Opcode: BNEZ16_MM
/* 591 */     MCD_OPC_FilterValue, 50, 9, 0, 0, // Skip to: 605
/* 596 */     MCD_OPC_CheckPredicate, 6, 46, 0, 0, // Skip to: 647
/* 601 */     MCD_OPC_Decode, 163, 23, 42, // Opcode: SWSP_MM
/* 605 */     MCD_OPC_FilterValue, 51, 9, 0, 0, // Skip to: 619
/* 610 */     MCD_OPC_CheckPredicate, 7, 32, 0, 0, // Skip to: 647
/* 615 */     MCD_OPC_Decode, 145, 7, 50, // Opcode: B16_MM
/* 619 */     MCD_OPC_FilterValue, 58, 9, 0, 0, // Skip to: 633
/* 624 */     MCD_OPC_CheckPredicate, 6, 18, 0, 0, // Skip to: 647
/* 629 */     MCD_OPC_Decode, 129, 23, 32, // Opcode: SW16_MM
/* 633 */     MCD_OPC_FilterValue, 59, 9, 0, 0, // Skip to: 647
/* 638 */     MCD_OPC_CheckPredicate, 6, 4, 0, 0, // Skip to: 647
/* 643 */     MCD_OPC_Decode, 231, 15, 51, // Opcode: LI16_MM
/* 647 */     MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMicroMips32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 238, 14, 0, // Skip to: 3830
/* 8 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 11 */      MCD_OPC_FilterValue, 0, 104, 0, 0, // Skip to: 120
/* 16 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 19 */      MCD_OPC_FilterValue, 0, 54, 0, 0, // Skip to: 78
/* 24 */      MCD_OPC_ExtractField, 11, 15,  // Inst{25-11} ...
/* 27 */      MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 41
/* 32 */      MCD_OPC_CheckPredicate, 7, 32, 0, 0, // Skip to: 69
/* 37 */      MCD_OPC_Decode, 186, 22, 10, // Opcode: SSNOP_MM
/* 41 */      MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 55
/* 46 */      MCD_OPC_CheckPredicate, 7, 18, 0, 0, // Skip to: 69
/* 51 */      MCD_OPC_Decode, 207, 12, 10, // Opcode: EHB_MM
/* 55 */      MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 69
/* 60 */      MCD_OPC_CheckPredicate, 7, 4, 0, 0, // Skip to: 69
/* 65 */      MCD_OPC_Decode, 182, 19, 10, // Opcode: PAUSE_MM
/* 69 */      MCD_OPC_CheckPredicate, 7, 101, 25, 0, // Skip to: 6575
/* 74 */      MCD_OPC_Decode, 235, 21, 52, // Opcode: SLL_MM
/* 78 */      MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 92
/* 83 */      MCD_OPC_CheckPredicate, 7, 87, 25, 0, // Skip to: 6575
/* 88 */      MCD_OPC_Decode, 182, 22, 52, // Opcode: SRL_MM
/* 92 */      MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 106
/* 97 */      MCD_OPC_CheckPredicate, 7, 73, 25, 0, // Skip to: 6575
/* 102 */     MCD_OPC_Decode, 157, 22, 52, // Opcode: SRA_MM
/* 106 */     MCD_OPC_FilterValue, 3, 64, 25, 0, // Skip to: 6575
/* 111 */     MCD_OPC_CheckPredicate, 7, 59, 25, 0, // Skip to: 6575
/* 116 */     MCD_OPC_Decode, 159, 20, 52, // Opcode: ROTR_MM
/* 120 */     MCD_OPC_FilterValue, 5, 227, 0, 0, // Skip to: 352
/* 125 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 128 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 149
/* 133 */     MCD_OPC_CheckPredicate, 8, 37, 25, 0, // Skip to: 6575
/* 138 */     MCD_OPC_CheckField, 11, 5, 0, 30, 25, 0, // Skip to: 6575
/* 145 */     MCD_OPC_Decode, 221, 9, 53, // Opcode: CMP_EQ_PH_MM
/* 149 */     MCD_OPC_FilterValue, 1, 16, 0, 0, // Skip to: 170
/* 154 */     MCD_OPC_CheckPredicate, 8, 16, 25, 0, // Skip to: 6575
/* 159 */     MCD_OPC_CheckField, 11, 5, 0, 9, 25, 0, // Skip to: 6575
/* 166 */     MCD_OPC_Decode, 235, 9, 53, // Opcode: CMP_LT_PH_MM
/* 170 */     MCD_OPC_FilterValue, 2, 16, 0, 0, // Skip to: 191
/* 175 */     MCD_OPC_CheckPredicate, 8, 251, 24, 0, // Skip to: 6575
/* 180 */     MCD_OPC_CheckField, 11, 5, 0, 244, 24, 0, // Skip to: 6575
/* 187 */     MCD_OPC_Decode, 229, 9, 53, // Opcode: CMP_LE_PH_MM
/* 191 */     MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 205
/* 196 */     MCD_OPC_CheckPredicate, 9, 230, 24, 0, // Skip to: 6575
/* 201 */     MCD_OPC_Decode, 199, 9, 54, // Opcode: CMPGDU_EQ_QB_MMR2
/* 205 */     MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 219
/* 210 */     MCD_OPC_CheckPredicate, 9, 216, 24, 0, // Skip to: 6575
/* 215 */     MCD_OPC_Decode, 203, 9, 54, // Opcode: CMPGDU_LT_QB_MMR2
/* 219 */     MCD_OPC_FilterValue, 8, 9, 0, 0, // Skip to: 233
/* 224 */     MCD_OPC_CheckPredicate, 9, 202, 24, 0, // Skip to: 6575
/* 229 */     MCD_OPC_Decode, 201, 9, 54, // Opcode: CMPGDU_LE_QB_MMR2
/* 233 */     MCD_OPC_FilterValue, 9, 16, 0, 0, // Skip to: 254
/* 238 */     MCD_OPC_CheckPredicate, 8, 188, 24, 0, // Skip to: 6575
/* 243 */     MCD_OPC_CheckField, 11, 5, 0, 181, 24, 0, // Skip to: 6575
/* 250 */     MCD_OPC_Decode, 211, 9, 53, // Opcode: CMPU_EQ_QB_MM
/* 254 */     MCD_OPC_FilterValue, 10, 16, 0, 0, // Skip to: 275
/* 259 */     MCD_OPC_CheckPredicate, 8, 167, 24, 0, // Skip to: 6575
/* 264 */     MCD_OPC_CheckField, 11, 5, 0, 160, 24, 0, // Skip to: 6575
/* 271 */     MCD_OPC_Decode, 215, 9, 53, // Opcode: CMPU_LT_QB_MM
/* 275 */     MCD_OPC_FilterValue, 11, 16, 0, 0, // Skip to: 296
/* 280 */     MCD_OPC_CheckPredicate, 8, 146, 24, 0, // Skip to: 6575
/* 285 */     MCD_OPC_CheckField, 11, 5, 0, 139, 24, 0, // Skip to: 6575
/* 292 */     MCD_OPC_Decode, 213, 9, 53, // Opcode: CMPU_LE_QB_MM
/* 296 */     MCD_OPC_FilterValue, 12, 9, 0, 0, // Skip to: 310
/* 301 */     MCD_OPC_CheckPredicate, 8, 125, 24, 0, // Skip to: 6575
/* 306 */     MCD_OPC_Decode, 154, 6, 55, // Opcode: ADDQ_S_W_MM
/* 310 */     MCD_OPC_FilterValue, 13, 9, 0, 0, // Skip to: 324
/* 315 */     MCD_OPC_CheckPredicate, 8, 111, 24, 0, // Skip to: 6575
/* 320 */     MCD_OPC_Decode, 206, 22, 55, // Opcode: SUBQ_S_W_MM
/* 324 */     MCD_OPC_FilterValue, 14, 9, 0, 0, // Skip to: 338
/* 329 */     MCD_OPC_CheckPredicate, 8, 97, 24, 0, // Skip to: 6575
/* 334 */     MCD_OPC_Decode, 157, 6, 55, // Opcode: ADDSC_MM
/* 338 */     MCD_OPC_FilterValue, 15, 88, 24, 0, // Skip to: 6575
/* 343 */     MCD_OPC_CheckPredicate, 8, 83, 24, 0, // Skip to: 6575
/* 348 */     MCD_OPC_Decode, 194, 6, 55, // Opcode: ADDWC_MM
/* 352 */     MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 366
/* 357 */     MCD_OPC_CheckPredicate, 7, 69, 24, 0, // Skip to: 6575
/* 362 */     MCD_OPC_Decode, 215, 8, 56, // Opcode: BREAK_MM
/* 366 */     MCD_OPC_FilterValue, 12, 9, 0, 0, // Skip to: 380
/* 371 */     MCD_OPC_CheckPredicate, 6, 55, 24, 0, // Skip to: 6575
/* 376 */     MCD_OPC_Decode, 231, 14, 57, // Opcode: INS_MM
/* 380 */     MCD_OPC_FilterValue, 13, 167, 1, 0, // Skip to: 808
/* 385 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 388 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 402
/* 393 */     MCD_OPC_CheckPredicate, 8, 33, 24, 0, // Skip to: 6575
/* 398 */     MCD_OPC_Decode, 150, 6, 58, // Opcode: ADDQ_PH_MM
/* 402 */     MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 416
/* 407 */     MCD_OPC_CheckPredicate, 9, 19, 24, 0, // Skip to: 6575
/* 412 */     MCD_OPC_Decode, 142, 6, 58, // Opcode: ADDQH_PH_MMR2
/* 416 */     MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 430
/* 421 */     MCD_OPC_CheckPredicate, 9, 5, 24, 0, // Skip to: 6575
/* 426 */     MCD_OPC_Decode, 148, 6, 55, // Opcode: ADDQH_W_MMR2
/* 430 */     MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 444
/* 435 */     MCD_OPC_CheckPredicate, 8, 247, 23, 0, // Skip to: 6575
/* 440 */     MCD_OPC_Decode, 180, 6, 58, // Opcode: ADDU_QB_MM
/* 444 */     MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 458
/* 449 */     MCD_OPC_CheckPredicate, 9, 233, 23, 0, // Skip to: 6575
/* 454 */     MCD_OPC_Decode, 178, 6, 58, // Opcode: ADDU_PH_MMR2
/* 458 */     MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 472
/* 463 */     MCD_OPC_CheckPredicate, 9, 219, 23, 0, // Skip to: 6575
/* 468 */     MCD_OPC_Decode, 173, 6, 58, // Opcode: ADDUH_QB_MMR2
/* 472 */     MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 486
/* 477 */     MCD_OPC_CheckPredicate, 8, 205, 23, 0, // Skip to: 6575
/* 482 */     MCD_OPC_Decode, 175, 21, 59, // Opcode: SHRAV_PH_MM
/* 486 */     MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 500
/* 491 */     MCD_OPC_CheckPredicate, 9, 191, 23, 0, // Skip to: 6575
/* 496 */     MCD_OPC_Decode, 177, 21, 59, // Opcode: SHRAV_QB_MMR2
/* 500 */     MCD_OPC_FilterValue, 8, 9, 0, 0, // Skip to: 514
/* 505 */     MCD_OPC_CheckPredicate, 8, 177, 23, 0, // Skip to: 6575
/* 510 */     MCD_OPC_Decode, 202, 22, 58, // Opcode: SUBQ_PH_MM
/* 514 */     MCD_OPC_FilterValue, 9, 9, 0, 0, // Skip to: 528
/* 519 */     MCD_OPC_CheckPredicate, 9, 163, 23, 0, // Skip to: 6575
/* 524 */     MCD_OPC_Decode, 194, 22, 58, // Opcode: SUBQH_PH_MMR2
/* 528 */     MCD_OPC_FilterValue, 10, 9, 0, 0, // Skip to: 542
/* 533 */     MCD_OPC_CheckPredicate, 9, 149, 23, 0, // Skip to: 6575
/* 538 */     MCD_OPC_Decode, 200, 22, 55, // Opcode: SUBQH_W_MMR2
/* 542 */     MCD_OPC_FilterValue, 11, 9, 0, 0, // Skip to: 556
/* 547 */     MCD_OPC_CheckPredicate, 8, 135, 23, 0, // Skip to: 6575
/* 552 */     MCD_OPC_Decode, 233, 22, 58, // Opcode: SUBU_QB_MM
/* 556 */     MCD_OPC_FilterValue, 12, 9, 0, 0, // Skip to: 570
/* 561 */     MCD_OPC_CheckPredicate, 9, 121, 23, 0, // Skip to: 6575
/* 566 */     MCD_OPC_Decode, 231, 22, 58, // Opcode: SUBU_PH_MMR2
/* 570 */     MCD_OPC_FilterValue, 13, 9, 0, 0, // Skip to: 584
/* 575 */     MCD_OPC_CheckPredicate, 9, 107, 23, 0, // Skip to: 6575
/* 580 */     MCD_OPC_Decode, 226, 22, 58, // Opcode: SUBUH_QB_MMR2
/* 584 */     MCD_OPC_FilterValue, 15, 9, 0, 0, // Skip to: 598
/* 589 */     MCD_OPC_CheckPredicate, 9, 93, 23, 0, // Skip to: 6575
/* 594 */     MCD_OPC_Decode, 235, 19, 60, // Opcode: PRECR_SRA_PH_W_MMR2
/* 598 */     MCD_OPC_FilterValue, 16, 9, 0, 0, // Skip to: 612
/* 603 */     MCD_OPC_CheckPredicate, 8, 79, 23, 0, // Skip to: 6575
/* 608 */     MCD_OPC_Decode, 152, 6, 58, // Opcode: ADDQ_S_PH_MM
/* 612 */     MCD_OPC_FilterValue, 17, 9, 0, 0, // Skip to: 626
/* 617 */     MCD_OPC_CheckPredicate, 9, 65, 23, 0, // Skip to: 6575
/* 622 */     MCD_OPC_Decode, 144, 6, 58, // Opcode: ADDQH_R_PH_MMR2
/* 626 */     MCD_OPC_FilterValue, 18, 9, 0, 0, // Skip to: 640
/* 631 */     MCD_OPC_CheckPredicate, 9, 51, 23, 0, // Skip to: 6575
/* 636 */     MCD_OPC_Decode, 146, 6, 55, // Opcode: ADDQH_R_W_MMR2
/* 640 */     MCD_OPC_FilterValue, 19, 9, 0, 0, // Skip to: 654
/* 645 */     MCD_OPC_CheckPredicate, 8, 37, 23, 0, // Skip to: 6575
/* 650 */     MCD_OPC_Decode, 184, 6, 58, // Opcode: ADDU_S_QB_MM
/* 654 */     MCD_OPC_FilterValue, 20, 9, 0, 0, // Skip to: 668
/* 659 */     MCD_OPC_CheckPredicate, 9, 23, 23, 0, // Skip to: 6575
/* 664 */     MCD_OPC_Decode, 182, 6, 58, // Opcode: ADDU_S_PH_MMR2
/* 668 */     MCD_OPC_FilterValue, 21, 9, 0, 0, // Skip to: 682
/* 673 */     MCD_OPC_CheckPredicate, 9, 9, 23, 0, // Skip to: 6575
/* 678 */     MCD_OPC_Decode, 175, 6, 58, // Opcode: ADDUH_R_QB_MMR2
/* 682 */     MCD_OPC_FilterValue, 22, 9, 0, 0, // Skip to: 696
/* 687 */     MCD_OPC_CheckPredicate, 8, 251, 22, 0, // Skip to: 6575
/* 692 */     MCD_OPC_Decode, 179, 21, 59, // Opcode: SHRAV_R_PH_MM
/* 696 */     MCD_OPC_FilterValue, 23, 9, 0, 0, // Skip to: 710
/* 701 */     MCD_OPC_CheckPredicate, 9, 237, 22, 0, // Skip to: 6575
/* 706 */     MCD_OPC_Decode, 181, 21, 59, // Opcode: SHRAV_R_QB_MMR2
/* 710 */     MCD_OPC_FilterValue, 24, 9, 0, 0, // Skip to: 724
/* 715 */     MCD_OPC_CheckPredicate, 8, 223, 22, 0, // Skip to: 6575
/* 720 */     MCD_OPC_Decode, 204, 22, 58, // Opcode: SUBQ_S_PH_MM
/* 724 */     MCD_OPC_FilterValue, 25, 9, 0, 0, // Skip to: 738
/* 729 */     MCD_OPC_CheckPredicate, 9, 209, 22, 0, // Skip to: 6575
/* 734 */     MCD_OPC_Decode, 196, 22, 58, // Opcode: SUBQH_R_PH_MMR2
/* 738 */     MCD_OPC_FilterValue, 26, 9, 0, 0, // Skip to: 752
/* 743 */     MCD_OPC_CheckPredicate, 9, 195, 22, 0, // Skip to: 6575
/* 748 */     MCD_OPC_Decode, 198, 22, 55, // Opcode: SUBQH_R_W_MMR2
/* 752 */     MCD_OPC_FilterValue, 27, 9, 0, 0, // Skip to: 766
/* 757 */     MCD_OPC_CheckPredicate, 8, 181, 22, 0, // Skip to: 6575
/* 762 */     MCD_OPC_Decode, 237, 22, 58, // Opcode: SUBU_S_QB_MM
/* 766 */     MCD_OPC_FilterValue, 28, 9, 0, 0, // Skip to: 780
/* 771 */     MCD_OPC_CheckPredicate, 9, 167, 22, 0, // Skip to: 6575
/* 776 */     MCD_OPC_Decode, 235, 22, 58, // Opcode: SUBU_S_PH_MMR2
/* 780 */     MCD_OPC_FilterValue, 29, 9, 0, 0, // Skip to: 794
/* 785 */     MCD_OPC_CheckPredicate, 9, 153, 22, 0, // Skip to: 6575
/* 790 */     MCD_OPC_Decode, 228, 22, 58, // Opcode: SUBUH_R_QB_MMR2
/* 794 */     MCD_OPC_FilterValue, 31, 144, 22, 0, // Skip to: 6575
/* 799 */     MCD_OPC_CheckPredicate, 9, 139, 22, 0, // Skip to: 6575
/* 804 */     MCD_OPC_Decode, 237, 19, 60, // Opcode: PRECR_SRA_R_PH_W_MMR2
/* 808 */     MCD_OPC_FilterValue, 14, 31, 0, 0, // Skip to: 844
/* 813 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 816 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 830
/* 821 */     MCD_OPC_CheckPredicate, 8, 117, 22, 0, // Skip to: 6575
/* 826 */     MCD_OPC_Decode, 159, 21, 59, // Opcode: SHLLV_PH_MM
/* 830 */     MCD_OPC_FilterValue, 16, 108, 22, 0, // Skip to: 6575
/* 835 */     MCD_OPC_CheckPredicate, 8, 103, 22, 0, // Skip to: 6575
/* 840 */     MCD_OPC_Decode, 163, 21, 59, // Opcode: SHLLV_S_PH_MM
/* 844 */     MCD_OPC_FilterValue, 16, 213, 0, 0, // Skip to: 1062
/* 849 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 852 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 866
/* 857 */     MCD_OPC_CheckPredicate, 7, 81, 22, 0, // Skip to: 6575
/* 862 */     MCD_OPC_Decode, 230, 21, 61, // Opcode: SLLV_MM
/* 866 */     MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 880
/* 871 */     MCD_OPC_CheckPredicate, 7, 67, 22, 0, // Skip to: 6575
/* 876 */     MCD_OPC_Decode, 177, 22, 61, // Opcode: SRLV_MM
/* 880 */     MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 894
/* 885 */     MCD_OPC_CheckPredicate, 7, 53, 22, 0, // Skip to: 6575
/* 890 */     MCD_OPC_Decode, 152, 22, 61, // Opcode: SRAV_MM
/* 894 */     MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 908
/* 899 */     MCD_OPC_CheckPredicate, 7, 39, 22, 0, // Skip to: 6575
/* 904 */     MCD_OPC_Decode, 157, 20, 61, // Opcode: ROTRV_MM
/* 908 */     MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 922
/* 913 */     MCD_OPC_CheckPredicate, 6, 25, 22, 0, // Skip to: 6575
/* 918 */     MCD_OPC_Decode, 199, 6, 55, // Opcode: ADD_MM
/* 922 */     MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 936
/* 927 */     MCD_OPC_CheckPredicate, 6, 11, 22, 0, // Skip to: 6575
/* 932 */     MCD_OPC_Decode, 209, 6, 55, // Opcode: ADDu_MM
/* 936 */     MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 950
/* 941 */     MCD_OPC_CheckPredicate, 6, 253, 21, 0, // Skip to: 6575
/* 946 */     MCD_OPC_Decode, 246, 22, 55, // Opcode: SUB_MM
/* 950 */     MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 964
/* 955 */     MCD_OPC_CheckPredicate, 6, 239, 21, 0, // Skip to: 6575
/* 960 */     MCD_OPC_Decode, 251, 22, 55, // Opcode: SUBu_MM
/* 964 */     MCD_OPC_FilterValue, 8, 9, 0, 0, // Skip to: 978
/* 969 */     MCD_OPC_CheckPredicate, 6, 225, 21, 0, // Skip to: 6575
/* 974 */     MCD_OPC_Decode, 245, 18, 55, // Opcode: MUL_MM
/* 978 */     MCD_OPC_FilterValue, 9, 9, 0, 0, // Skip to: 992
/* 983 */     MCD_OPC_CheckPredicate, 6, 211, 21, 0, // Skip to: 6575
/* 988 */     MCD_OPC_Decode, 227, 6, 55, // Opcode: AND_MM
/* 992 */     MCD_OPC_FilterValue, 10, 9, 0, 0, // Skip to: 1006
/* 997 */     MCD_OPC_CheckPredicate, 6, 197, 21, 0, // Skip to: 6575
/* 1002 */    MCD_OPC_Decode, 171, 19, 55, // Opcode: OR_MM
/* 1006 */    MCD_OPC_FilterValue, 11, 9, 0, 0, // Skip to: 1020
/* 1011 */    MCD_OPC_CheckPredicate, 6, 183, 21, 0, // Skip to: 6575
/* 1016 */    MCD_OPC_Decode, 154, 19, 55, // Opcode: NOR_MM
/* 1020 */    MCD_OPC_FilterValue, 12, 9, 0, 0, // Skip to: 1034
/* 1025 */    MCD_OPC_CheckPredicate, 6, 169, 21, 0, // Skip to: 6575
/* 1030 */    MCD_OPC_Decode, 180, 24, 55, // Opcode: XOR_MM
/* 1034 */    MCD_OPC_FilterValue, 13, 9, 0, 0, // Skip to: 1048
/* 1039 */    MCD_OPC_CheckPredicate, 7, 155, 21, 0, // Skip to: 6575
/* 1044 */    MCD_OPC_Decode, 244, 21, 55, // Opcode: SLT_MM
/* 1048 */    MCD_OPC_FilterValue, 14, 146, 21, 0, // Skip to: 6575
/* 1053 */    MCD_OPC_CheckPredicate, 7, 141, 21, 0, // Skip to: 6575
/* 1058 */    MCD_OPC_Decode, 254, 21, 55, // Opcode: SLTu_MM
/* 1062 */    MCD_OPC_FilterValue, 21, 199, 0, 0, // Skip to: 1266
/* 1067 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 1070 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 1084
/* 1075 */    MCD_OPC_CheckPredicate, 8, 119, 21, 0, // Skip to: 6575
/* 1080 */    MCD_OPC_Decode, 212, 18, 58, // Opcode: MULEU_S_PH_QBL_MM
/* 1084 */    MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 1098
/* 1089 */    MCD_OPC_CheckPredicate, 8, 105, 21, 0, // Skip to: 6575
/* 1094 */    MCD_OPC_Decode, 214, 18, 58, // Opcode: MULEU_S_PH_QBR_MM
/* 1098 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 1112
/* 1103 */    MCD_OPC_CheckPredicate, 8, 91, 21, 0, // Skip to: 6575
/* 1108 */    MCD_OPC_Decode, 216, 18, 58, // Opcode: MULQ_RS_PH_MM
/* 1112 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 1126
/* 1117 */    MCD_OPC_CheckPredicate, 9, 77, 21, 0, // Skip to: 6575
/* 1122 */    MCD_OPC_Decode, 220, 18, 58, // Opcode: MULQ_S_PH_MMR2
/* 1126 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 1140
/* 1131 */    MCD_OPC_CheckPredicate, 9, 63, 21, 0, // Skip to: 6575
/* 1136 */    MCD_OPC_Decode, 218, 18, 55, // Opcode: MULQ_RS_W_MMR2
/* 1140 */    MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 1154
/* 1145 */    MCD_OPC_CheckPredicate, 9, 49, 21, 0, // Skip to: 6575
/* 1150 */    MCD_OPC_Decode, 222, 18, 55, // Opcode: MULQ_S_W_MMR2
/* 1154 */    MCD_OPC_FilterValue, 8, 9, 0, 0, // Skip to: 1168
/* 1159 */    MCD_OPC_CheckPredicate, 9, 35, 21, 0, // Skip to: 6575
/* 1164 */    MCD_OPC_Decode, 235, 6, 62, // Opcode: APPEND_MMR2
/* 1168 */    MCD_OPC_FilterValue, 9, 9, 0, 0, // Skip to: 1182
/* 1173 */    MCD_OPC_CheckPredicate, 9, 21, 21, 0, // Skip to: 6575
/* 1178 */    MCD_OPC_Decode, 248, 19, 62, // Opcode: PREPEND_MMR2
/* 1182 */    MCD_OPC_FilterValue, 10, 9, 0, 0, // Skip to: 1196
/* 1187 */    MCD_OPC_CheckPredicate, 8, 7, 21, 0, // Skip to: 6575
/* 1192 */    MCD_OPC_Decode, 194, 17, 55, // Opcode: MODSUB_MM
/* 1196 */    MCD_OPC_FilterValue, 11, 9, 0, 0, // Skip to: 1210
/* 1201 */    MCD_OPC_CheckPredicate, 8, 249, 20, 0, // Skip to: 6575
/* 1206 */    MCD_OPC_Decode, 183, 21, 61, // Opcode: SHRAV_R_W_MM
/* 1210 */    MCD_OPC_FilterValue, 12, 9, 0, 0, // Skip to: 1224
/* 1215 */    MCD_OPC_CheckPredicate, 9, 235, 20, 0, // Skip to: 6575
/* 1220 */    MCD_OPC_Decode, 195, 21, 59, // Opcode: SHRLV_PH_MMR2
/* 1224 */    MCD_OPC_FilterValue, 13, 9, 0, 0, // Skip to: 1238
/* 1229 */    MCD_OPC_CheckPredicate, 8, 221, 20, 0, // Skip to: 6575
/* 1234 */    MCD_OPC_Decode, 197, 21, 59, // Opcode: SHRLV_QB_MM
/* 1238 */    MCD_OPC_FilterValue, 14, 9, 0, 0, // Skip to: 1252
/* 1243 */    MCD_OPC_CheckPredicate, 8, 207, 20, 0, // Skip to: 6575
/* 1248 */    MCD_OPC_Decode, 161, 21, 59, // Opcode: SHLLV_QB_MM
/* 1252 */    MCD_OPC_FilterValue, 15, 198, 20, 0, // Skip to: 6575
/* 1257 */    MCD_OPC_CheckPredicate, 8, 193, 20, 0, // Skip to: 6575
/* 1262 */    MCD_OPC_Decode, 165, 21, 61, // Opcode: SHLLV_S_W_MM
/* 1266 */    MCD_OPC_FilterValue, 24, 45, 0, 0, // Skip to: 1316
/* 1271 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 1274 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 1288
/* 1279 */    MCD_OPC_CheckPredicate, 6, 171, 20, 0, // Skip to: 6575
/* 1284 */    MCD_OPC_Decode, 234, 17, 63, // Opcode: MOVN_I_MM
/* 1288 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 1302
/* 1293 */    MCD_OPC_CheckPredicate, 6, 157, 20, 0, // Skip to: 6575
/* 1298 */    MCD_OPC_Decode, 255, 17, 63, // Opcode: MOVZ_I_MM
/* 1302 */    MCD_OPC_FilterValue, 4, 148, 20, 0, // Skip to: 6575
/* 1307 */    MCD_OPC_CheckPredicate, 7, 143, 20, 0, // Skip to: 6575
/* 1312 */    MCD_OPC_Decode, 175, 16, 64, // Opcode: LWXS_MM
/* 1316 */    MCD_OPC_FilterValue, 29, 23, 0, 0, // Skip to: 1344
/* 1321 */    MCD_OPC_CheckPredicate, 8, 129, 20, 0, // Skip to: 6575
/* 1326 */    MCD_OPC_CheckField, 22, 4, 0, 122, 20, 0, // Skip to: 6575
/* 1333 */    MCD_OPC_CheckField, 6, 8, 0, 115, 20, 0, // Skip to: 6575
/* 1340 */    MCD_OPC_Decode, 157, 21, 65, // Opcode: SHILO_MM
/* 1344 */    MCD_OPC_FilterValue, 37, 73, 0, 0, // Skip to: 1422
/* 1349 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 1352 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 1366
/* 1357 */    MCD_OPC_CheckPredicate, 8, 93, 20, 0, // Skip to: 6575
/* 1362 */    MCD_OPC_Decode, 208, 18, 54, // Opcode: MULEQ_S_W_PHL_MM
/* 1366 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 1380
/* 1371 */    MCD_OPC_CheckPredicate, 8, 79, 20, 0, // Skip to: 6575
/* 1376 */    MCD_OPC_Decode, 210, 18, 54, // Opcode: MULEQ_S_W_PHR_MM
/* 1380 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 1394
/* 1385 */    MCD_OPC_CheckPredicate, 8, 65, 20, 0, // Skip to: 6575
/* 1390 */    MCD_OPC_Decode, 221, 15, 64, // Opcode: LHX_MM
/* 1394 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 1408
/* 1399 */    MCD_OPC_CheckPredicate, 8, 51, 20, 0, // Skip to: 6575
/* 1404 */    MCD_OPC_Decode, 177, 16, 64, // Opcode: LWX_MM
/* 1408 */    MCD_OPC_FilterValue, 8, 42, 20, 0, // Skip to: 6575
/* 1413 */    MCD_OPC_CheckPredicate, 8, 37, 20, 0, // Skip to: 6575
/* 1418 */    MCD_OPC_Decode, 164, 15, 64, // Opcode: LBUX_MM
/* 1422 */    MCD_OPC_FilterValue, 44, 9, 0, 0, // Skip to: 1436
/* 1427 */    MCD_OPC_CheckPredicate, 6, 23, 20, 0, // Skip to: 6575
/* 1432 */    MCD_OPC_Decode, 255, 12, 66, // Opcode: EXT_MM
/* 1436 */    MCD_OPC_FilterValue, 45, 143, 0, 0, // Skip to: 1584
/* 1441 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 1444 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 1458
/* 1449 */    MCD_OPC_CheckPredicate, 9, 1, 20, 0, // Skip to: 6575
/* 1454 */    MCD_OPC_Decode, 249, 18, 58, // Opcode: MUL_PH_MMR2
/* 1458 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 1472
/* 1463 */    MCD_OPC_CheckPredicate, 9, 243, 19, 0, // Skip to: 6575
/* 1468 */    MCD_OPC_Decode, 233, 19, 58, // Opcode: PRECR_QB_PH_MMR2
/* 1472 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 1486
/* 1477 */    MCD_OPC_CheckPredicate, 8, 229, 19, 0, // Skip to: 6575
/* 1482 */    MCD_OPC_Decode, 229, 19, 58, // Opcode: PRECRQ_QB_PH_MM
/* 1486 */    MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 1500
/* 1491 */    MCD_OPC_CheckPredicate, 8, 215, 19, 0, // Skip to: 6575
/* 1496 */    MCD_OPC_Decode, 227, 19, 67, // Opcode: PRECRQ_PH_W_MM
/* 1500 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 1514
/* 1505 */    MCD_OPC_CheckPredicate, 8, 201, 19, 0, // Skip to: 6575
/* 1510 */    MCD_OPC_Decode, 231, 19, 67, // Opcode: PRECRQ_RS_PH_W_MM
/* 1514 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 1528
/* 1519 */    MCD_OPC_CheckPredicate, 8, 187, 19, 0, // Skip to: 6575
/* 1524 */    MCD_OPC_Decode, 225, 19, 58, // Opcode: PRECRQU_S_QB_PH_MM
/* 1528 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 1542
/* 1533 */    MCD_OPC_CheckPredicate, 8, 173, 19, 0, // Skip to: 6575
/* 1538 */    MCD_OPC_Decode, 180, 19, 58, // Opcode: PACKRL_PH_MM
/* 1542 */    MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 1556
/* 1547 */    MCD_OPC_CheckPredicate, 8, 159, 19, 0, // Skip to: 6575
/* 1552 */    MCD_OPC_Decode, 200, 19, 58, // Opcode: PICK_QB_MM
/* 1556 */    MCD_OPC_FilterValue, 8, 9, 0, 0, // Skip to: 1570
/* 1561 */    MCD_OPC_CheckPredicate, 8, 145, 19, 0, // Skip to: 6575
/* 1566 */    MCD_OPC_Decode, 198, 19, 58, // Opcode: PICK_PH_MM
/* 1570 */    MCD_OPC_FilterValue, 16, 136, 19, 0, // Skip to: 6575
/* 1575 */    MCD_OPC_CheckPredicate, 9, 131, 19, 0, // Skip to: 6575
/* 1580 */    MCD_OPC_Decode, 254, 18, 58, // Opcode: MUL_S_PH_MMR2
/* 1584 */    MCD_OPC_FilterValue, 52, 45, 0, 0, // Skip to: 1634
/* 1589 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 1592 */    MCD_OPC_FilterValue, 19, 16, 0, 0, // Skip to: 1613
/* 1597 */    MCD_OPC_CheckPredicate, 10, 109, 19, 0, // Skip to: 6575
/* 1602 */    MCD_OPC_CheckField, 14, 2, 0, 102, 19, 0, // Skip to: 6575
/* 1609 */    MCD_OPC_Decode, 149, 17, 68, // Opcode: MFHGC0_MM
/* 1613 */    MCD_OPC_FilterValue, 27, 93, 19, 0, // Skip to: 6575
/* 1618 */    MCD_OPC_CheckPredicate, 10, 88, 19, 0, // Skip to: 6575
/* 1623 */    MCD_OPC_CheckField, 14, 2, 0, 81, 19, 0, // Skip to: 6575
/* 1630 */    MCD_OPC_Decode, 178, 18, 69, // Opcode: MTHGC0_MM
/* 1634 */    MCD_OPC_FilterValue, 53, 109, 0, 0, // Skip to: 1748
/* 1639 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 1642 */    MCD_OPC_FilterValue, 11, 9, 0, 0, // Skip to: 1656
/* 1647 */    MCD_OPC_CheckPredicate, 8, 59, 19, 0, // Skip to: 6575
/* 1652 */    MCD_OPC_Decode, 193, 21, 52, // Opcode: SHRA_R_W_MM
/* 1656 */    MCD_OPC_FilterValue, 12, 16, 0, 0, // Skip to: 1677
/* 1661 */    MCD_OPC_CheckPredicate, 8, 45, 19, 0, // Skip to: 6575
/* 1666 */    MCD_OPC_CheckField, 11, 1, 0, 38, 19, 0, // Skip to: 6575
/* 1673 */    MCD_OPC_Decode, 185, 21, 70, // Opcode: SHRA_PH_MM
/* 1677 */    MCD_OPC_FilterValue, 14, 31, 0, 0, // Skip to: 1713
/* 1682 */    MCD_OPC_ExtractField, 11, 1,  // Inst{11} ...
/* 1685 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 1699
/* 1690 */    MCD_OPC_CheckPredicate, 8, 16, 19, 0, // Skip to: 6575
/* 1695 */    MCD_OPC_Decode, 167, 21, 70, // Opcode: SHLL_PH_MM
/* 1699 */    MCD_OPC_FilterValue, 1, 7, 19, 0, // Skip to: 6575
/* 1704 */    MCD_OPC_CheckPredicate, 8, 2, 19, 0, // Skip to: 6575
/* 1709 */    MCD_OPC_Decode, 171, 21, 70, // Opcode: SHLL_S_PH_MM
/* 1713 */    MCD_OPC_FilterValue, 15, 9, 0, 0, // Skip to: 1727
/* 1718 */    MCD_OPC_CheckPredicate, 8, 244, 18, 0, // Skip to: 6575
/* 1723 */    MCD_OPC_Decode, 173, 21, 52, // Opcode: SHLL_S_W_MM
/* 1727 */    MCD_OPC_FilterValue, 28, 235, 18, 0, // Skip to: 6575
/* 1732 */    MCD_OPC_CheckPredicate, 8, 230, 18, 0, // Skip to: 6575
/* 1737 */    MCD_OPC_CheckField, 11, 1, 0, 223, 18, 0, // Skip to: 6575
/* 1744 */    MCD_OPC_Decode, 189, 21, 70, // Opcode: SHRA_R_PH_MM
/* 1748 */    MCD_OPC_FilterValue, 60, 8, 8, 0, // Skip to: 3809
/* 1753 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 1756 */    MCD_OPC_FilterValue, 0, 31, 0, 0, // Skip to: 1792
/* 1761 */    MCD_OPC_ExtractField, 11, 1,  // Inst{11} ...
/* 1764 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 1778
/* 1769 */    MCD_OPC_CheckPredicate, 7, 193, 18, 0, // Skip to: 6575
/* 1774 */    MCD_OPC_Decode, 210, 23, 71, // Opcode: TEQ_MM
/* 1778 */    MCD_OPC_FilterValue, 1, 184, 18, 0, // Skip to: 6575
/* 1783 */    MCD_OPC_CheckPredicate, 7, 179, 18, 0, // Skip to: 6575
/* 1788 */    MCD_OPC_Decode, 128, 24, 71, // Opcode: TLT_MM
/* 1792 */    MCD_OPC_FilterValue, 1, 131, 0, 0, // Skip to: 1928
/* 1797 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 1800 */    MCD_OPC_FilterValue, 0, 45, 0, 0, // Skip to: 1850
/* 1805 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1808 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 1829
/* 1813 */    MCD_OPC_CheckPredicate, 8, 149, 18, 0, // Skip to: 6575
/* 1818 */    MCD_OPC_CheckField, 21, 5, 0, 142, 18, 0, // Skip to: 6575
/* 1825 */    MCD_OPC_Decode, 154, 17, 72, // Opcode: MFHI_DSP_MM
/* 1829 */    MCD_OPC_FilterValue, 1, 133, 18, 0, // Skip to: 6575
/* 1834 */    MCD_OPC_CheckPredicate, 8, 128, 18, 0, // Skip to: 6575
/* 1839 */    MCD_OPC_CheckField, 21, 5, 0, 121, 18, 0, // Skip to: 6575
/* 1846 */    MCD_OPC_Decode, 182, 18, 73, // Opcode: MTHI_DSP_MM
/* 1850 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 1864
/* 1855 */    MCD_OPC_CheckPredicate, 8, 107, 18, 0, // Skip to: 6575
/* 1860 */    MCD_OPC_Decode, 169, 21, 74, // Opcode: SHLL_QB_MM
/* 1864 */    MCD_OPC_FilterValue, 2, 45, 0, 0, // Skip to: 1914
/* 1869 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1872 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 1893
/* 1877 */    MCD_OPC_CheckPredicate, 8, 85, 18, 0, // Skip to: 6575
/* 1882 */    MCD_OPC_CheckField, 21, 5, 0, 78, 18, 0, // Skip to: 6575
/* 1889 */    MCD_OPC_Decode, 160, 17, 72, // Opcode: MFLO_DSP_MM
/* 1893 */    MCD_OPC_FilterValue, 1, 69, 18, 0, // Skip to: 6575
/* 1898 */    MCD_OPC_CheckPredicate, 8, 64, 18, 0, // Skip to: 6575
/* 1903 */    MCD_OPC_CheckField, 21, 5, 0, 57, 18, 0, // Skip to: 6575
/* 1910 */    MCD_OPC_Decode, 189, 18, 75, // Opcode: MTLO_DSP_MM
/* 1914 */    MCD_OPC_FilterValue, 3, 48, 18, 0, // Skip to: 6575
/* 1919 */    MCD_OPC_CheckPredicate, 8, 43, 18, 0, // Skip to: 6575
/* 1924 */    MCD_OPC_Decode, 201, 21, 74, // Opcode: SHRL_QB_MM
/* 1928 */    MCD_OPC_FilterValue, 2, 101, 0, 0, // Skip to: 2034
/* 1933 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 1936 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 1950
/* 1941 */    MCD_OPC_CheckPredicate, 9, 21, 18, 0, // Skip to: 6575
/* 1946 */    MCD_OPC_Decode, 157, 12, 76, // Opcode: DPA_W_PH_MMR2
/* 1950 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 1964
/* 1955 */    MCD_OPC_CheckPredicate, 9, 7, 18, 0, // Skip to: 6575
/* 1960 */    MCD_OPC_Decode, 153, 7, 77, // Opcode: BALIGN_MMR2
/* 1964 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 1978
/* 1969 */    MCD_OPC_CheckPredicate, 9, 249, 17, 0, // Skip to: 6575
/* 1974 */    MCD_OPC_Decode, 155, 12, 76, // Opcode: DPAX_W_PH_MMR2
/* 1978 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 1992
/* 1983 */    MCD_OPC_CheckPredicate, 8, 235, 17, 0, // Skip to: 6575
/* 1988 */    MCD_OPC_Decode, 151, 12, 76, // Opcode: DPAU_H_QBL_MM
/* 1992 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 2006
/* 1997 */    MCD_OPC_CheckPredicate, 8, 221, 17, 0, // Skip to: 6575
/* 2002 */    MCD_OPC_Decode, 234, 12, 78, // Opcode: EXTPV_MM
/* 2006 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 2020
/* 2011 */    MCD_OPC_CheckPredicate, 8, 207, 17, 0, // Skip to: 6575
/* 2016 */    MCD_OPC_Decode, 153, 12, 76, // Opcode: DPAU_H_QBR_MM
/* 2020 */    MCD_OPC_FilterValue, 7, 198, 17, 0, // Skip to: 6575
/* 2025 */    MCD_OPC_CheckPredicate, 8, 193, 17, 0, // Skip to: 6575
/* 2030 */    MCD_OPC_Decode, 231, 12, 78, // Opcode: EXTPDPV_MM
/* 2034 */    MCD_OPC_FilterValue, 4, 171, 0, 0, // Skip to: 2210
/* 2039 */    MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 2042 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 2056
/* 2047 */    MCD_OPC_CheckPredicate, 9, 171, 17, 0, // Skip to: 6575
/* 2052 */    MCD_OPC_Decode, 248, 5, 79, // Opcode: ABSQ_S_QB_MMR2
/* 2056 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 2070
/* 2061 */    MCD_OPC_CheckPredicate, 8, 157, 17, 0, // Skip to: 6575
/* 2066 */    MCD_OPC_Decode, 246, 5, 79, // Opcode: ABSQ_S_PH_MM
/* 2070 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 2084
/* 2075 */    MCD_OPC_CheckPredicate, 8, 143, 17, 0, // Skip to: 6575
/* 2080 */    MCD_OPC_Decode, 250, 5, 80, // Opcode: ABSQ_S_W_MM
/* 2084 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 2098
/* 2089 */    MCD_OPC_CheckPredicate, 8, 129, 17, 0, // Skip to: 6575
/* 2094 */    MCD_OPC_Decode, 131, 8, 80, // Opcode: BITREV_MM
/* 2098 */    MCD_OPC_FilterValue, 8, 9, 0, 0, // Skip to: 2112
/* 2103 */    MCD_OPC_CheckPredicate, 8, 115, 17, 0, // Skip to: 6575
/* 2108 */    MCD_OPC_Decode, 230, 14, 81, // Opcode: INSV_MM
/* 2112 */    MCD_OPC_FilterValue, 10, 9, 0, 0, // Skip to: 2126
/* 2117 */    MCD_OPC_CheckPredicate, 8, 101, 17, 0, // Skip to: 6575
/* 2122 */    MCD_OPC_Decode, 213, 19, 82, // Opcode: PRECEQ_W_PHL_MM
/* 2126 */    MCD_OPC_FilterValue, 12, 9, 0, 0, // Skip to: 2140
/* 2131 */    MCD_OPC_CheckPredicate, 8, 87, 17, 0, // Skip to: 6575
/* 2136 */    MCD_OPC_Decode, 215, 19, 82, // Opcode: PRECEQ_W_PHR_MM
/* 2140 */    MCD_OPC_FilterValue, 14, 9, 0, 0, // Skip to: 2154
/* 2145 */    MCD_OPC_CheckPredicate, 8, 73, 17, 0, // Skip to: 6575
/* 2150 */    MCD_OPC_Decode, 207, 19, 79, // Opcode: PRECEQU_PH_QBL_MM
/* 2154 */    MCD_OPC_FilterValue, 18, 9, 0, 0, // Skip to: 2168
/* 2159 */    MCD_OPC_CheckPredicate, 8, 59, 17, 0, // Skip to: 6575
/* 2164 */    MCD_OPC_Decode, 211, 19, 79, // Opcode: PRECEQU_PH_QBR_MM
/* 2168 */    MCD_OPC_FilterValue, 22, 9, 0, 0, // Skip to: 2182
/* 2173 */    MCD_OPC_CheckPredicate, 8, 45, 17, 0, // Skip to: 6575
/* 2178 */    MCD_OPC_Decode, 219, 19, 79, // Opcode: PRECEU_PH_QBL_MM
/* 2182 */    MCD_OPC_FilterValue, 26, 9, 0, 0, // Skip to: 2196
/* 2187 */    MCD_OPC_CheckPredicate, 8, 31, 17, 0, // Skip to: 6575
/* 2192 */    MCD_OPC_Decode, 223, 19, 79, // Opcode: PRECEU_PH_QBR_MM
/* 2196 */    MCD_OPC_FilterValue, 30, 22, 17, 0, // Skip to: 6575
/* 2201 */    MCD_OPC_CheckPredicate, 8, 17, 17, 0, // Skip to: 6575
/* 2206 */    MCD_OPC_Decode, 252, 19, 82, // Opcode: RADDU_W_QB_MM
/* 2210 */    MCD_OPC_FilterValue, 5, 87, 0, 0, // Skip to: 2302
/* 2215 */    MCD_OPC_ExtractField, 11, 15,  // Inst{25-11} ...
/* 2218 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 2232
/* 2223 */    MCD_OPC_CheckPredicate, 10, 251, 16, 0, // Skip to: 6575
/* 2228 */    MCD_OPC_Decode, 225, 23, 10, // Opcode: TLBGP_MM
/* 2232 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 2246
/* 2237 */    MCD_OPC_CheckPredicate, 10, 237, 16, 0, // Skip to: 6575
/* 2242 */    MCD_OPC_Decode, 227, 23, 10, // Opcode: TLBGR_MM
/* 2246 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 2260
/* 2251 */    MCD_OPC_CheckPredicate, 10, 223, 16, 0, // Skip to: 6575
/* 2256 */    MCD_OPC_Decode, 229, 23, 10, // Opcode: TLBGWI_MM
/* 2260 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 2274
/* 2265 */    MCD_OPC_CheckPredicate, 10, 209, 16, 0, // Skip to: 6575
/* 2270 */    MCD_OPC_Decode, 231, 23, 10, // Opcode: TLBGWR_MM
/* 2274 */    MCD_OPC_FilterValue, 8, 9, 0, 0, // Skip to: 2288
/* 2279 */    MCD_OPC_CheckPredicate, 10, 195, 16, 0, // Skip to: 6575
/* 2284 */    MCD_OPC_Decode, 223, 23, 10, // Opcode: TLBGINV_MM
/* 2288 */    MCD_OPC_FilterValue, 10, 186, 16, 0, // Skip to: 6575
/* 2293 */    MCD_OPC_CheckPredicate, 10, 181, 16, 0, // Skip to: 6575
/* 2298 */    MCD_OPC_Decode, 222, 23, 10, // Opcode: TLBGINVF_MM
/* 2302 */    MCD_OPC_FilterValue, 7, 31, 0, 0, // Skip to: 2338
/* 2307 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 2310 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 2324
/* 2315 */    MCD_OPC_CheckPredicate, 9, 159, 16, 0, // Skip to: 6575
/* 2320 */    MCD_OPC_Decode, 187, 21, 74, // Opcode: SHRA_QB_MMR2
/* 2324 */    MCD_OPC_FilterValue, 2, 150, 16, 0, // Skip to: 6575
/* 2329 */    MCD_OPC_CheckPredicate, 9, 145, 16, 0, // Skip to: 6575
/* 2334 */    MCD_OPC_Decode, 191, 21, 74, // Opcode: SHRA_R_QB_MMR2
/* 2338 */    MCD_OPC_FilterValue, 8, 31, 0, 0, // Skip to: 2374
/* 2343 */    MCD_OPC_ExtractField, 11, 1,  // Inst{11} ...
/* 2346 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 2360
/* 2351 */    MCD_OPC_CheckPredicate, 7, 123, 16, 0, // Skip to: 6575
/* 2356 */    MCD_OPC_Decode, 219, 23, 71, // Opcode: TGE_MM
/* 2360 */    MCD_OPC_FilterValue, 1, 114, 16, 0, // Skip to: 6575
/* 2365 */    MCD_OPC_CheckPredicate, 7, 109, 16, 0, // Skip to: 6575
/* 2370 */    MCD_OPC_Decode, 255, 23, 71, // Opcode: TLTU_MM
/* 2374 */    MCD_OPC_FilterValue, 9, 101, 0, 0, // Skip to: 2480
/* 2379 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 2382 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 2403
/* 2387 */    MCD_OPC_CheckPredicate, 8, 87, 16, 0, // Skip to: 6575
/* 2392 */    MCD_OPC_CheckField, 21, 5, 0, 80, 16, 0, // Skip to: 6575
/* 2399 */    MCD_OPC_Decode, 185, 18, 83, // Opcode: MTHLIP_MM
/* 2403 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 2417
/* 2408 */    MCD_OPC_CheckPredicate, 8, 66, 16, 0, // Skip to: 6575
/* 2413 */    MCD_OPC_Decode, 227, 16, 76, // Opcode: MAQ_S_W_PHR_MM
/* 2417 */    MCD_OPC_FilterValue, 2, 16, 0, 0, // Skip to: 2438
/* 2422 */    MCD_OPC_CheckPredicate, 8, 52, 16, 0, // Skip to: 6575
/* 2427 */    MCD_OPC_CheckField, 21, 5, 0, 45, 16, 0, // Skip to: 6575
/* 2434 */    MCD_OPC_Decode, 156, 21, 83, // Opcode: SHILOV_MM
/* 2438 */    MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 2452
/* 2443 */    MCD_OPC_CheckPredicate, 8, 31, 16, 0, // Skip to: 6575
/* 2448 */    MCD_OPC_Decode, 225, 16, 76, // Opcode: MAQ_S_W_PHL_MM
/* 2452 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 2466
/* 2457 */    MCD_OPC_CheckPredicate, 8, 17, 16, 0, // Skip to: 6575
/* 2462 */    MCD_OPC_Decode, 223, 16, 76, // Opcode: MAQ_SA_W_PHR_MM
/* 2466 */    MCD_OPC_FilterValue, 7, 8, 16, 0, // Skip to: 6575
/* 2471 */    MCD_OPC_CheckPredicate, 8, 3, 16, 0, // Skip to: 6575
/* 2476 */    MCD_OPC_Decode, 221, 16, 76, // Opcode: MAQ_SA_W_PHL_MM
/* 2480 */    MCD_OPC_FilterValue, 10, 115, 0, 0, // Skip to: 2600
/* 2485 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 2488 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 2502
/* 2493 */    MCD_OPC_CheckPredicate, 8, 237, 15, 0, // Skip to: 6575
/* 2498 */    MCD_OPC_Decode, 149, 12, 76, // Opcode: DPAQ_S_W_PH_MM
/* 2502 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 2516
/* 2507 */    MCD_OPC_CheckPredicate, 8, 223, 15, 0, // Skip to: 6575
/* 2512 */    MCD_OPC_Decode, 214, 16, 76, // Opcode: MADD_DSP_MM
/* 2516 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 2530
/* 2521 */    MCD_OPC_CheckPredicate, 8, 209, 15, 0, // Skip to: 6575
/* 2526 */    MCD_OPC_Decode, 147, 12, 76, // Opcode: DPAQ_SA_L_W_MM
/* 2530 */    MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 2544
/* 2535 */    MCD_OPC_CheckPredicate, 8, 195, 15, 0, // Skip to: 6575
/* 2540 */    MCD_OPC_Decode, 204, 16, 76, // Opcode: MADDU_DSP_MM
/* 2544 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 2558
/* 2549 */    MCD_OPC_CheckPredicate, 9, 181, 15, 0, // Skip to: 6575
/* 2554 */    MCD_OPC_Decode, 145, 12, 76, // Opcode: DPAQX_S_W_PH_MMR2
/* 2558 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 2572
/* 2563 */    MCD_OPC_CheckPredicate, 8, 167, 15, 0, // Skip to: 6575
/* 2568 */    MCD_OPC_Decode, 150, 18, 76, // Opcode: MSUB_DSP_MM
/* 2572 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 2586
/* 2577 */    MCD_OPC_CheckPredicate, 9, 153, 15, 0, // Skip to: 6575
/* 2582 */    MCD_OPC_Decode, 143, 12, 76, // Opcode: DPAQX_SA_W_PH_MMR2
/* 2586 */    MCD_OPC_FilterValue, 7, 144, 15, 0, // Skip to: 6575
/* 2591 */    MCD_OPC_CheckPredicate, 8, 139, 15, 0, // Skip to: 6575
/* 2596 */    MCD_OPC_Decode, 140, 18, 76, // Opcode: MSUBU_DSP_MM
/* 2600 */    MCD_OPC_FilterValue, 12, 27, 1, 0, // Skip to: 2888
/* 2605 */    MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 2608 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 2622
/* 2613 */    MCD_OPC_CheckPredicate, 8, 117, 15, 0, // Skip to: 6575
/* 2618 */    MCD_OPC_Decode, 141, 20, 84, // Opcode: REPLV_PH_MM
/* 2622 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 2636
/* 2627 */    MCD_OPC_CheckPredicate, 8, 103, 15, 0, // Skip to: 6575
/* 2632 */    MCD_OPC_Decode, 143, 20, 84, // Opcode: REPLV_QB_MM
/* 2636 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 2650
/* 2641 */    MCD_OPC_CheckPredicate, 7, 89, 15, 0, // Skip to: 6575
/* 2646 */    MCD_OPC_Decode, 244, 20, 80, // Opcode: SEB_MM
/* 2650 */    MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 2664
/* 2655 */    MCD_OPC_CheckPredicate, 7, 75, 15, 0, // Skip to: 6575
/* 2660 */    MCD_OPC_Decode, 248, 20, 80, // Opcode: SEH_MM
/* 2664 */    MCD_OPC_FilterValue, 9, 9, 0, 0, // Skip to: 2678
/* 2669 */    MCD_OPC_CheckPredicate, 7, 61, 15, 0, // Skip to: 6575
/* 2674 */    MCD_OPC_Decode, 173, 9, 80, // Opcode: CLO_MM
/* 2678 */    MCD_OPC_FilterValue, 11, 9, 0, 0, // Skip to: 2692
/* 2683 */    MCD_OPC_CheckPredicate, 7, 47, 15, 0, // Skip to: 6575
/* 2688 */    MCD_OPC_Decode, 194, 9, 80, // Opcode: CLZ_MM
/* 2692 */    MCD_OPC_FilterValue, 13, 9, 0, 0, // Skip to: 2706
/* 2697 */    MCD_OPC_CheckPredicate, 6, 33, 15, 0, // Skip to: 6575
/* 2702 */    MCD_OPC_Decode, 129, 20, 85, // Opcode: RDHWR_MM
/* 2706 */    MCD_OPC_FilterValue, 14, 9, 0, 0, // Skip to: 2720
/* 2711 */    MCD_OPC_CheckPredicate, 8, 19, 15, 0, // Skip to: 6575
/* 2716 */    MCD_OPC_Decode, 206, 19, 79, // Opcode: PRECEQU_PH_QBLA_MM
/* 2720 */    MCD_OPC_FilterValue, 15, 9, 0, 0, // Skip to: 2734
/* 2725 */    MCD_OPC_CheckPredicate, 7, 5, 15, 0, // Skip to: 6575
/* 2730 */    MCD_OPC_Decode, 170, 24, 80, // Opcode: WSBH_MM
/* 2734 */    MCD_OPC_FilterValue, 17, 9, 0, 0, // Skip to: 2748
/* 2739 */    MCD_OPC_CheckPredicate, 6, 247, 14, 0, // Skip to: 6575
/* 2744 */    MCD_OPC_Decode, 235, 18, 86, // Opcode: MULT_MM
/* 2748 */    MCD_OPC_FilterValue, 18, 9, 0, 0, // Skip to: 2762
/* 2753 */    MCD_OPC_CheckPredicate, 8, 233, 14, 0, // Skip to: 6575
/* 2758 */    MCD_OPC_Decode, 210, 19, 79, // Opcode: PRECEQU_PH_QBRA_MM
/* 2762 */    MCD_OPC_FilterValue, 19, 9, 0, 0, // Skip to: 2776
/* 2767 */    MCD_OPC_CheckPredicate, 6, 219, 14, 0, // Skip to: 6575
/* 2772 */    MCD_OPC_Decode, 237, 18, 86, // Opcode: MULTu_MM
/* 2776 */    MCD_OPC_FilterValue, 21, 9, 0, 0, // Skip to: 2790
/* 2781 */    MCD_OPC_CheckPredicate, 6, 205, 14, 0, // Skip to: 6575
/* 2786 */    MCD_OPC_Decode, 237, 20, 86, // Opcode: SDIV_MM
/* 2790 */    MCD_OPC_FilterValue, 22, 9, 0, 0, // Skip to: 2804
/* 2795 */    MCD_OPC_CheckPredicate, 8, 191, 14, 0, // Skip to: 6575
/* 2800 */    MCD_OPC_Decode, 218, 19, 79, // Opcode: PRECEU_PH_QBLA_MM
/* 2804 */    MCD_OPC_FilterValue, 23, 9, 0, 0, // Skip to: 2818
/* 2809 */    MCD_OPC_CheckPredicate, 6, 177, 14, 0, // Skip to: 6575
/* 2814 */    MCD_OPC_Decode, 153, 24, 86, // Opcode: UDIV_MM
/* 2818 */    MCD_OPC_FilterValue, 25, 9, 0, 0, // Skip to: 2832
/* 2823 */    MCD_OPC_CheckPredicate, 6, 163, 14, 0, // Skip to: 6575
/* 2828 */    MCD_OPC_Decode, 215, 16, 86, // Opcode: MADD_MM
/* 2832 */    MCD_OPC_FilterValue, 26, 9, 0, 0, // Skip to: 2846
/* 2837 */    MCD_OPC_CheckPredicate, 8, 149, 14, 0, // Skip to: 6575
/* 2842 */    MCD_OPC_Decode, 222, 19, 79, // Opcode: PRECEU_PH_QBRA_MM
/* 2846 */    MCD_OPC_FilterValue, 27, 9, 0, 0, // Skip to: 2860
/* 2851 */    MCD_OPC_CheckPredicate, 6, 135, 14, 0, // Skip to: 6575
/* 2856 */    MCD_OPC_Decode, 205, 16, 86, // Opcode: MADDU_MM
/* 2860 */    MCD_OPC_FilterValue, 29, 9, 0, 0, // Skip to: 2874
/* 2865 */    MCD_OPC_CheckPredicate, 6, 121, 14, 0, // Skip to: 6575
/* 2870 */    MCD_OPC_Decode, 151, 18, 86, // Opcode: MSUB_MM
/* 2874 */    MCD_OPC_FilterValue, 31, 112, 14, 0, // Skip to: 6575
/* 2879 */    MCD_OPC_CheckPredicate, 6, 107, 14, 0, // Skip to: 6575
/* 2884 */    MCD_OPC_Decode, 141, 18, 86, // Opcode: MSUBU_MM
/* 2888 */    MCD_OPC_FilterValue, 13, 206, 0, 0, // Skip to: 3099
/* 2893 */    MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 2896 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 2917
/* 2901 */    MCD_OPC_CheckPredicate, 7, 85, 14, 0, // Skip to: 6575
/* 2906 */    MCD_OPC_CheckField, 16, 10, 0, 78, 14, 0, // Skip to: 6575
/* 2913 */    MCD_OPC_Decode, 239, 23, 10, // Opcode: TLBP_MM
/* 2917 */    MCD_OPC_FilterValue, 2, 16, 0, 0, // Skip to: 2938
/* 2922 */    MCD_OPC_CheckPredicate, 7, 64, 14, 0, // Skip to: 6575
/* 2927 */    MCD_OPC_CheckField, 16, 10, 0, 57, 14, 0, // Skip to: 6575
/* 2934 */    MCD_OPC_Decode, 242, 23, 10, // Opcode: TLBR_MM
/* 2938 */    MCD_OPC_FilterValue, 4, 16, 0, 0, // Skip to: 2959
/* 2943 */    MCD_OPC_CheckPredicate, 7, 43, 14, 0, // Skip to: 6575
/* 2948 */    MCD_OPC_CheckField, 16, 10, 0, 36, 14, 0, // Skip to: 6575
/* 2955 */    MCD_OPC_Decode, 245, 23, 10, // Opcode: TLBWI_MM
/* 2959 */    MCD_OPC_FilterValue, 6, 16, 0, 0, // Skip to: 2980
/* 2964 */    MCD_OPC_CheckPredicate, 7, 22, 14, 0, // Skip to: 6575
/* 2969 */    MCD_OPC_CheckField, 16, 10, 0, 15, 14, 0, // Skip to: 6575
/* 2976 */    MCD_OPC_Decode, 248, 23, 10, // Opcode: TLBWR_MM
/* 2980 */    MCD_OPC_FilterValue, 13, 16, 0, 0, // Skip to: 3001
/* 2985 */    MCD_OPC_CheckPredicate, 7, 1, 14, 0, // Skip to: 6575
/* 2990 */    MCD_OPC_CheckField, 21, 5, 0, 250, 13, 0, // Skip to: 6575
/* 2997 */    MCD_OPC_Decode, 179, 23, 87, // Opcode: SYNC_MM
/* 3001 */    MCD_OPC_FilterValue, 17, 9, 0, 0, // Skip to: 3015
/* 3006 */    MCD_OPC_CheckPredicate, 7, 236, 13, 0, // Skip to: 6575
/* 3011 */    MCD_OPC_Decode, 184, 23, 88, // Opcode: SYSCALL_MM
/* 3015 */    MCD_OPC_FilterValue, 18, 9, 0, 0, // Skip to: 3029
/* 3020 */    MCD_OPC_CheckPredicate, 7, 222, 13, 0, // Skip to: 6575
/* 3025 */    MCD_OPC_Decode, 162, 24, 88, // Opcode: WAIT_MM
/* 3029 */    MCD_OPC_FilterValue, 24, 9, 0, 0, // Skip to: 3043
/* 3034 */    MCD_OPC_CheckPredicate, 10, 208, 13, 0, // Skip to: 6575
/* 3039 */    MCD_OPC_Decode, 203, 14, 88, // Opcode: HYPCALL_MM
/* 3043 */    MCD_OPC_FilterValue, 27, 9, 0, 0, // Skip to: 3057
/* 3048 */    MCD_OPC_CheckPredicate, 7, 194, 13, 0, // Skip to: 6575
/* 3053 */    MCD_OPC_Decode, 223, 20, 88, // Opcode: SDBBP_MM
/* 3057 */    MCD_OPC_FilterValue, 28, 16, 0, 0, // Skip to: 3078
/* 3062 */    MCD_OPC_CheckPredicate, 7, 180, 13, 0, // Skip to: 6575
/* 3067 */    MCD_OPC_CheckField, 16, 10, 0, 173, 13, 0, // Skip to: 6575
/* 3074 */    MCD_OPC_Decode, 207, 11, 10, // Opcode: DERET_MM
/* 3078 */    MCD_OPC_FilterValue, 30, 164, 13, 0, // Skip to: 6575
/* 3083 */    MCD_OPC_CheckPredicate, 7, 159, 13, 0, // Skip to: 6575
/* 3088 */    MCD_OPC_CheckField, 16, 10, 0, 152, 13, 0, // Skip to: 6575
/* 3095 */    MCD_OPC_Decode, 220, 12, 10, // Opcode: ERET_MM
/* 3099 */    MCD_OPC_FilterValue, 15, 16, 0, 0, // Skip to: 3120
/* 3104 */    MCD_OPC_CheckPredicate, 9, 138, 13, 0, // Skip to: 6575
/* 3109 */    MCD_OPC_CheckField, 11, 1, 0, 131, 13, 0, // Skip to: 6575
/* 3116 */    MCD_OPC_Decode, 199, 21, 70, // Opcode: SHRL_PH_MMR2
/* 3120 */    MCD_OPC_FilterValue, 16, 31, 0, 0, // Skip to: 3156
/* 3125 */    MCD_OPC_ExtractField, 11, 1,  // Inst{11} ...
/* 3128 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 3142
/* 3133 */    MCD_OPC_CheckPredicate, 7, 109, 13, 0, // Skip to: 6575
/* 3138 */    MCD_OPC_Decode, 218, 23, 71, // Opcode: TGEU_MM
/* 3142 */    MCD_OPC_FilterValue, 1, 100, 13, 0, // Skip to: 6575
/* 3147 */    MCD_OPC_CheckPredicate, 7, 95, 13, 0, // Skip to: 6575
/* 3152 */    MCD_OPC_Decode, 132, 24, 71, // Opcode: TNE_MM
/* 3156 */    MCD_OPC_FilterValue, 18, 115, 0, 0, // Skip to: 3276
/* 3161 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 3164 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 3178
/* 3169 */    MCD_OPC_CheckPredicate, 9, 73, 13, 0, // Skip to: 6575
/* 3174 */    MCD_OPC_Decode, 180, 12, 76, // Opcode: DPS_W_PH_MMR2
/* 3178 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 3192
/* 3183 */    MCD_OPC_CheckPredicate, 8, 59, 13, 0, // Skip to: 6575
/* 3188 */    MCD_OPC_Decode, 234, 18, 89, // Opcode: MULT_DSP_MM
/* 3192 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 3206
/* 3197 */    MCD_OPC_CheckPredicate, 9, 45, 13, 0, // Skip to: 6575
/* 3202 */    MCD_OPC_Decode, 178, 12, 76, // Opcode: DPSX_W_PH_MMR2
/* 3206 */    MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 3220
/* 3211 */    MCD_OPC_CheckPredicate, 8, 31, 13, 0, // Skip to: 6575
/* 3216 */    MCD_OPC_Decode, 232, 18, 89, // Opcode: MULTU_DSP_MM
/* 3220 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 3234
/* 3225 */    MCD_OPC_CheckPredicate, 8, 17, 13, 0, // Skip to: 6575
/* 3230 */    MCD_OPC_Decode, 174, 12, 76, // Opcode: DPSU_H_QBL_MM
/* 3234 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 3248
/* 3239 */    MCD_OPC_CheckPredicate, 9, 3, 13, 0, // Skip to: 6575
/* 3244 */    MCD_OPC_Decode, 229, 18, 76, // Opcode: MULSA_W_PH_MMR2
/* 3248 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 3262
/* 3253 */    MCD_OPC_CheckPredicate, 8, 245, 12, 0, // Skip to: 6575
/* 3258 */    MCD_OPC_Decode, 176, 12, 76, // Opcode: DPSU_H_QBR_MM
/* 3262 */    MCD_OPC_FilterValue, 7, 236, 12, 0, // Skip to: 6575
/* 3267 */    MCD_OPC_CheckPredicate, 8, 231, 12, 0, // Skip to: 6575
/* 3272 */    MCD_OPC_Decode, 227, 18, 76, // Opcode: MULSAQ_S_W_PH_MM
/* 3276 */    MCD_OPC_FilterValue, 19, 16, 0, 0, // Skip to: 3297
/* 3281 */    MCD_OPC_CheckPredicate, 10, 217, 12, 0, // Skip to: 6575
/* 3286 */    MCD_OPC_CheckField, 14, 2, 0, 210, 12, 0, // Skip to: 6575
/* 3293 */    MCD_OPC_Decode, 139, 17, 68, // Opcode: MFGC0_MM
/* 3297 */    MCD_OPC_FilterValue, 20, 31, 0, 0, // Skip to: 3333
/* 3302 */    MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 3305 */    MCD_OPC_FilterValue, 25, 9, 0, 0, // Skip to: 3319
/* 3310 */    MCD_OPC_CheckPredicate, 7, 188, 12, 0, // Skip to: 6575
/* 3315 */    MCD_OPC_Decode, 146, 9, 90, // Opcode: CFC2_MM
/* 3319 */    MCD_OPC_FilterValue, 27, 179, 12, 0, // Skip to: 6575
/* 3324 */    MCD_OPC_CheckPredicate, 7, 174, 12, 0, // Skip to: 6575
/* 3329 */    MCD_OPC_Decode, 181, 10, 91, // Opcode: CTC2_MM
/* 3333 */    MCD_OPC_FilterValue, 21, 87, 0, 0, // Skip to: 3425
/* 3338 */    MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 3341 */    MCD_OPC_FilterValue, 1, 16, 0, 0, // Skip to: 3362
/* 3346 */    MCD_OPC_CheckPredicate, 6, 152, 12, 0, // Skip to: 6575
/* 3351 */    MCD_OPC_CheckField, 21, 5, 0, 145, 12, 0, // Skip to: 6575
/* 3358 */    MCD_OPC_Decode, 155, 17, 92, // Opcode: MFHI_MM
/* 3362 */    MCD_OPC_FilterValue, 3, 16, 0, 0, // Skip to: 3383
/* 3367 */    MCD_OPC_CheckPredicate, 6, 131, 12, 0, // Skip to: 6575
/* 3372 */    MCD_OPC_CheckField, 21, 5, 0, 124, 12, 0, // Skip to: 6575
/* 3379 */    MCD_OPC_Decode, 161, 17, 92, // Opcode: MFLO_MM
/* 3383 */    MCD_OPC_FilterValue, 5, 16, 0, 0, // Skip to: 3404
/* 3388 */    MCD_OPC_CheckPredicate, 6, 110, 12, 0, // Skip to: 6575
/* 3393 */    MCD_OPC_CheckField, 21, 5, 0, 103, 12, 0, // Skip to: 6575
/* 3400 */    MCD_OPC_Decode, 183, 18, 92, // Opcode: MTHI_MM
/* 3404 */    MCD_OPC_FilterValue, 7, 94, 12, 0, // Skip to: 6575
/* 3409 */    MCD_OPC_CheckPredicate, 6, 89, 12, 0, // Skip to: 6575
/* 3414 */    MCD_OPC_CheckField, 21, 5, 0, 82, 12, 0, // Skip to: 6575
/* 3421 */    MCD_OPC_Decode, 190, 18, 92, // Opcode: MTLO_MM
/* 3425 */    MCD_OPC_FilterValue, 23, 16, 0, 0, // Skip to: 3446
/* 3430 */    MCD_OPC_CheckPredicate, 8, 68, 12, 0, // Skip to: 6575
/* 3435 */    MCD_OPC_CheckField, 11, 2, 0, 61, 12, 0, // Skip to: 6575
/* 3442 */    MCD_OPC_Decode, 147, 20, 93, // Opcode: REPL_QB_MM
/* 3446 */    MCD_OPC_FilterValue, 25, 115, 0, 0, // Skip to: 3566
/* 3451 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 3454 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 3468
/* 3459 */    MCD_OPC_CheckPredicate, 8, 39, 12, 0, // Skip to: 6575
/* 3464 */    MCD_OPC_Decode, 254, 19, 94, // Opcode: RDDSP_MM
/* 3468 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 3482
/* 3473 */    MCD_OPC_CheckPredicate, 8, 25, 12, 0, // Skip to: 6575
/* 3478 */    MCD_OPC_Decode, 251, 12, 95, // Opcode: EXTR_W_MM
/* 3482 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 3496
/* 3487 */    MCD_OPC_CheckPredicate, 8, 11, 12, 0, // Skip to: 6575
/* 3492 */    MCD_OPC_Decode, 166, 24, 94, // Opcode: WRDSP_MM
/* 3496 */    MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 3510
/* 3501 */    MCD_OPC_CheckPredicate, 8, 253, 11, 0, // Skip to: 6575
/* 3506 */    MCD_OPC_Decode, 247, 12, 95, // Opcode: EXTR_R_W_MM
/* 3510 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 3524
/* 3515 */    MCD_OPC_CheckPredicate, 8, 239, 11, 0, // Skip to: 6575
/* 3520 */    MCD_OPC_Decode, 235, 12, 95, // Opcode: EXTP_MM
/* 3524 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 3538
/* 3529 */    MCD_OPC_CheckPredicate, 8, 225, 11, 0, // Skip to: 6575
/* 3534 */    MCD_OPC_Decode, 245, 12, 95, // Opcode: EXTR_RS_W_MM
/* 3538 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 3552
/* 3543 */    MCD_OPC_CheckPredicate, 8, 211, 11, 0, // Skip to: 6575
/* 3548 */    MCD_OPC_Decode, 232, 12, 95, // Opcode: EXTPDP_MM
/* 3552 */    MCD_OPC_FilterValue, 7, 202, 11, 0, // Skip to: 6575
/* 3557 */    MCD_OPC_CheckPredicate, 8, 197, 11, 0, // Skip to: 6575
/* 3562 */    MCD_OPC_Decode, 249, 12, 95, // Opcode: EXTR_S_H_MM
/* 3566 */    MCD_OPC_FilterValue, 26, 115, 0, 0, // Skip to: 3686
/* 3571 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 3574 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 3588
/* 3579 */    MCD_OPC_CheckPredicate, 8, 175, 11, 0, // Skip to: 6575
/* 3584 */    MCD_OPC_Decode, 166, 12, 76, // Opcode: DPSQ_S_W_PH_MM
/* 3588 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 3602
/* 3593 */    MCD_OPC_CheckPredicate, 8, 161, 11, 0, // Skip to: 6575
/* 3598 */    MCD_OPC_Decode, 243, 12, 78, // Opcode: EXTRV_W_MM
/* 3602 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 3616
/* 3607 */    MCD_OPC_CheckPredicate, 8, 147, 11, 0, // Skip to: 6575
/* 3612 */    MCD_OPC_Decode, 164, 12, 76, // Opcode: DPSQ_SA_L_W_MM
/* 3616 */    MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 3630
/* 3621 */    MCD_OPC_CheckPredicate, 8, 133, 11, 0, // Skip to: 6575
/* 3626 */    MCD_OPC_Decode, 239, 12, 78, // Opcode: EXTRV_R_W_MM
/* 3630 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 3644
/* 3635 */    MCD_OPC_CheckPredicate, 9, 119, 11, 0, // Skip to: 6575
/* 3640 */    MCD_OPC_Decode, 162, 12, 76, // Opcode: DPSQX_S_W_PH_MMR2
/* 3644 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 3658
/* 3649 */    MCD_OPC_CheckPredicate, 8, 105, 11, 0, // Skip to: 6575
/* 3654 */    MCD_OPC_Decode, 237, 12, 78, // Opcode: EXTRV_RS_W_MM
/* 3658 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 3672
/* 3663 */    MCD_OPC_CheckPredicate, 9, 91, 11, 0, // Skip to: 6575
/* 3668 */    MCD_OPC_Decode, 160, 12, 76, // Opcode: DPSQX_SA_W_PH_MMR2
/* 3672 */    MCD_OPC_FilterValue, 7, 82, 11, 0, // Skip to: 6575
/* 3677 */    MCD_OPC_CheckPredicate, 8, 77, 11, 0, // Skip to: 6575
/* 3682 */    MCD_OPC_Decode, 241, 12, 78, // Opcode: EXTRV_S_H_MM
/* 3686 */    MCD_OPC_FilterValue, 27, 16, 0, 0, // Skip to: 3707
/* 3691 */    MCD_OPC_CheckPredicate, 10, 63, 11, 0, // Skip to: 6575
/* 3696 */    MCD_OPC_CheckField, 14, 2, 0, 56, 11, 0, // Skip to: 6575
/* 3703 */    MCD_OPC_Decode, 168, 18, 69, // Opcode: MTGC0_MM
/* 3707 */    MCD_OPC_FilterValue, 28, 47, 0, 0, // Skip to: 3759
/* 3712 */    MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 3715 */    MCD_OPC_FilterValue, 1, 25, 0, 0, // Skip to: 3745
/* 3720 */    MCD_OPC_CheckPredicate, 6, 11, 0, 0, // Skip to: 3736
/* 3725 */    MCD_OPC_CheckField, 21, 5, 0, 4, 0, 0, // Skip to: 3736
/* 3732 */    MCD_OPC_Decode, 144, 15, 92, // Opcode: JR_MM
/* 3736 */    MCD_OPC_CheckPredicate, 6, 18, 11, 0, // Skip to: 6575
/* 3741 */    MCD_OPC_Decode, 249, 14, 80, // Opcode: JALR_MM
/* 3745 */    MCD_OPC_FilterValue, 9, 9, 11, 0, // Skip to: 6575
/* 3750 */    MCD_OPC_CheckPredicate, 6, 4, 11, 0, // Skip to: 6575
/* 3755 */    MCD_OPC_Decode, 246, 14, 80, // Opcode: JALRS_MM
/* 3759 */    MCD_OPC_FilterValue, 29, 251, 10, 0, // Skip to: 6575
/* 3764 */    MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 3767 */    MCD_OPC_FilterValue, 8, 16, 0, 0, // Skip to: 3788
/* 3772 */    MCD_OPC_CheckPredicate, 7, 238, 10, 0, // Skip to: 6575
/* 3777 */    MCD_OPC_CheckField, 21, 5, 0, 231, 10, 0, // Skip to: 6575
/* 3784 */    MCD_OPC_Decode, 232, 11, 92, // Opcode: DI_MM
/* 3788 */    MCD_OPC_FilterValue, 10, 222, 10, 0, // Skip to: 6575
/* 3793 */    MCD_OPC_CheckPredicate, 7, 217, 10, 0, // Skip to: 6575
/* 3798 */    MCD_OPC_CheckField, 21, 5, 0, 210, 10, 0, // Skip to: 6575
/* 3805 */    MCD_OPC_Decode, 211, 12, 92, // Opcode: EI_MM
/* 3809 */    MCD_OPC_FilterValue, 61, 201, 10, 0, // Skip to: 6575
/* 3814 */    MCD_OPC_CheckPredicate, 8, 196, 10, 0, // Skip to: 6575
/* 3819 */    MCD_OPC_CheckField, 6, 5, 0, 189, 10, 0, // Skip to: 6575
/* 3826 */    MCD_OPC_Decode, 145, 20, 96, // Opcode: REPL_PH_MM
/* 3830 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 3844
/* 3835 */    MCD_OPC_CheckPredicate, 6, 175, 10, 0, // Skip to: 6575
/* 3840 */    MCD_OPC_Decode, 203, 6, 97, // Opcode: ADDi_MM
/* 3844 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 3858
/* 3849 */    MCD_OPC_CheckPredicate, 7, 161, 10, 0, // Skip to: 6575
/* 3854 */    MCD_OPC_Decode, 178, 15, 98, // Opcode: LBu_MM
/* 3858 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 3872
/* 3863 */    MCD_OPC_CheckPredicate, 7, 147, 10, 0, // Skip to: 6575
/* 3868 */    MCD_OPC_Decode, 202, 20, 98, // Opcode: SB_MM
/* 3872 */    MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 3886
/* 3877 */    MCD_OPC_CheckPredicate, 7, 133, 10, 0, // Skip to: 6575
/* 3882 */    MCD_OPC_Decode, 170, 15, 98, // Opcode: LB_MM
/* 3886 */    MCD_OPC_FilterValue, 8, 73, 0, 0, // Skip to: 3964
/* 3891 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 3894 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 3908
/* 3899 */    MCD_OPC_CheckPredicate, 7, 111, 10, 0, // Skip to: 6575
/* 3904 */    MCD_OPC_Decode, 161, 16, 99, // Opcode: LWP_MM
/* 3908 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 3922
/* 3913 */    MCD_OPC_CheckPredicate, 7, 97, 10, 0, // Skip to: 6575
/* 3918 */    MCD_OPC_Decode, 156, 16, 99, // Opcode: LWM32_MM
/* 3922 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 3936
/* 3927 */    MCD_OPC_CheckPredicate, 6, 83, 10, 0, // Skip to: 6575
/* 3932 */    MCD_OPC_Decode, 249, 8, 100, // Opcode: CACHE_MM
/* 3936 */    MCD_OPC_FilterValue, 9, 9, 0, 0, // Skip to: 3950
/* 3941 */    MCD_OPC_CheckPredicate, 7, 69, 10, 0, // Skip to: 6575
/* 3946 */    MCD_OPC_Decode, 156, 23, 99, // Opcode: SWP_MM
/* 3950 */    MCD_OPC_FilterValue, 13, 60, 10, 0, // Skip to: 6575
/* 3955 */    MCD_OPC_CheckPredicate, 7, 55, 10, 0, // Skip to: 6575
/* 3960 */    MCD_OPC_Decode, 153, 23, 99, // Opcode: SWM32_MM
/* 3964 */    MCD_OPC_FilterValue, 12, 9, 0, 0, // Skip to: 3978
/* 3969 */    MCD_OPC_CheckPredicate, 6, 41, 10, 0, // Skip to: 6575
/* 3974 */    MCD_OPC_Decode, 205, 6, 97, // Opcode: ADDiu_MM
/* 3978 */    MCD_OPC_FilterValue, 13, 9, 0, 0, // Skip to: 3992
/* 3983 */    MCD_OPC_CheckPredicate, 7, 27, 10, 0, // Skip to: 6575
/* 3988 */    MCD_OPC_Decode, 230, 15, 98, // Opcode: LHu_MM
/* 3992 */    MCD_OPC_FilterValue, 14, 9, 0, 0, // Skip to: 4006
/* 3997 */    MCD_OPC_CheckPredicate, 7, 13, 10, 0, // Skip to: 6575
/* 4002 */    MCD_OPC_Decode, 204, 21, 98, // Opcode: SH_MM
/* 4006 */    MCD_OPC_FilterValue, 15, 9, 0, 0, // Skip to: 4020
/* 4011 */    MCD_OPC_CheckPredicate, 7, 255, 9, 0, // Skip to: 6575
/* 4016 */    MCD_OPC_Decode, 223, 15, 98, // Opcode: LH_MM
/* 4020 */    MCD_OPC_FilterValue, 16, 83, 1, 0, // Skip to: 4364
/* 4025 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 4028 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 4042
/* 4033 */    MCD_OPC_CheckPredicate, 6, 233, 9, 0, // Skip to: 6575
/* 4038 */    MCD_OPC_Decode, 165, 8, 101, // Opcode: BLTZ_MM
/* 4042 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 4056
/* 4047 */    MCD_OPC_CheckPredicate, 6, 219, 9, 0, // Skip to: 6575
/* 4052 */    MCD_OPC_Decode, 160, 8, 101, // Opcode: BLTZAL_MM
/* 4056 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 4070
/* 4061 */    MCD_OPC_CheckPredicate, 6, 205, 9, 0, // Skip to: 6575
/* 4066 */    MCD_OPC_Decode, 231, 7, 101, // Opcode: BGEZ_MM
/* 4070 */    MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 4084
/* 4075 */    MCD_OPC_CheckPredicate, 6, 191, 9, 0, // Skip to: 6575
/* 4080 */    MCD_OPC_Decode, 226, 7, 101, // Opcode: BGEZAL_MM
/* 4084 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 4098
/* 4089 */    MCD_OPC_CheckPredicate, 6, 177, 9, 0, // Skip to: 6575
/* 4094 */    MCD_OPC_Decode, 142, 8, 101, // Opcode: BLEZ_MM
/* 4098 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 4112
/* 4103 */    MCD_OPC_CheckPredicate, 6, 163, 9, 0, // Skip to: 6575
/* 4108 */    MCD_OPC_Decode, 195, 8, 101, // Opcode: BNEZC_MM
/* 4112 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 4126
/* 4117 */    MCD_OPC_CheckPredicate, 6, 149, 9, 0, // Skip to: 6575
/* 4122 */    MCD_OPC_Decode, 240, 7, 101, // Opcode: BGTZ_MM
/* 4126 */    MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 4140
/* 4131 */    MCD_OPC_CheckPredicate, 6, 135, 9, 0, // Skip to: 6575
/* 4136 */    MCD_OPC_Decode, 205, 7, 101, // Opcode: BEQZC_MM
/* 4140 */    MCD_OPC_FilterValue, 8, 9, 0, 0, // Skip to: 4154
/* 4145 */    MCD_OPC_CheckPredicate, 6, 121, 9, 0, // Skip to: 6575
/* 4150 */    MCD_OPC_Decode, 253, 23, 102, // Opcode: TLTI_MM
/* 4154 */    MCD_OPC_FilterValue, 9, 9, 0, 0, // Skip to: 4168
/* 4159 */    MCD_OPC_CheckPredicate, 6, 107, 9, 0, // Skip to: 6575
/* 4164 */    MCD_OPC_Decode, 216, 23, 102, // Opcode: TGEI_MM
/* 4168 */    MCD_OPC_FilterValue, 10, 9, 0, 0, // Skip to: 4182
/* 4173 */    MCD_OPC_CheckPredicate, 6, 93, 9, 0, // Skip to: 6575
/* 4178 */    MCD_OPC_Decode, 252, 23, 102, // Opcode: TLTIU_MM
/* 4182 */    MCD_OPC_FilterValue, 11, 9, 0, 0, // Skip to: 4196
/* 4187 */    MCD_OPC_CheckPredicate, 6, 79, 9, 0, // Skip to: 6575
/* 4192 */    MCD_OPC_Decode, 215, 23, 102, // Opcode: TGEIU_MM
/* 4196 */    MCD_OPC_FilterValue, 12, 9, 0, 0, // Skip to: 4210
/* 4201 */    MCD_OPC_CheckPredicate, 6, 65, 9, 0, // Skip to: 6575
/* 4206 */    MCD_OPC_Decode, 131, 24, 102, // Opcode: TNEI_MM
/* 4210 */    MCD_OPC_FilterValue, 13, 9, 0, 0, // Skip to: 4224
/* 4215 */    MCD_OPC_CheckPredicate, 6, 51, 9, 0, // Skip to: 6575
/* 4220 */    MCD_OPC_Decode, 130, 16, 103, // Opcode: LUi_MM
/* 4224 */    MCD_OPC_FilterValue, 14, 9, 0, 0, // Skip to: 4238
/* 4229 */    MCD_OPC_CheckPredicate, 6, 37, 9, 0, // Skip to: 6575
/* 4234 */    MCD_OPC_Decode, 209, 23, 102, // Opcode: TEQI_MM
/* 4238 */    MCD_OPC_FilterValue, 16, 9, 0, 0, // Skip to: 4252
/* 4243 */    MCD_OPC_CheckPredicate, 6, 23, 9, 0, // Skip to: 6575
/* 4248 */    MCD_OPC_Decode, 175, 23, 104, // Opcode: SYNCI_MM
/* 4252 */    MCD_OPC_FilterValue, 17, 9, 0, 0, // Skip to: 4266
/* 4257 */    MCD_OPC_CheckPredicate, 6, 9, 9, 0, // Skip to: 6575
/* 4262 */    MCD_OPC_Decode, 159, 8, 101, // Opcode: BLTZALS_MM
/* 4266 */    MCD_OPC_FilterValue, 19, 9, 0, 0, // Skip to: 4280
/* 4271 */    MCD_OPC_CheckPredicate, 6, 251, 8, 0, // Skip to: 6575
/* 4276 */    MCD_OPC_Decode, 225, 7, 101, // Opcode: BGEZALS_MM
/* 4280 */    MCD_OPC_FilterValue, 25, 16, 0, 0, // Skip to: 4301
/* 4285 */    MCD_OPC_CheckPredicate, 11, 237, 8, 0, // Skip to: 6575
/* 4290 */    MCD_OPC_CheckField, 16, 5, 0, 230, 8, 0, // Skip to: 6575
/* 4297 */    MCD_OPC_Decode, 209, 8, 105, // Opcode: BPOSGE32C_MMR3
/* 4301 */    MCD_OPC_FilterValue, 27, 16, 0, 0, // Skip to: 4322
/* 4306 */    MCD_OPC_CheckPredicate, 12, 216, 8, 0, // Skip to: 6575
/* 4311 */    MCD_OPC_CheckField, 16, 5, 0, 209, 8, 0, // Skip to: 6575
/* 4318 */    MCD_OPC_Decode, 210, 8, 106, // Opcode: BPOSGE32_MM
/* 4322 */    MCD_OPC_FilterValue, 28, 16, 0, 0, // Skip to: 4343
/* 4327 */    MCD_OPC_CheckPredicate, 13, 195, 8, 0, // Skip to: 6575
/* 4332 */    MCD_OPC_CheckField, 16, 2, 0, 188, 8, 0, // Skip to: 6575
/* 4339 */    MCD_OPC_Decode, 168, 7, 107, // Opcode: BC1F_MM
/* 4343 */    MCD_OPC_FilterValue, 29, 179, 8, 0, // Skip to: 6575
/* 4348 */    MCD_OPC_CheckPredicate, 13, 174, 8, 0, // Skip to: 6575
/* 4353 */    MCD_OPC_CheckField, 16, 2, 0, 167, 8, 0, // Skip to: 6575
/* 4360 */    MCD_OPC_Decode, 173, 7, 107, // Opcode: BC1T_MM
/* 4364 */    MCD_OPC_FilterValue, 20, 9, 0, 0, // Skip to: 4378
/* 4369 */    MCD_OPC_CheckPredicate, 6, 153, 8, 0, // Skip to: 6575
/* 4374 */    MCD_OPC_Decode, 177, 19, 108, // Opcode: ORi_MM
/* 4378 */    MCD_OPC_FilterValue, 21, 234, 5, 0, // Skip to: 5897
/* 4383 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 4386 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 4400
/* 4391 */    MCD_OPC_CheckPredicate, 14, 131, 8, 0, // Skip to: 6575
/* 4396 */    MCD_OPC_Decode, 219, 16, 109, // Opcode: MADD_S_MM
/* 4400 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 4414
/* 4405 */    MCD_OPC_CheckPredicate, 14, 117, 8, 0, // Skip to: 6575
/* 4410 */    MCD_OPC_Decode, 143, 19, 109, // Opcode: NMADD_S_MM
/* 4414 */    MCD_OPC_FilterValue, 8, 59, 0, 0, // Skip to: 4478
/* 4419 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 4422 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 4436
/* 4427 */    MCD_OPC_CheckPredicate, 13, 95, 8, 0, // Skip to: 6575
/* 4432 */    MCD_OPC_Decode, 173, 16, 110, // Opcode: LWXC1_MM
/* 4436 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 4450
/* 4441 */    MCD_OPC_CheckPredicate, 13, 81, 8, 0, // Skip to: 6575
/* 4446 */    MCD_OPC_Decode, 166, 23, 110, // Opcode: SWXC1_MM
/* 4450 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 4464
/* 4455 */    MCD_OPC_CheckPredicate, 15, 67, 8, 0, // Skip to: 6575
/* 4460 */    MCD_OPC_Decode, 255, 15, 111, // Opcode: LUXC1_MM
/* 4464 */    MCD_OPC_FilterValue, 6, 58, 8, 0, // Skip to: 6575
/* 4469 */    MCD_OPC_CheckPredicate, 15, 53, 8, 0, // Skip to: 6575
/* 4474 */    MCD_OPC_Decode, 255, 22, 111, // Opcode: SUXC1_MM
/* 4478 */    MCD_OPC_FilterValue, 9, 9, 0, 0, // Skip to: 4492
/* 4483 */    MCD_OPC_CheckPredicate, 16, 39, 8, 0, // Skip to: 6575
/* 4488 */    MCD_OPC_Decode, 211, 16, 112, // Opcode: MADD_D32_MM
/* 4492 */    MCD_OPC_FilterValue, 10, 9, 0, 0, // Skip to: 4506
/* 4497 */    MCD_OPC_CheckPredicate, 16, 25, 8, 0, // Skip to: 6575
/* 4502 */    MCD_OPC_Decode, 140, 19, 112, // Opcode: NMADD_D32_MM
/* 4506 */    MCD_OPC_FilterValue, 32, 101, 0, 0, // Skip to: 4612
/* 4511 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 4514 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 4535
/* 4519 */    MCD_OPC_CheckPredicate, 13, 3, 8, 0, // Skip to: 6575
/* 4524 */    MCD_OPC_CheckField, 11, 2, 0, 252, 7, 0, // Skip to: 6575
/* 4531 */    MCD_OPC_Decode, 224, 17, 113, // Opcode: MOVF_S_MM
/* 4535 */    MCD_OPC_FilterValue, 1, 16, 0, 0, // Skip to: 4556
/* 4540 */    MCD_OPC_CheckPredicate, 13, 238, 7, 0, // Skip to: 6575
/* 4545 */    MCD_OPC_CheckField, 11, 2, 0, 231, 7, 0, // Skip to: 6575
/* 4552 */    MCD_OPC_Decode, 245, 17, 113, // Opcode: MOVT_S_MM
/* 4556 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 4570
/* 4561 */    MCD_OPC_CheckPredicate, 6, 217, 7, 0, // Skip to: 6575
/* 4566 */    MCD_OPC_Decode, 241, 19, 114, // Opcode: PREFX_MM
/* 4570 */    MCD_OPC_FilterValue, 8, 16, 0, 0, // Skip to: 4591
/* 4575 */    MCD_OPC_CheckPredicate, 17, 203, 7, 0, // Skip to: 6575
/* 4580 */    MCD_OPC_CheckField, 11, 2, 0, 196, 7, 0, // Skip to: 6575
/* 4587 */    MCD_OPC_Decode, 218, 17, 115, // Opcode: MOVF_D32_MM
/* 4591 */    MCD_OPC_FilterValue, 9, 187, 7, 0, // Skip to: 6575
/* 4596 */    MCD_OPC_CheckPredicate, 17, 182, 7, 0, // Skip to: 6575
/* 4601 */    MCD_OPC_CheckField, 11, 2, 0, 175, 7, 0, // Skip to: 6575
/* 4608 */    MCD_OPC_Decode, 239, 17, 115, // Opcode: MOVT_D32_MM
/* 4612 */    MCD_OPC_FilterValue, 33, 9, 0, 0, // Skip to: 4626
/* 4617 */    MCD_OPC_CheckPredicate, 14, 161, 7, 0, // Skip to: 6575
/* 4622 */    MCD_OPC_Decode, 155, 18, 109, // Opcode: MSUB_S_MM
/* 4626 */    MCD_OPC_FilterValue, 34, 9, 0, 0, // Skip to: 4640
/* 4631 */    MCD_OPC_CheckPredicate, 14, 147, 7, 0, // Skip to: 6575
/* 4636 */    MCD_OPC_Decode, 148, 19, 109, // Opcode: NMSUB_S_MM
/* 4640 */    MCD_OPC_FilterValue, 41, 9, 0, 0, // Skip to: 4654
/* 4645 */    MCD_OPC_CheckPredicate, 16, 133, 7, 0, // Skip to: 6575
/* 4650 */    MCD_OPC_Decode, 147, 18, 112, // Opcode: MSUB_D32_MM
/* 4654 */    MCD_OPC_FilterValue, 42, 9, 0, 0, // Skip to: 4668
/* 4659 */    MCD_OPC_CheckPredicate, 16, 119, 7, 0, // Skip to: 6575
/* 4664 */    MCD_OPC_Decode, 145, 19, 112, // Opcode: NMSUB_D32_MM
/* 4668 */    MCD_OPC_FilterValue, 48, 59, 0, 0, // Skip to: 4732
/* 4673 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 4676 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 4690
/* 4681 */    MCD_OPC_CheckPredicate, 18, 97, 7, 0, // Skip to: 6575
/* 4686 */    MCD_OPC_Decode, 138, 13, 116, // Opcode: FADD_D32_MM
/* 4690 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 4704
/* 4695 */    MCD_OPC_CheckPredicate, 18, 83, 7, 0, // Skip to: 6575
/* 4700 */    MCD_OPC_Decode, 156, 14, 116, // Opcode: FSUB_D32_MM
/* 4704 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 4718
/* 4709 */    MCD_OPC_CheckPredicate, 18, 69, 7, 0, // Skip to: 6575
/* 4714 */    MCD_OPC_Decode, 239, 13, 116, // Opcode: FMUL_D32_MM
/* 4718 */    MCD_OPC_FilterValue, 7, 60, 7, 0, // Skip to: 6575
/* 4723 */    MCD_OPC_CheckPredicate, 18, 55, 7, 0, // Skip to: 6575
/* 4728 */    MCD_OPC_Decode, 177, 13, 116, // Opcode: FDIV_D32_MM
/* 4732 */    MCD_OPC_FilterValue, 56, 59, 0, 0, // Skip to: 4796
/* 4737 */    MCD_OPC_ExtractField, 6, 4,  // Inst{9-6} ...
/* 4740 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 4754
/* 4745 */    MCD_OPC_CheckPredicate, 13, 33, 7, 0, // Skip to: 6575
/* 4750 */    MCD_OPC_Decode, 236, 17, 117, // Opcode: MOVN_I_S_MM
/* 4754 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 4768
/* 4759 */    MCD_OPC_CheckPredicate, 13, 19, 7, 0, // Skip to: 6575
/* 4764 */    MCD_OPC_Decode, 129, 18, 117, // Opcode: MOVZ_I_S_MM
/* 4768 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 4782
/* 4773 */    MCD_OPC_CheckPredicate, 17, 5, 7, 0, // Skip to: 6575
/* 4778 */    MCD_OPC_Decode, 230, 17, 118, // Opcode: MOVN_I_D32_MM
/* 4782 */    MCD_OPC_FilterValue, 5, 252, 6, 0, // Skip to: 6575
/* 4787 */    MCD_OPC_CheckPredicate, 17, 247, 6, 0, // Skip to: 6575
/* 4792 */    MCD_OPC_Decode, 251, 17, 118, // Opcode: MOVZ_I_D32_MM
/* 4796 */    MCD_OPC_FilterValue, 59, 96, 2, 0, // Skip to: 5409
/* 4801 */    MCD_OPC_ExtractField, 6, 7,  // Inst{12-6} ...
/* 4804 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 4825
/* 4809 */    MCD_OPC_CheckPredicate, 19, 225, 6, 0, // Skip to: 6575
/* 4814 */    MCD_OPC_CheckField, 13, 3, 1, 218, 6, 0, // Skip to: 6575
/* 4821 */    MCD_OPC_Decode, 134, 17, 119, // Opcode: MFC1_MM
/* 4825 */    MCD_OPC_FilterValue, 1, 16, 0, 0, // Skip to: 4846
/* 4830 */    MCD_OPC_CheckPredicate, 18, 204, 6, 0, // Skip to: 6575
/* 4835 */    MCD_OPC_CheckField, 13, 3, 1, 197, 6, 0, // Skip to: 6575
/* 4842 */    MCD_OPC_Decode, 228, 13, 120, // Opcode: FMOV_D32_MM
/* 4846 */    MCD_OPC_FilterValue, 4, 31, 0, 0, // Skip to: 4882
/* 4851 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 4854 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 4868
/* 4859 */    MCD_OPC_CheckPredicate, 20, 175, 6, 0, // Skip to: 6575
/* 4864 */    MCD_OPC_Decode, 197, 10, 121, // Opcode: CVT_L_S_MM
/* 4868 */    MCD_OPC_FilterValue, 2, 166, 6, 0, // Skip to: 6575
/* 4873 */    MCD_OPC_CheckPredicate, 20, 161, 6, 0, // Skip to: 6575
/* 4878 */    MCD_OPC_Decode, 194, 10, 122, // Opcode: CVT_L_D64_MM
/* 4882 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 4896
/* 4887 */    MCD_OPC_CheckPredicate, 13, 147, 6, 0, // Skip to: 6575
/* 4892 */    MCD_OPC_Decode, 222, 17, 123, // Opcode: MOVF_I_MM
/* 4896 */    MCD_OPC_FilterValue, 8, 31, 0, 0, // Skip to: 4932
/* 4901 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 4904 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 4918
/* 4909 */    MCD_OPC_CheckPredicate, 19, 125, 6, 0, // Skip to: 6575
/* 4914 */    MCD_OPC_Decode, 178, 20, 124, // Opcode: RSQRT_S_MM
/* 4918 */    MCD_OPC_FilterValue, 2, 116, 6, 0, // Skip to: 6575
/* 4923 */    MCD_OPC_CheckPredicate, 18, 111, 6, 0, // Skip to: 6575
/* 4928 */    MCD_OPC_Decode, 174, 20, 120, // Opcode: RSQRT_D32_MM
/* 4932 */    MCD_OPC_FilterValue, 13, 31, 0, 0, // Skip to: 4968
/* 4937 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 4940 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 4954
/* 4945 */    MCD_OPC_CheckPredicate, 19, 89, 6, 0, // Skip to: 6575
/* 4950 */    MCD_OPC_Decode, 135, 13, 124, // Opcode: FABS_S_MM
/* 4954 */    MCD_OPC_FilterValue, 1, 80, 6, 0, // Skip to: 6575
/* 4959 */    MCD_OPC_CheckPredicate, 18, 75, 6, 0, // Skip to: 6575
/* 4964 */    MCD_OPC_Decode, 131, 13, 120, // Opcode: FABS_D32_MM
/* 4968 */    MCD_OPC_FilterValue, 32, 16, 0, 0, // Skip to: 4989
/* 4973 */    MCD_OPC_CheckPredicate, 19, 61, 6, 0, // Skip to: 6575
/* 4978 */    MCD_OPC_CheckField, 13, 3, 1, 54, 6, 0, // Skip to: 6575
/* 4985 */    MCD_OPC_Decode, 163, 18, 125, // Opcode: MTC1_MM
/* 4989 */    MCD_OPC_FilterValue, 36, 31, 0, 0, // Skip to: 5025
/* 4994 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 4997 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 5011
/* 5002 */    MCD_OPC_CheckPredicate, 19, 32, 6, 0, // Skip to: 6575
/* 5007 */    MCD_OPC_Decode, 218, 10, 124, // Opcode: CVT_W_S_MM
/* 5011 */    MCD_OPC_FilterValue, 2, 23, 6, 0, // Skip to: 6575
/* 5016 */    MCD_OPC_CheckPredicate, 18, 18, 6, 0, // Skip to: 6575
/* 5021 */    MCD_OPC_Decode, 214, 10, 126, // Opcode: CVT_W_D32_MM
/* 5025 */    MCD_OPC_FilterValue, 37, 9, 0, 0, // Skip to: 5039
/* 5030 */    MCD_OPC_CheckPredicate, 13, 4, 6, 0, // Skip to: 6575
/* 5035 */    MCD_OPC_Decode, 243, 17, 123, // Opcode: MOVT_I_MM
/* 5039 */    MCD_OPC_FilterValue, 40, 31, 0, 0, // Skip to: 5075
/* 5044 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 5047 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 5061
/* 5052 */    MCD_OPC_CheckPredicate, 19, 238, 5, 0, // Skip to: 6575
/* 5057 */    MCD_OPC_Decode, 152, 14, 124, // Opcode: FSQRT_S_MM
/* 5061 */    MCD_OPC_FilterValue, 2, 229, 5, 0, // Skip to: 6575
/* 5066 */    MCD_OPC_CheckPredicate, 18, 224, 5, 0, // Skip to: 6575
/* 5071 */    MCD_OPC_Decode, 148, 14, 120, // Opcode: FSQRT_D32_MM
/* 5075 */    MCD_OPC_FilterValue, 44, 59, 0, 0, // Skip to: 5139
/* 5080 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 5083 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 5097
/* 5088 */    MCD_OPC_CheckPredicate, 19, 202, 5, 0, // Skip to: 6575
/* 5093 */    MCD_OPC_Decode, 215, 13, 124, // Opcode: FLOOR_W_S_MM
/* 5097 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 5111
/* 5102 */    MCD_OPC_CheckPredicate, 19, 188, 5, 0, // Skip to: 6575
/* 5107 */    MCD_OPC_Decode, 143, 24, 124, // Opcode: TRUNC_W_S_MM
/* 5111 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 5125
/* 5116 */    MCD_OPC_CheckPredicate, 18, 174, 5, 0, // Skip to: 6575
/* 5121 */    MCD_OPC_Decode, 213, 13, 126, // Opcode: FLOOR_W_MM
/* 5125 */    MCD_OPC_FilterValue, 3, 165, 5, 0, // Skip to: 6575
/* 5130 */    MCD_OPC_CheckPredicate, 18, 160, 5, 0, // Skip to: 6575
/* 5135 */    MCD_OPC_Decode, 141, 24, 126, // Opcode: TRUNC_W_MM
/* 5139 */    MCD_OPC_FilterValue, 45, 16, 0, 0, // Skip to: 5160
/* 5144 */    MCD_OPC_CheckPredicate, 18, 146, 5, 0, // Skip to: 6575
/* 5149 */    MCD_OPC_CheckField, 13, 3, 1, 139, 5, 0, // Skip to: 6575
/* 5156 */    MCD_OPC_Decode, 248, 13, 120, // Opcode: FNEG_D32_MM
/* 5160 */    MCD_OPC_FilterValue, 64, 32, 0, 0, // Skip to: 5197
/* 5165 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 5168 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 5182
/* 5173 */    MCD_OPC_CheckPredicate, 19, 117, 5, 0, // Skip to: 6575
/* 5178 */    MCD_OPC_Decode, 145, 9, 127, // Opcode: CFC1_MM
/* 5182 */    MCD_OPC_FilterValue, 1, 108, 5, 0, // Skip to: 6575
/* 5187 */    MCD_OPC_CheckPredicate, 18, 103, 5, 0, // Skip to: 6575
/* 5192 */    MCD_OPC_Decode, 144, 17, 128, 1, // Opcode: MFHC1_D32_MM
/* 5197 */    MCD_OPC_FilterValue, 72, 31, 0, 0, // Skip to: 5233
/* 5202 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 5205 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 5219
/* 5210 */    MCD_OPC_CheckPredicate, 19, 80, 5, 0, // Skip to: 6575
/* 5215 */    MCD_OPC_Decode, 139, 20, 124, // Opcode: RECIP_S_MM
/* 5219 */    MCD_OPC_FilterValue, 2, 71, 5, 0, // Skip to: 6575
/* 5224 */    MCD_OPC_CheckPredicate, 18, 66, 5, 0, // Skip to: 6575
/* 5229 */    MCD_OPC_Decode, 135, 20, 120, // Opcode: RECIP_D32_MM
/* 5233 */    MCD_OPC_FilterValue, 77, 33, 0, 0, // Skip to: 5271
/* 5238 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 5241 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 5256
/* 5246 */    MCD_OPC_CheckPredicate, 18, 44, 5, 0, // Skip to: 6575
/* 5251 */    MCD_OPC_Decode, 184, 10, 129, 1, // Opcode: CVT_D32_S_MM
/* 5256 */    MCD_OPC_FilterValue, 1, 34, 5, 0, // Skip to: 6575
/* 5261 */    MCD_OPC_CheckPredicate, 18, 29, 5, 0, // Skip to: 6575
/* 5266 */    MCD_OPC_Decode, 186, 10, 129, 1, // Opcode: CVT_D32_W_MM
/* 5271 */    MCD_OPC_FilterValue, 96, 33, 0, 0, // Skip to: 5309
/* 5276 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 5279 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 5294
/* 5284 */    MCD_OPC_CheckPredicate, 19, 6, 5, 0, // Skip to: 6575
/* 5289 */    MCD_OPC_Decode, 180, 10, 130, 1, // Opcode: CTC1_MM
/* 5294 */    MCD_OPC_FilterValue, 1, 252, 4, 0, // Skip to: 6575
/* 5299 */    MCD_OPC_CheckPredicate, 18, 247, 4, 0, // Skip to: 6575
/* 5304 */    MCD_OPC_Decode, 173, 18, 131, 1, // Opcode: MTHC1_D32_MM
/* 5309 */    MCD_OPC_FilterValue, 108, 59, 0, 0, // Skip to: 5373
/* 5314 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 5317 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 5331
/* 5322 */    MCD_OPC_CheckPredicate, 19, 224, 4, 0, // Skip to: 6575
/* 5327 */    MCD_OPC_Decode, 134, 9, 124, // Opcode: CEIL_W_S_MM
/* 5331 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 5345
/* 5336 */    MCD_OPC_CheckPredicate, 19, 210, 4, 0, // Skip to: 6575
/* 5341 */    MCD_OPC_Decode, 171, 20, 124, // Opcode: ROUND_W_S_MM
/* 5345 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 5359
/* 5350 */    MCD_OPC_CheckPredicate, 18, 196, 4, 0, // Skip to: 6575
/* 5355 */    MCD_OPC_Decode, 132, 9, 126, // Opcode: CEIL_W_MM
/* 5359 */    MCD_OPC_FilterValue, 3, 187, 4, 0, // Skip to: 6575
/* 5364 */    MCD_OPC_CheckPredicate, 18, 182, 4, 0, // Skip to: 6575
/* 5369 */    MCD_OPC_Decode, 169, 20, 126, // Opcode: ROUND_W_MM
/* 5373 */    MCD_OPC_FilterValue, 109, 173, 4, 0, // Skip to: 6575
/* 5378 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 5381 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 5395
/* 5386 */    MCD_OPC_CheckPredicate, 18, 160, 4, 0, // Skip to: 6575
/* 5391 */    MCD_OPC_Decode, 203, 10, 126, // Opcode: CVT_S_D32_MM
/* 5395 */    MCD_OPC_FilterValue, 1, 151, 4, 0, // Skip to: 6575
/* 5400 */    MCD_OPC_CheckPredicate, 19, 146, 4, 0, // Skip to: 6575
/* 5405 */    MCD_OPC_Decode, 211, 10, 124, // Opcode: CVT_S_W_MM
/* 5409 */    MCD_OPC_FilterValue, 60, 137, 4, 0, // Skip to: 6575
/* 5414 */    MCD_OPC_ExtractField, 6, 7,  // Inst{12-6} ...
/* 5417 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 5432
/* 5422 */    MCD_OPC_CheckPredicate, 13, 124, 4, 0, // Skip to: 6575
/* 5427 */    MCD_OPC_Decode, 231, 10, 132, 1, // Opcode: C_F_S_MM
/* 5432 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 5447
/* 5437 */    MCD_OPC_CheckPredicate, 13, 109, 4, 0, // Skip to: 6575
/* 5442 */    MCD_OPC_Decode, 187, 11, 132, 1, // Opcode: C_UN_S_MM
/* 5447 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 5462
/* 5452 */    MCD_OPC_CheckPredicate, 13, 94, 4, 0, // Skip to: 6575
/* 5457 */    MCD_OPC_Decode, 225, 10, 132, 1, // Opcode: C_EQ_S_MM
/* 5462 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 5477
/* 5467 */    MCD_OPC_CheckPredicate, 13, 79, 4, 0, // Skip to: 6575
/* 5472 */    MCD_OPC_Decode, 169, 11, 132, 1, // Opcode: C_UEQ_S_MM
/* 5477 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 5492
/* 5482 */    MCD_OPC_CheckPredicate, 13, 64, 4, 0, // Skip to: 6575
/* 5487 */    MCD_OPC_Decode, 151, 11, 132, 1, // Opcode: C_OLT_S_MM
/* 5492 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 5507
/* 5497 */    MCD_OPC_CheckPredicate, 13, 49, 4, 0, // Skip to: 6575
/* 5502 */    MCD_OPC_Decode, 181, 11, 132, 1, // Opcode: C_ULT_S_MM
/* 5507 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 5522
/* 5512 */    MCD_OPC_CheckPredicate, 13, 34, 4, 0, // Skip to: 6575
/* 5517 */    MCD_OPC_Decode, 145, 11, 132, 1, // Opcode: C_OLE_S_MM
/* 5522 */    MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 5537
/* 5527 */    MCD_OPC_CheckPredicate, 13, 19, 4, 0, // Skip to: 6575
/* 5532 */    MCD_OPC_Decode, 175, 11, 132, 1, // Opcode: C_ULE_S_MM
/* 5537 */    MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 5552
/* 5542 */    MCD_OPC_CheckPredicate, 13, 4, 4, 0, // Skip to: 6575
/* 5547 */    MCD_OPC_Decode, 163, 11, 132, 1, // Opcode: C_SF_S_MM
/* 5552 */    MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 5567
/* 5557 */    MCD_OPC_CheckPredicate, 13, 245, 3, 0, // Skip to: 6575
/* 5562 */    MCD_OPC_Decode, 255, 10, 132, 1, // Opcode: C_NGLE_S_MM
/* 5567 */    MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 5582
/* 5572 */    MCD_OPC_CheckPredicate, 13, 230, 3, 0, // Skip to: 6575
/* 5577 */    MCD_OPC_Decode, 157, 11, 132, 1, // Opcode: C_SEQ_S_MM
/* 5582 */    MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 5597
/* 5587 */    MCD_OPC_CheckPredicate, 13, 215, 3, 0, // Skip to: 6575
/* 5592 */    MCD_OPC_Decode, 133, 11, 132, 1, // Opcode: C_NGL_S_MM
/* 5597 */    MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 5612
/* 5602 */    MCD_OPC_CheckPredicate, 13, 200, 3, 0, // Skip to: 6575
/* 5607 */    MCD_OPC_Decode, 243, 10, 132, 1, // Opcode: C_LT_S_MM
/* 5612 */    MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 5627
/* 5617 */    MCD_OPC_CheckPredicate, 13, 185, 3, 0, // Skip to: 6575
/* 5622 */    MCD_OPC_Decode, 249, 10, 132, 1, // Opcode: C_NGE_S_MM
/* 5627 */    MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 5642
/* 5632 */    MCD_OPC_CheckPredicate, 13, 170, 3, 0, // Skip to: 6575
/* 5637 */    MCD_OPC_Decode, 237, 10, 132, 1, // Opcode: C_LE_S_MM
/* 5642 */    MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 5657
/* 5647 */    MCD_OPC_CheckPredicate, 13, 155, 3, 0, // Skip to: 6575
/* 5652 */    MCD_OPC_Decode, 139, 11, 132, 1, // Opcode: C_NGT_S_MM
/* 5657 */    MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 5672
/* 5662 */    MCD_OPC_CheckPredicate, 17, 140, 3, 0, // Skip to: 6575
/* 5667 */    MCD_OPC_Decode, 227, 10, 133, 1, // Opcode: C_F_D32_MM
/* 5672 */    MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 5687
/* 5677 */    MCD_OPC_CheckPredicate, 17, 125, 3, 0, // Skip to: 6575
/* 5682 */    MCD_OPC_Decode, 183, 11, 133, 1, // Opcode: C_UN_D32_MM
/* 5687 */    MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 5702
/* 5692 */    MCD_OPC_CheckPredicate, 17, 110, 3, 0, // Skip to: 6575
/* 5697 */    MCD_OPC_Decode, 221, 10, 133, 1, // Opcode: C_EQ_D32_MM
/* 5702 */    MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 5717
/* 5707 */    MCD_OPC_CheckPredicate, 17, 95, 3, 0, // Skip to: 6575
/* 5712 */    MCD_OPC_Decode, 165, 11, 133, 1, // Opcode: C_UEQ_D32_MM
/* 5717 */    MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 5732
/* 5722 */    MCD_OPC_CheckPredicate, 17, 80, 3, 0, // Skip to: 6575
/* 5727 */    MCD_OPC_Decode, 147, 11, 133, 1, // Opcode: C_OLT_D32_MM
/* 5732 */    MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 5747
/* 5737 */    MCD_OPC_CheckPredicate, 17, 65, 3, 0, // Skip to: 6575
/* 5742 */    MCD_OPC_Decode, 177, 11, 133, 1, // Opcode: C_ULT_D32_MM
/* 5747 */    MCD_OPC_FilterValue, 22, 10, 0, 0, // Skip to: 5762
/* 5752 */    MCD_OPC_CheckPredicate, 17, 50, 3, 0, // Skip to: 6575
/* 5757 */    MCD_OPC_Decode, 141, 11, 133, 1, // Opcode: C_OLE_D32_MM
/* 5762 */    MCD_OPC_FilterValue, 23, 10, 0, 0, // Skip to: 5777
/* 5767 */    MCD_OPC_CheckPredicate, 17, 35, 3, 0, // Skip to: 6575
/* 5772 */    MCD_OPC_Decode, 171, 11, 133, 1, // Opcode: C_ULE_D32_MM
/* 5777 */    MCD_OPC_FilterValue, 24, 10, 0, 0, // Skip to: 5792
/* 5782 */    MCD_OPC_CheckPredicate, 17, 20, 3, 0, // Skip to: 6575
/* 5787 */    MCD_OPC_Decode, 159, 11, 133, 1, // Opcode: C_SF_D32_MM
/* 5792 */    MCD_OPC_FilterValue, 25, 10, 0, 0, // Skip to: 5807
/* 5797 */    MCD_OPC_CheckPredicate, 17, 5, 3, 0, // Skip to: 6575
/* 5802 */    MCD_OPC_Decode, 251, 10, 133, 1, // Opcode: C_NGLE_D32_MM
/* 5807 */    MCD_OPC_FilterValue, 26, 10, 0, 0, // Skip to: 5822
/* 5812 */    MCD_OPC_CheckPredicate, 17, 246, 2, 0, // Skip to: 6575
/* 5817 */    MCD_OPC_Decode, 153, 11, 133, 1, // Opcode: C_SEQ_D32_MM
/* 5822 */    MCD_OPC_FilterValue, 27, 10, 0, 0, // Skip to: 5837
/* 5827 */    MCD_OPC_CheckPredicate, 17, 231, 2, 0, // Skip to: 6575
/* 5832 */    MCD_OPC_Decode, 129, 11, 133, 1, // Opcode: C_NGL_D32_MM
/* 5837 */    MCD_OPC_FilterValue, 28, 10, 0, 0, // Skip to: 5852
/* 5842 */    MCD_OPC_CheckPredicate, 17, 216, 2, 0, // Skip to: 6575
/* 5847 */    MCD_OPC_Decode, 239, 10, 133, 1, // Opcode: C_LT_D32_MM
/* 5852 */    MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 5867
/* 5857 */    MCD_OPC_CheckPredicate, 17, 201, 2, 0, // Skip to: 6575
/* 5862 */    MCD_OPC_Decode, 245, 10, 133, 1, // Opcode: C_NGE_D32_MM
/* 5867 */    MCD_OPC_FilterValue, 30, 10, 0, 0, // Skip to: 5882
/* 5872 */    MCD_OPC_CheckPredicate, 17, 186, 2, 0, // Skip to: 6575
/* 5877 */    MCD_OPC_Decode, 233, 10, 133, 1, // Opcode: C_LE_D32_MM
/* 5882 */    MCD_OPC_FilterValue, 31, 176, 2, 0, // Skip to: 6575
/* 5887 */    MCD_OPC_CheckPredicate, 17, 171, 2, 0, // Skip to: 6575
/* 5892 */    MCD_OPC_Decode, 135, 11, 133, 1, // Opcode: C_NGT_D32_MM
/* 5897 */    MCD_OPC_FilterValue, 22, 48, 0, 0, // Skip to: 5950
/* 5902 */    MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 5905 */    MCD_OPC_FilterValue, 197, 1, 9, 0, 0, // Skip to: 5920
/* 5911 */    MCD_OPC_CheckPredicate, 8, 147, 2, 0, // Skip to: 6575
/* 5916 */    MCD_OPC_Decode, 205, 9, 54, // Opcode: CMPGU_EQ_QB_MM
/* 5920 */    MCD_OPC_FilterValue, 133, 2, 9, 0, 0, // Skip to: 5935
/* 5926 */    MCD_OPC_CheckPredicate, 8, 132, 2, 0, // Skip to: 6575
/* 5931 */    MCD_OPC_Decode, 209, 9, 54, // Opcode: CMPGU_LT_QB_MM
/* 5935 */    MCD_OPC_FilterValue, 197, 2, 122, 2, 0, // Skip to: 6575
/* 5941 */    MCD_OPC_CheckPredicate, 8, 117, 2, 0, // Skip to: 6575
/* 5946 */    MCD_OPC_Decode, 207, 9, 54, // Opcode: CMPGU_LE_QB_MM
/* 5950 */    MCD_OPC_FilterValue, 24, 115, 1, 0, // Skip to: 6326
/* 5955 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 5958 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 5972
/* 5963 */    MCD_OPC_CheckPredicate, 6, 95, 2, 0, // Skip to: 6575
/* 5968 */    MCD_OPC_Decode, 153, 16, 99, // Opcode: LWL_MM
/* 5972 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 5986
/* 5977 */    MCD_OPC_CheckPredicate, 6, 81, 2, 0, // Skip to: 6575
/* 5982 */    MCD_OPC_Decode, 166, 16, 99, // Opcode: LWR_MM
/* 5986 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 6000
/* 5991 */    MCD_OPC_CheckPredicate, 6, 67, 2, 0, // Skip to: 6575
/* 5996 */    MCD_OPC_Decode, 242, 19, 100, // Opcode: PREF_MM
/* 6000 */    MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 6014
/* 6005 */    MCD_OPC_CheckPredicate, 6, 53, 2, 0, // Skip to: 6575
/* 6010 */    MCD_OPC_Decode, 243, 15, 99, // Opcode: LL_MM
/* 6014 */    MCD_OPC_FilterValue, 6, 123, 0, 0, // Skip to: 6142
/* 6019 */    MCD_OPC_ExtractField, 9, 3,  // Inst{11-9} ...
/* 6022 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6037
/* 6027 */    MCD_OPC_CheckPredicate, 21, 31, 2, 0, // Skip to: 6575
/* 6032 */    MCD_OPC_Decode, 177, 15, 134, 1, // Opcode: LBuE_MM
/* 6037 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 6052
/* 6042 */    MCD_OPC_CheckPredicate, 21, 16, 2, 0, // Skip to: 6575
/* 6047 */    MCD_OPC_Decode, 229, 15, 134, 1, // Opcode: LHuE_MM
/* 6052 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 6067
/* 6057 */    MCD_OPC_CheckPredicate, 22, 1, 2, 0, // Skip to: 6575
/* 6062 */    MCD_OPC_Decode, 152, 16, 134, 1, // Opcode: LWLE_MM
/* 6067 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 6082
/* 6072 */    MCD_OPC_CheckPredicate, 22, 242, 1, 0, // Skip to: 6575
/* 6077 */    MCD_OPC_Decode, 165, 16, 134, 1, // Opcode: LWRE_MM
/* 6082 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 6097
/* 6087 */    MCD_OPC_CheckPredicate, 21, 227, 1, 0, // Skip to: 6575
/* 6092 */    MCD_OPC_Decode, 158, 15, 134, 1, // Opcode: LBE_MM
/* 6097 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 6112
/* 6102 */    MCD_OPC_CheckPredicate, 21, 212, 1, 0, // Skip to: 6575
/* 6107 */    MCD_OPC_Decode, 210, 15, 134, 1, // Opcode: LHE_MM
/* 6112 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 6127
/* 6117 */    MCD_OPC_CheckPredicate, 21, 197, 1, 0, // Skip to: 6575
/* 6122 */    MCD_OPC_Decode, 241, 15, 134, 1, // Opcode: LLE_MM
/* 6127 */    MCD_OPC_FilterValue, 7, 187, 1, 0, // Skip to: 6575
/* 6132 */    MCD_OPC_CheckPredicate, 21, 182, 1, 0, // Skip to: 6575
/* 6137 */    MCD_OPC_Decode, 145, 16, 134, 1, // Opcode: LWE_MM
/* 6142 */    MCD_OPC_FilterValue, 8, 9, 0, 0, // Skip to: 6156
/* 6147 */    MCD_OPC_CheckPredicate, 6, 167, 1, 0, // Skip to: 6575
/* 6152 */    MCD_OPC_Decode, 150, 23, 99, // Opcode: SWL_MM
/* 6156 */    MCD_OPC_FilterValue, 9, 9, 0, 0, // Skip to: 6170
/* 6161 */    MCD_OPC_CheckPredicate, 6, 153, 1, 0, // Skip to: 6575
/* 6166 */    MCD_OPC_Decode, 161, 23, 99, // Opcode: SWR_MM
/* 6170 */    MCD_OPC_FilterValue, 10, 123, 0, 0, // Skip to: 6298
/* 6175 */    MCD_OPC_ExtractField, 9, 3,  // Inst{11-9} ...
/* 6178 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6193
/* 6183 */    MCD_OPC_CheckPredicate, 22, 131, 1, 0, // Skip to: 6575
/* 6188 */    MCD_OPC_Decode, 149, 23, 134, 1, // Opcode: SWLE_MM
/* 6193 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 6208
/* 6198 */    MCD_OPC_CheckPredicate, 22, 116, 1, 0, // Skip to: 6575
/* 6203 */    MCD_OPC_Decode, 160, 23, 134, 1, // Opcode: SWRE_MM
/* 6208 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 6223
/* 6213 */    MCD_OPC_CheckPredicate, 21, 101, 1, 0, // Skip to: 6575
/* 6218 */    MCD_OPC_Decode, 240, 19, 135, 1, // Opcode: PREFE_MM
/* 6223 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 6238
/* 6228 */    MCD_OPC_CheckPredicate, 21, 86, 1, 0, // Skip to: 6575
/* 6233 */    MCD_OPC_Decode, 248, 8, 135, 1, // Opcode: CACHEE_MM
/* 6238 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 6253
/* 6243 */    MCD_OPC_CheckPredicate, 21, 71, 1, 0, // Skip to: 6575
/* 6248 */    MCD_OPC_Decode, 199, 20, 134, 1, // Opcode: SBE_MM
/* 6253 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 6268
/* 6258 */    MCD_OPC_CheckPredicate, 21, 56, 1, 0, // Skip to: 6575
/* 6263 */    MCD_OPC_Decode, 149, 21, 134, 1, // Opcode: SHE_MM
/* 6268 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 6283
/* 6273 */    MCD_OPC_CheckPredicate, 21, 41, 1, 0, // Skip to: 6575
/* 6278 */    MCD_OPC_Decode, 212, 20, 134, 1, // Opcode: SCE_MM
/* 6283 */    MCD_OPC_FilterValue, 7, 31, 1, 0, // Skip to: 6575
/* 6288 */    MCD_OPC_CheckPredicate, 21, 26, 1, 0, // Skip to: 6575
/* 6293 */    MCD_OPC_Decode, 143, 23, 134, 1, // Opcode: SWE_MM
/* 6298 */    MCD_OPC_FilterValue, 11, 9, 0, 0, // Skip to: 6312
/* 6303 */    MCD_OPC_CheckPredicate, 6, 11, 1, 0, // Skip to: 6575
/* 6308 */    MCD_OPC_Decode, 214, 20, 99, // Opcode: SC_MM
/* 6312 */    MCD_OPC_FilterValue, 14, 2, 1, 0, // Skip to: 6575
/* 6317 */    MCD_OPC_CheckPredicate, 6, 253, 0, 0, // Skip to: 6575
/* 6322 */    MCD_OPC_Decode, 170, 16, 99, // Opcode: LWU_MM
/* 6326 */    MCD_OPC_FilterValue, 28, 9, 0, 0, // Skip to: 6340
/* 6331 */    MCD_OPC_CheckPredicate, 6, 239, 0, 0, // Skip to: 6575
/* 6336 */    MCD_OPC_Decode, 186, 24, 108, // Opcode: XORi_MM
/* 6340 */    MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 6355
/* 6345 */    MCD_OPC_CheckPredicate, 6, 225, 0, 0, // Skip to: 6575
/* 6350 */    MCD_OPC_Decode, 250, 14, 136, 1, // Opcode: JALS_MM
/* 6355 */    MCD_OPC_FilterValue, 30, 10, 0, 0, // Skip to: 6370
/* 6360 */    MCD_OPC_CheckPredicate, 6, 210, 0, 0, // Skip to: 6575
/* 6365 */    MCD_OPC_Decode, 130, 6, 137, 1, // Opcode: ADDIUPC_MM
/* 6370 */    MCD_OPC_FilterValue, 36, 9, 0, 0, // Skip to: 6384
/* 6375 */    MCD_OPC_CheckPredicate, 7, 195, 0, 0, // Skip to: 6575
/* 6380 */    MCD_OPC_Decode, 248, 21, 97, // Opcode: SLTi_MM
/* 6384 */    MCD_OPC_FilterValue, 37, 10, 0, 0, // Skip to: 6399
/* 6389 */    MCD_OPC_CheckPredicate, 6, 181, 0, 0, // Skip to: 6575
/* 6394 */    MCD_OPC_Decode, 208, 7, 138, 1, // Opcode: BEQ_MM
/* 6399 */    MCD_OPC_FilterValue, 38, 10, 0, 0, // Skip to: 6414
/* 6404 */    MCD_OPC_CheckPredicate, 19, 166, 0, 0, // Skip to: 6575
/* 6409 */    MCD_OPC_Decode, 135, 23, 139, 1, // Opcode: SWC1_MM
/* 6414 */    MCD_OPC_FilterValue, 39, 10, 0, 0, // Skip to: 6429
/* 6419 */    MCD_OPC_CheckPredicate, 19, 151, 0, 0, // Skip to: 6575
/* 6424 */    MCD_OPC_Decode, 137, 16, 139, 1, // Opcode: LWC1_MM
/* 6429 */    MCD_OPC_FilterValue, 44, 9, 0, 0, // Skip to: 6443
/* 6434 */    MCD_OPC_CheckPredicate, 7, 136, 0, 0, // Skip to: 6575
/* 6439 */    MCD_OPC_Decode, 251, 21, 97, // Opcode: SLTiu_MM
/* 6443 */    MCD_OPC_FilterValue, 45, 10, 0, 0, // Skip to: 6458
/* 6448 */    MCD_OPC_CheckPredicate, 6, 122, 0, 0, // Skip to: 6575
/* 6453 */    MCD_OPC_Decode, 198, 8, 138, 1, // Opcode: BNE_MM
/* 6458 */    MCD_OPC_FilterValue, 46, 10, 0, 0, // Skip to: 6473
/* 6463 */    MCD_OPC_CheckPredicate, 18, 107, 0, 0, // Skip to: 6575
/* 6468 */    MCD_OPC_Decode, 230, 20, 139, 1, // Opcode: SDC1_MM_D32
/* 6473 */    MCD_OPC_FilterValue, 47, 10, 0, 0, // Skip to: 6488
/* 6478 */    MCD_OPC_CheckPredicate, 18, 92, 0, 0, // Skip to: 6575
/* 6483 */    MCD_OPC_Decode, 183, 15, 139, 1, // Opcode: LDC1_MM_D32
/* 6488 */    MCD_OPC_FilterValue, 52, 9, 0, 0, // Skip to: 6502
/* 6493 */    MCD_OPC_CheckPredicate, 6, 77, 0, 0, // Skip to: 6575
/* 6498 */    MCD_OPC_Decode, 233, 6, 108, // Opcode: ANDi_MM
/* 6502 */    MCD_OPC_FilterValue, 53, 10, 0, 0, // Skip to: 6517
/* 6507 */    MCD_OPC_CheckPredicate, 6, 63, 0, 0, // Skip to: 6575
/* 6512 */    MCD_OPC_Decode, 145, 15, 136, 1, // Opcode: J_MM
/* 6517 */    MCD_OPC_FilterValue, 60, 10, 0, 0, // Skip to: 6532
/* 6522 */    MCD_OPC_CheckPredicate, 6, 48, 0, 0, // Skip to: 6575
/* 6527 */    MCD_OPC_Decode, 252, 14, 140, 1, // Opcode: JALX_MM
/* 6532 */    MCD_OPC_FilterValue, 61, 10, 0, 0, // Skip to: 6547
/* 6537 */    MCD_OPC_CheckPredicate, 6, 33, 0, 0, // Skip to: 6575
/* 6542 */    MCD_OPC_Decode, 253, 14, 136, 1, // Opcode: JAL_MM
/* 6547 */    MCD_OPC_FilterValue, 62, 9, 0, 0, // Skip to: 6561
/* 6552 */    MCD_OPC_CheckPredicate, 7, 18, 0, 0, // Skip to: 6575
/* 6557 */    MCD_OPC_Decode, 169, 23, 98, // Opcode: SW_MM
/* 6561 */    MCD_OPC_FilterValue, 63, 9, 0, 0, // Skip to: 6575
/* 6566 */    MCD_OPC_CheckPredicate, 7, 4, 0, 0, // Skip to: 6575
/* 6571 */    MCD_OPC_Decode, 179, 16, 98, // Opcode: LW_MM
/* 6575 */    MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMicroMipsDSP32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 62, 10, 0, 0, // Skip to: 18
/* 8 */       MCD_OPC_CheckPredicate, 8, 20, 0, 0, // Skip to: 33
/* 13 */      MCD_OPC_Decode, 141, 23, 141, 1, // Opcode: SWDSP_MM
/* 18 */      MCD_OPC_FilterValue, 63, 10, 0, 0, // Skip to: 33
/* 23 */      MCD_OPC_CheckPredicate, 8, 5, 0, 0, // Skip to: 33
/* 28 */      MCD_OPC_Decode, 143, 16, 141, 1, // Opcode: LWDSP_MM
/* 33 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMicroMipsFP6432[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 21, 39, 1, 0, // Skip to: 303
/* 8 */       MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 11 */      MCD_OPC_FilterValue, 59, 48, 0, 0, // Skip to: 64
/* 16 */      MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 19 */      MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 34
/* 24 */      MCD_OPC_CheckPredicate, 20, 48, 1, 0, // Skip to: 333
/* 29 */      MCD_OPC_Decode, 162, 18, 142, 1, // Opcode: MTC1_D64_MM
/* 34 */      MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 49
/* 39 */      MCD_OPC_CheckPredicate, 20, 33, 1, 0, // Skip to: 333
/* 44 */      MCD_OPC_Decode, 146, 17, 143, 1, // Opcode: MFHC1_D64_MM
/* 49 */      MCD_OPC_FilterValue, 7, 23, 1, 0, // Skip to: 333
/* 54 */      MCD_OPC_CheckPredicate, 20, 18, 1, 0, // Skip to: 333
/* 59 */      MCD_OPC_Decode, 175, 18, 144, 1, // Opcode: MTHC1_D64_MM
/* 64 */      MCD_OPC_FilterValue, 123, 16, 0, 0, // Skip to: 85
/* 69 */      MCD_OPC_CheckPredicate, 20, 3, 1, 0, // Skip to: 333
/* 74 */      MCD_OPC_CheckField, 11, 5, 4, 252, 0, 0, // Skip to: 333
/* 81 */      MCD_OPC_Decode, 230, 13, 122, // Opcode: FMOV_D64_MM
/* 85 */      MCD_OPC_FilterValue, 176, 2, 10, 0, 0, // Skip to: 101
/* 91 */      MCD_OPC_CheckPredicate, 20, 237, 0, 0, // Skip to: 333
/* 96 */      MCD_OPC_Decode, 140, 13, 145, 1, // Opcode: FADD_D64_MM
/* 101 */     MCD_OPC_FilterValue, 187, 2, 17, 0, 0, // Skip to: 124
/* 107 */     MCD_OPC_CheckPredicate, 20, 221, 0, 0, // Skip to: 333
/* 112 */     MCD_OPC_CheckField, 11, 5, 9, 214, 0, 0, // Skip to: 333
/* 119 */     MCD_OPC_Decode, 216, 10, 146, 1, // Opcode: CVT_W_D64_MM
/* 124 */     MCD_OPC_FilterValue, 240, 2, 10, 0, 0, // Skip to: 140
/* 130 */     MCD_OPC_CheckPredicate, 20, 198, 0, 0, // Skip to: 333
/* 135 */     MCD_OPC_Decode, 158, 14, 145, 1, // Opcode: FSUB_D64_MM
/* 140 */     MCD_OPC_FilterValue, 176, 3, 10, 0, 0, // Skip to: 156
/* 146 */     MCD_OPC_CheckPredicate, 20, 182, 0, 0, // Skip to: 333
/* 151 */     MCD_OPC_Decode, 241, 13, 145, 1, // Opcode: FMUL_D64_MM
/* 156 */     MCD_OPC_FilterValue, 240, 3, 10, 0, 0, // Skip to: 172
/* 162 */     MCD_OPC_CheckPredicate, 20, 166, 0, 0, // Skip to: 333
/* 167 */     MCD_OPC_Decode, 179, 13, 145, 1, // Opcode: FDIV_D64_MM
/* 172 */     MCD_OPC_FilterValue, 187, 4, 45, 0, 0, // Skip to: 223
/* 178 */     MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 181 */     MCD_OPC_FilterValue, 8, 9, 0, 0, // Skip to: 195
/* 186 */     MCD_OPC_CheckPredicate, 20, 142, 0, 0, // Skip to: 333
/* 191 */     MCD_OPC_Decode, 176, 20, 122, // Opcode: RSQRT_D64_MM
/* 195 */     MCD_OPC_FilterValue, 9, 9, 0, 0, // Skip to: 209
/* 200 */     MCD_OPC_CheckPredicate, 20, 128, 0, 0, // Skip to: 333
/* 205 */     MCD_OPC_Decode, 150, 14, 122, // Opcode: FSQRT_D64_MM
/* 209 */     MCD_OPC_FilterValue, 10, 119, 0, 0, // Skip to: 333
/* 214 */     MCD_OPC_CheckPredicate, 20, 114, 0, 0, // Skip to: 333
/* 219 */     MCD_OPC_Decode, 137, 20, 122, // Opcode: RECIP_D64_MM
/* 223 */     MCD_OPC_FilterValue, 251, 6, 104, 0, 0, // Skip to: 333
/* 229 */     MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 232 */     MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 246
/* 237 */     MCD_OPC_CheckPredicate, 20, 91, 0, 0, // Skip to: 333
/* 242 */     MCD_OPC_Decode, 189, 10, 121, // Opcode: CVT_D64_S_MM
/* 246 */     MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 261
/* 251 */     MCD_OPC_CheckPredicate, 20, 77, 0, 0, // Skip to: 333
/* 256 */     MCD_OPC_Decode, 205, 10, 146, 1, // Opcode: CVT_S_D64_MM
/* 261 */     MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 275
/* 266 */     MCD_OPC_CheckPredicate, 20, 62, 0, 0, // Skip to: 333
/* 271 */     MCD_OPC_Decode, 133, 13, 122, // Opcode: FABS_D64_MM
/* 275 */     MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 289
/* 280 */     MCD_OPC_CheckPredicate, 20, 48, 0, 0, // Skip to: 333
/* 285 */     MCD_OPC_Decode, 250, 13, 122, // Opcode: FNEG_D64_MM
/* 289 */     MCD_OPC_FilterValue, 6, 39, 0, 0, // Skip to: 333
/* 294 */     MCD_OPC_CheckPredicate, 20, 34, 0, 0, // Skip to: 333
/* 299 */     MCD_OPC_Decode, 191, 10, 121, // Opcode: CVT_D64_W_MM
/* 303 */     MCD_OPC_FilterValue, 46, 10, 0, 0, // Skip to: 318
/* 308 */     MCD_OPC_CheckPredicate, 23, 20, 0, 0, // Skip to: 333
/* 313 */     MCD_OPC_Decode, 229, 20, 139, 1, // Opcode: SDC1_D64_MMR6
/* 318 */     MCD_OPC_FilterValue, 47, 10, 0, 0, // Skip to: 333
/* 323 */     MCD_OPC_CheckPredicate, 23, 5, 0, 0, // Skip to: 333
/* 328 */     MCD_OPC_Decode, 182, 15, 139, 1, // Opcode: LDC1_D64_MMR6
/* 333 */     MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMicroMipsR616[] = {
/* 0 */       MCD_OPC_ExtractField, 10, 6,  // Inst{15-10} ...
/* 3 */       MCD_OPC_FilterValue, 1, 33, 0, 0, // Skip to: 41
/* 8 */       MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 11 */      MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 26
/* 16 */      MCD_OPC_CheckPredicate, 24, 173, 1, 0, // Skip to: 450
/* 21 */      MCD_OPC_Decode, 171, 6, 147, 1, // Opcode: ADDU16_MMR6
/* 26 */      MCD_OPC_FilterValue, 1, 163, 1, 0, // Skip to: 450
/* 31 */      MCD_OPC_CheckPredicate, 24, 158, 1, 0, // Skip to: 450
/* 36 */      MCD_OPC_Decode, 224, 22, 147, 1, // Opcode: SUBU16_MMR6
/* 41 */      MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 55
/* 46 */      MCD_OPC_CheckPredicate, 24, 143, 1, 0, // Skip to: 450
/* 51 */      MCD_OPC_Decode, 209, 17, 33, // Opcode: MOVE16_MMR6
/* 55 */      MCD_OPC_FilterValue, 9, 31, 0, 0, // Skip to: 91
/* 60 */      MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 63 */      MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 77
/* 68 */      MCD_OPC_CheckPredicate, 24, 121, 1, 0, // Skip to: 450
/* 73 */      MCD_OPC_Decode, 221, 21, 34, // Opcode: SLL16_MMR6
/* 77 */      MCD_OPC_FilterValue, 1, 112, 1, 0, // Skip to: 450
/* 82 */      MCD_OPC_CheckPredicate, 24, 107, 1, 0, // Skip to: 450
/* 87 */      MCD_OPC_Decode, 162, 22, 34, // Opcode: SRL16_MMR6
/* 91 */      MCD_OPC_FilterValue, 11, 9, 0, 0, // Skip to: 105
/* 96 */      MCD_OPC_CheckPredicate, 24, 93, 1, 0, // Skip to: 450
/* 101 */     MCD_OPC_Decode, 222, 6, 35, // Opcode: ANDI16_MMR6
/* 105 */     MCD_OPC_FilterValue, 17, 228, 0, 0, // Skip to: 338
/* 110 */     MCD_OPC_ExtractField, 2, 1,  // Inst{2} ...
/* 113 */     MCD_OPC_FilterValue, 0, 206, 0, 0, // Skip to: 324
/* 118 */     MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 121 */     MCD_OPC_FilterValue, 0, 33, 0, 0, // Skip to: 159
/* 126 */     MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 129 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 144
/* 134 */     MCD_OPC_CheckPredicate, 24, 55, 1, 0, // Skip to: 450
/* 139 */     MCD_OPC_Decode, 159, 19, 148, 1, // Opcode: NOT16_MMR6
/* 144 */     MCD_OPC_FilterValue, 1, 45, 1, 0, // Skip to: 450
/* 149 */     MCD_OPC_CheckPredicate, 24, 40, 1, 0, // Skip to: 450
/* 154 */     MCD_OPC_Decode, 174, 24, 149, 1, // Opcode: XOR16_MMR6
/* 159 */     MCD_OPC_FilterValue, 1, 33, 0, 0, // Skip to: 197
/* 164 */     MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 167 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 182
/* 172 */     MCD_OPC_CheckPredicate, 24, 17, 1, 0, // Skip to: 450
/* 177 */     MCD_OPC_Decode, 218, 6, 149, 1, // Opcode: AND16_MMR6
/* 182 */     MCD_OPC_FilterValue, 1, 7, 1, 0, // Skip to: 450
/* 187 */     MCD_OPC_CheckPredicate, 24, 2, 1, 0, // Skip to: 450
/* 192 */     MCD_OPC_Decode, 165, 19, 149, 1, // Opcode: OR16_MMR6
/* 197 */     MCD_OPC_FilterValue, 2, 31, 0, 0, // Skip to: 233
/* 202 */     MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 205 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 219
/* 210 */     MCD_OPC_CheckPredicate, 24, 235, 0, 0, // Skip to: 450
/* 215 */     MCD_OPC_Decode, 155, 16, 38, // Opcode: LWM16_MMR6
/* 219 */     MCD_OPC_FilterValue, 1, 226, 0, 0, // Skip to: 450
/* 224 */     MCD_OPC_CheckPredicate, 24, 221, 0, 0, // Skip to: 450
/* 229 */     MCD_OPC_Decode, 152, 23, 38, // Opcode: SWM16_MMR6
/* 233 */     MCD_OPC_FilterValue, 3, 212, 0, 0, // Skip to: 450
/* 238 */     MCD_OPC_ExtractField, 3, 2,  // Inst{4-3} ...
/* 241 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 256
/* 246 */     MCD_OPC_CheckPredicate, 24, 199, 0, 0, // Skip to: 450
/* 251 */     MCD_OPC_Decode, 137, 15, 150, 1, // Opcode: JRC16_MMR6
/* 256 */     MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 271
/* 261 */     MCD_OPC_CheckPredicate, 24, 184, 0, 0, // Skip to: 450
/* 266 */     MCD_OPC_Decode, 239, 14, 150, 1, // Opcode: JALRC16_MMR6
/* 271 */     MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 286
/* 276 */     MCD_OPC_CheckPredicate, 24, 169, 0, 0, // Skip to: 450
/* 281 */     MCD_OPC_Decode, 138, 15, 151, 1, // Opcode: JRCADDIUSP_MMR6
/* 286 */     MCD_OPC_FilterValue, 3, 159, 0, 0, // Skip to: 450
/* 291 */     MCD_OPC_ExtractField, 5, 1,  // Inst{5} ...
/* 294 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 309
/* 299 */     MCD_OPC_CheckPredicate, 24, 146, 0, 0, // Skip to: 450
/* 304 */     MCD_OPC_Decode, 213, 8, 152, 1, // Opcode: BREAK16_MMR6
/* 309 */     MCD_OPC_FilterValue, 1, 136, 0, 0, // Skip to: 450
/* 314 */     MCD_OPC_CheckPredicate, 24, 131, 0, 0, // Skip to: 450
/* 319 */     MCD_OPC_Decode, 221, 20, 152, 1, // Opcode: SDBBP16_MMR6
/* 324 */     MCD_OPC_FilterValue, 1, 121, 0, 0, // Skip to: 450
/* 329 */     MCD_OPC_CheckPredicate, 24, 116, 0, 0, // Skip to: 450
/* 334 */     MCD_OPC_Decode, 213, 17, 48, // Opcode: MOVEP_MMR6
/* 338 */     MCD_OPC_FilterValue, 34, 9, 0, 0, // Skip to: 352
/* 343 */     MCD_OPC_CheckPredicate, 24, 102, 0, 0, // Skip to: 450
/* 348 */     MCD_OPC_Decode, 195, 20, 32, // Opcode: SB16_MMR6
/* 352 */     MCD_OPC_FilterValue, 35, 9, 0, 0, // Skip to: 366
/* 357 */     MCD_OPC_CheckPredicate, 24, 88, 0, 0, // Skip to: 450
/* 362 */     MCD_OPC_Decode, 202, 7, 49, // Opcode: BEQZC16_MMR6
/* 366 */     MCD_OPC_FilterValue, 42, 9, 0, 0, // Skip to: 380
/* 371 */     MCD_OPC_CheckPredicate, 24, 74, 0, 0, // Skip to: 450
/* 376 */     MCD_OPC_Decode, 145, 21, 32, // Opcode: SH16_MMR6
/* 380 */     MCD_OPC_FilterValue, 43, 9, 0, 0, // Skip to: 394
/* 385 */     MCD_OPC_CheckPredicate, 24, 60, 0, 0, // Skip to: 450
/* 390 */     MCD_OPC_Decode, 192, 8, 49, // Opcode: BNEZC16_MMR6
/* 394 */     MCD_OPC_FilterValue, 50, 9, 0, 0, // Skip to: 408
/* 399 */     MCD_OPC_CheckPredicate, 24, 46, 0, 0, // Skip to: 450
/* 404 */     MCD_OPC_Decode, 164, 23, 42, // Opcode: SWSP_MMR6
/* 408 */     MCD_OPC_FilterValue, 51, 9, 0, 0, // Skip to: 422
/* 413 */     MCD_OPC_CheckPredicate, 24, 32, 0, 0, // Skip to: 450
/* 418 */     MCD_OPC_Decode, 162, 7, 50, // Opcode: BC16_MMR6
/* 422 */     MCD_OPC_FilterValue, 58, 9, 0, 0, // Skip to: 436
/* 427 */     MCD_OPC_CheckPredicate, 24, 18, 0, 0, // Skip to: 450
/* 432 */     MCD_OPC_Decode, 130, 23, 32, // Opcode: SW16_MMR6
/* 436 */     MCD_OPC_FilterValue, 59, 9, 0, 0, // Skip to: 450
/* 441 */     MCD_OPC_CheckPredicate, 24, 4, 0, 0, // Skip to: 450
/* 446 */     MCD_OPC_Decode, 232, 15, 51, // Opcode: LI16_MMR6
/* 450 */     MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMicroMipsR632[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 98, 4, 0, // Skip to: 1130
/* 8 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 11 */      MCD_OPC_FilterValue, 0, 112, 0, 0, // Skip to: 128
/* 16 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 19 */      MCD_OPC_FilterValue, 0, 54, 0, 0, // Skip to: 78
/* 24 */      MCD_OPC_ExtractField, 11, 15,  // Inst{25-11} ...
/* 27 */      MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 41
/* 32 */      MCD_OPC_CheckPredicate, 24, 32, 0, 0, // Skip to: 69
/* 37 */      MCD_OPC_Decode, 187, 22, 10, // Opcode: SSNOP_MMR6
/* 41 */      MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 55
/* 46 */      MCD_OPC_CheckPredicate, 24, 18, 0, 0, // Skip to: 69
/* 51 */      MCD_OPC_Decode, 208, 12, 10, // Opcode: EHB_MMR6
/* 55 */      MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 69
/* 60 */      MCD_OPC_CheckPredicate, 24, 4, 0, 0, // Skip to: 69
/* 65 */      MCD_OPC_Decode, 183, 19, 10, // Opcode: PAUSE_MMR6
/* 69 */      MCD_OPC_CheckPredicate, 24, 80, 12, 0, // Skip to: 3226
/* 74 */      MCD_OPC_Decode, 236, 21, 52, // Opcode: SLL_MMR6
/* 78 */      MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 92
/* 83 */      MCD_OPC_CheckPredicate, 24, 66, 12, 0, // Skip to: 3226
/* 88 */      MCD_OPC_Decode, 254, 20, 55, // Opcode: SELEQZ_MMR6
/* 92 */      MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 106
/* 97 */      MCD_OPC_CheckPredicate, 24, 52, 12, 0, // Skip to: 3226
/* 102 */     MCD_OPC_Decode, 133, 21, 55, // Opcode: SELNEZ_MMR6
/* 106 */     MCD_OPC_FilterValue, 7, 43, 12, 0, // Skip to: 3226
/* 111 */     MCD_OPC_CheckPredicate, 24, 38, 12, 0, // Skip to: 3226
/* 116 */     MCD_OPC_CheckField, 14, 2, 0, 31, 12, 0, // Skip to: 3226
/* 123 */     MCD_OPC_Decode, 130, 20, 153, 1, // Opcode: RDHWR_MMR6
/* 128 */     MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 142
/* 133 */     MCD_OPC_CheckPredicate, 24, 16, 12, 0, // Skip to: 3226
/* 138 */     MCD_OPC_Decode, 216, 8, 56, // Opcode: BREAK_MMR6
/* 142 */     MCD_OPC_FilterValue, 12, 9, 0, 0, // Skip to: 156
/* 147 */     MCD_OPC_CheckPredicate, 24, 2, 12, 0, // Skip to: 3226
/* 152 */     MCD_OPC_Decode, 232, 14, 57, // Opcode: INS_MMR6
/* 156 */     MCD_OPC_FilterValue, 15, 17, 0, 0, // Skip to: 178
/* 161 */     MCD_OPC_CheckPredicate, 24, 244, 11, 0, // Skip to: 3226
/* 166 */     MCD_OPC_CheckField, 6, 3, 0, 237, 11, 0, // Skip to: 3226
/* 173 */     MCD_OPC_Decode, 248, 15, 154, 1, // Opcode: LSA_MMR6
/* 178 */     MCD_OPC_FilterValue, 16, 136, 0, 0, // Skip to: 319
/* 183 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 186 */     MCD_OPC_FilterValue, 1, 16, 0, 0, // Skip to: 207
/* 191 */     MCD_OPC_CheckPredicate, 24, 214, 11, 0, // Skip to: 3226
/* 196 */     MCD_OPC_CheckField, 16, 5, 0, 207, 11, 0, // Skip to: 3226
/* 203 */     MCD_OPC_Decode, 195, 9, 25, // Opcode: CLZ_MMR6
/* 207 */     MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 221
/* 212 */     MCD_OPC_CheckPredicate, 24, 193, 11, 0, // Skip to: 3226
/* 217 */     MCD_OPC_Decode, 200, 6, 55, // Opcode: ADD_MMR6
/* 221 */     MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 235
/* 226 */     MCD_OPC_CheckPredicate, 24, 179, 11, 0, // Skip to: 3226
/* 231 */     MCD_OPC_Decode, 176, 6, 55, // Opcode: ADDU_MMR6
/* 235 */     MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 249
/* 240 */     MCD_OPC_CheckPredicate, 24, 165, 11, 0, // Skip to: 3226
/* 245 */     MCD_OPC_Decode, 247, 22, 55, // Opcode: SUB_MMR6
/* 249 */     MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 263
/* 254 */     MCD_OPC_CheckPredicate, 24, 151, 11, 0, // Skip to: 3226
/* 259 */     MCD_OPC_Decode, 229, 22, 55, // Opcode: SUBU_MMR6
/* 263 */     MCD_OPC_FilterValue, 9, 9, 0, 0, // Skip to: 277
/* 268 */     MCD_OPC_CheckPredicate, 24, 137, 11, 0, // Skip to: 3226
/* 273 */     MCD_OPC_Decode, 228, 6, 55, // Opcode: AND_MMR6
/* 277 */     MCD_OPC_FilterValue, 10, 9, 0, 0, // Skip to: 291
/* 282 */     MCD_OPC_CheckPredicate, 24, 123, 11, 0, // Skip to: 3226
/* 287 */     MCD_OPC_Decode, 172, 19, 55, // Opcode: OR_MMR6
/* 291 */     MCD_OPC_FilterValue, 11, 9, 0, 0, // Skip to: 305
/* 296 */     MCD_OPC_CheckPredicate, 24, 109, 11, 0, // Skip to: 3226
/* 301 */     MCD_OPC_Decode, 155, 19, 55, // Opcode: NOR_MMR6
/* 305 */     MCD_OPC_FilterValue, 12, 100, 11, 0, // Skip to: 3226
/* 310 */     MCD_OPC_CheckPredicate, 24, 95, 11, 0, // Skip to: 3226
/* 315 */     MCD_OPC_Decode, 181, 24, 55, // Opcode: XOR_MMR6
/* 319 */     MCD_OPC_FilterValue, 24, 115, 0, 0, // Skip to: 439
/* 324 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 327 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 341
/* 332 */     MCD_OPC_CheckPredicate, 24, 73, 11, 0, // Skip to: 3226
/* 337 */     MCD_OPC_Decode, 246, 18, 55, // Opcode: MUL_MMR6
/* 341 */     MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 355
/* 346 */     MCD_OPC_CheckPredicate, 24, 59, 11, 0, // Skip to: 3226
/* 351 */     MCD_OPC_Decode, 203, 18, 55, // Opcode: MUH_MMR6
/* 355 */     MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 369
/* 360 */     MCD_OPC_CheckPredicate, 24, 45, 11, 0, // Skip to: 3226
/* 365 */     MCD_OPC_Decode, 239, 18, 55, // Opcode: MULU_MMR6
/* 369 */     MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 383
/* 374 */     MCD_OPC_CheckPredicate, 24, 31, 11, 0, // Skip to: 3226
/* 379 */     MCD_OPC_Decode, 201, 18, 55, // Opcode: MUHU_MMR6
/* 383 */     MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 397
/* 388 */     MCD_OPC_CheckPredicate, 24, 17, 11, 0, // Skip to: 3226
/* 393 */     MCD_OPC_Decode, 222, 11, 55, // Opcode: DIV_MMR6
/* 397 */     MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 411
/* 402 */     MCD_OPC_CheckPredicate, 24, 3, 11, 0, // Skip to: 3226
/* 407 */     MCD_OPC_Decode, 198, 17, 55, // Opcode: MOD_MMR6
/* 411 */     MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 425
/* 416 */     MCD_OPC_CheckPredicate, 24, 245, 10, 0, // Skip to: 3226
/* 421 */     MCD_OPC_Decode, 220, 11, 55, // Opcode: DIVU_MMR6
/* 425 */     MCD_OPC_FilterValue, 7, 236, 10, 0, // Skip to: 3226
/* 430 */     MCD_OPC_CheckPredicate, 24, 231, 10, 0, // Skip to: 3226
/* 435 */     MCD_OPC_Decode, 196, 17, 55, // Opcode: MODU_MMR6
/* 439 */     MCD_OPC_FilterValue, 31, 17, 0, 0, // Skip to: 461
/* 444 */     MCD_OPC_CheckPredicate, 24, 217, 10, 0, // Skip to: 3226
/* 449 */     MCD_OPC_CheckField, 6, 3, 0, 210, 10, 0, // Skip to: 3226
/* 456 */     MCD_OPC_Decode, 212, 6, 155, 1, // Opcode: ALIGN_MMR6
/* 461 */     MCD_OPC_FilterValue, 44, 9, 0, 0, // Skip to: 475
/* 466 */     MCD_OPC_CheckPredicate, 24, 195, 10, 0, // Skip to: 3226
/* 471 */     MCD_OPC_Decode, 128, 13, 66, // Opcode: EXT_MMR6
/* 475 */     MCD_OPC_FilterValue, 52, 45, 0, 0, // Skip to: 525
/* 480 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 483 */     MCD_OPC_FilterValue, 3, 16, 0, 0, // Skip to: 504
/* 488 */     MCD_OPC_CheckPredicate, 24, 173, 10, 0, // Skip to: 3226
/* 493 */     MCD_OPC_CheckField, 14, 2, 0, 166, 10, 0, // Skip to: 3226
/* 500 */     MCD_OPC_Decode, 141, 17, 68, // Opcode: MFHC0_MMR6
/* 504 */     MCD_OPC_FilterValue, 11, 157, 10, 0, // Skip to: 3226
/* 509 */     MCD_OPC_CheckPredicate, 24, 152, 10, 0, // Skip to: 3226
/* 514 */     MCD_OPC_CheckField, 14, 2, 0, 145, 10, 0, // Skip to: 3226
/* 521 */     MCD_OPC_Decode, 170, 18, 69, // Opcode: MTHC0_MMR6
/* 525 */     MCD_OPC_FilterValue, 60, 66, 2, 0, // Skip to: 1108
/* 530 */     MCD_OPC_ExtractField, 14, 2,  // Inst{15-14} ...
/* 533 */     MCD_OPC_FilterValue, 0, 138, 0, 0, // Skip to: 676
/* 538 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 541 */     MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 555
/* 546 */     MCD_OPC_CheckPredicate, 24, 115, 10, 0, // Skip to: 3226
/* 551 */     MCD_OPC_Decode, 130, 17, 68, // Opcode: MFC0_MMR6
/* 555 */     MCD_OPC_FilterValue, 5, 45, 0, 0, // Skip to: 605
/* 560 */     MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 563 */     MCD_OPC_FilterValue, 3, 16, 0, 0, // Skip to: 584
/* 568 */     MCD_OPC_CheckPredicate, 24, 93, 10, 0, // Skip to: 3226
/* 573 */     MCD_OPC_CheckField, 21, 5, 0, 86, 10, 0, // Skip to: 3226
/* 580 */     MCD_OPC_Decode, 203, 12, 92, // Opcode: DVP_MMR6
/* 584 */     MCD_OPC_FilterValue, 7, 77, 10, 0, // Skip to: 3226
/* 589 */     MCD_OPC_CheckPredicate, 24, 72, 10, 0, // Skip to: 3226
/* 594 */     MCD_OPC_CheckField, 21, 5, 0, 65, 10, 0, // Skip to: 3226
/* 601 */     MCD_OPC_Decode, 226, 12, 92, // Opcode: EVP_MMR6
/* 605 */     MCD_OPC_FilterValue, 11, 9, 0, 0, // Skip to: 619
/* 610 */     MCD_OPC_CheckPredicate, 24, 51, 10, 0, // Skip to: 3226
/* 615 */     MCD_OPC_Decode, 158, 18, 69, // Opcode: MTC0_MMR6
/* 619 */     MCD_OPC_FilterValue, 12, 16, 0, 0, // Skip to: 640
/* 624 */     MCD_OPC_CheckPredicate, 24, 37, 10, 0, // Skip to: 3226
/* 629 */     MCD_OPC_CheckField, 11, 3, 1, 30, 10, 0, // Skip to: 3226
/* 636 */     MCD_OPC_Decode, 133, 8, 86, // Opcode: BITSWAP_MMR6
/* 640 */     MCD_OPC_FilterValue, 28, 21, 10, 0, // Skip to: 3226
/* 645 */     MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 648 */     MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 662
/* 653 */     MCD_OPC_CheckPredicate, 24, 8, 10, 0, // Skip to: 3226
/* 658 */     MCD_OPC_Decode, 243, 14, 80, // Opcode: JALRC_MMR6
/* 662 */     MCD_OPC_FilterValue, 3, 255, 9, 0, // Skip to: 3226
/* 667 */     MCD_OPC_CheckPredicate, 24, 250, 9, 0, // Skip to: 3226
/* 672 */     MCD_OPC_Decode, 242, 14, 80, // Opcode: JALRC_HB_MMR6
/* 676 */     MCD_OPC_FilterValue, 1, 10, 1, 0, // Skip to: 947
/* 681 */     MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 684 */     MCD_OPC_FilterValue, 0, 45, 0, 0, // Skip to: 734
/* 689 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 692 */     MCD_OPC_FilterValue, 13, 16, 0, 0, // Skip to: 713
/* 697 */     MCD_OPC_CheckPredicate, 24, 220, 9, 0, // Skip to: 3226
/* 702 */     MCD_OPC_CheckField, 16, 10, 0, 213, 9, 0, // Skip to: 3226
/* 709 */     MCD_OPC_Decode, 236, 23, 10, // Opcode: TLBINV_MMR6
/* 713 */     MCD_OPC_FilterValue, 29, 204, 9, 0, // Skip to: 3226
/* 718 */     MCD_OPC_CheckPredicate, 24, 199, 9, 0, // Skip to: 3226
/* 723 */     MCD_OPC_CheckField, 21, 5, 0, 192, 9, 0, // Skip to: 3226
/* 730 */     MCD_OPC_Decode, 233, 11, 92, // Opcode: DI_MMR6
/* 734 */     MCD_OPC_FilterValue, 1, 31, 0, 0, // Skip to: 770
/* 739 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 742 */     MCD_OPC_FilterValue, 12, 9, 0, 0, // Skip to: 756
/* 747 */     MCD_OPC_CheckPredicate, 24, 170, 9, 0, // Skip to: 3226
/* 752 */     MCD_OPC_Decode, 174, 9, 80, // Opcode: CLO_MMR6
/* 756 */     MCD_OPC_FilterValue, 20, 161, 9, 0, // Skip to: 3226
/* 761 */     MCD_OPC_CheckPredicate, 24, 156, 9, 0, // Skip to: 3226
/* 766 */     MCD_OPC_Decode, 137, 17, 90, // Opcode: MFC2_MMR6
/* 770 */     MCD_OPC_FilterValue, 2, 45, 0, 0, // Skip to: 820
/* 775 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 778 */     MCD_OPC_FilterValue, 13, 16, 0, 0, // Skip to: 799
/* 783 */     MCD_OPC_CheckPredicate, 24, 134, 9, 0, // Skip to: 3226
/* 788 */     MCD_OPC_CheckField, 16, 10, 0, 127, 9, 0, // Skip to: 3226
/* 795 */     MCD_OPC_Decode, 234, 23, 10, // Opcode: TLBINVF_MMR6
/* 799 */     MCD_OPC_FilterValue, 29, 118, 9, 0, // Skip to: 3226
/* 804 */     MCD_OPC_CheckPredicate, 24, 113, 9, 0, // Skip to: 3226
/* 809 */     MCD_OPC_CheckField, 21, 5, 0, 106, 9, 0, // Skip to: 3226
/* 816 */     MCD_OPC_Decode, 212, 12, 92, // Opcode: EI_MMR6
/* 820 */     MCD_OPC_FilterValue, 3, 16, 0, 0, // Skip to: 841
/* 825 */     MCD_OPC_CheckPredicate, 24, 92, 9, 0, // Skip to: 3226
/* 830 */     MCD_OPC_CheckField, 6, 5, 20, 85, 9, 0, // Skip to: 3226
/* 837 */     MCD_OPC_Decode, 166, 18, 91, // Opcode: MTC2_MMR6
/* 841 */     MCD_OPC_FilterValue, 4, 23, 0, 0, // Skip to: 869
/* 846 */     MCD_OPC_CheckPredicate, 25, 71, 9, 0, // Skip to: 3226
/* 851 */     MCD_OPC_CheckField, 21, 5, 0, 64, 9, 0, // Skip to: 3226
/* 858 */     MCD_OPC_CheckField, 6, 5, 5, 57, 9, 0, // Skip to: 3226
/* 865 */     MCD_OPC_Decode, 185, 14, 92, // Opcode: GINVI_MMR6
/* 869 */     MCD_OPC_FilterValue, 5, 23, 0, 0, // Skip to: 897
/* 874 */     MCD_OPC_CheckPredicate, 24, 43, 9, 0, // Skip to: 3226
/* 879 */     MCD_OPC_CheckField, 21, 5, 0, 36, 9, 0, // Skip to: 3226
/* 886 */     MCD_OPC_CheckField, 6, 5, 13, 29, 9, 0, // Skip to: 3226
/* 893 */     MCD_OPC_Decode, 180, 23, 87, // Opcode: SYNC_MMR6
/* 897 */     MCD_OPC_FilterValue, 6, 24, 0, 0, // Skip to: 926
/* 902 */     MCD_OPC_CheckPredicate, 25, 15, 9, 0, // Skip to: 3226
/* 907 */     MCD_OPC_CheckField, 21, 5, 0, 8, 9, 0, // Skip to: 3226
/* 914 */     MCD_OPC_CheckField, 6, 3, 5, 1, 9, 0, // Skip to: 3226
/* 921 */     MCD_OPC_Decode, 188, 14, 156, 1, // Opcode: GINVT_MMR6
/* 926 */     MCD_OPC_FilterValue, 7, 247, 8, 0, // Skip to: 3226
/* 931 */     MCD_OPC_CheckPredicate, 24, 242, 8, 0, // Skip to: 3226
/* 936 */     MCD_OPC_CheckField, 6, 5, 12, 235, 8, 0, // Skip to: 3226
/* 943 */     MCD_OPC_Decode, 171, 24, 80, // Opcode: WSBH_MMR6
/* 947 */     MCD_OPC_FilterValue, 2, 45, 0, 0, // Skip to: 997
/* 952 */     MCD_OPC_ExtractField, 6, 8,  // Inst{13-6} ...
/* 955 */     MCD_OPC_FilterValue, 52, 9, 0, 0, // Skip to: 969
/* 960 */     MCD_OPC_CheckPredicate, 24, 213, 8, 0, // Skip to: 3226
/* 965 */     MCD_OPC_Decode, 147, 17, 90, // Opcode: MFHC2_MMR6
/* 969 */     MCD_OPC_FilterValue, 77, 9, 0, 0, // Skip to: 983
/* 974 */     MCD_OPC_CheckPredicate, 24, 199, 8, 0, // Skip to: 3226
/* 979 */     MCD_OPC_Decode, 163, 24, 88, // Opcode: WAIT_MMR6
/* 983 */     MCD_OPC_FilterValue, 116, 190, 8, 0, // Skip to: 3226
/* 988 */     MCD_OPC_CheckPredicate, 24, 185, 8, 0, // Skip to: 3226
/* 993 */     MCD_OPC_Decode, 176, 18, 91, // Opcode: MTHC2_MMR6
/* 997 */     MCD_OPC_FilterValue, 3, 176, 8, 0, // Skip to: 3226
/* 1002 */    MCD_OPC_ExtractField, 6, 8,  // Inst{13-6} ...
/* 1005 */    MCD_OPC_FilterValue, 109, 9, 0, 0, // Skip to: 1019
/* 1010 */    MCD_OPC_CheckPredicate, 24, 163, 8, 0, // Skip to: 3226
/* 1015 */    MCD_OPC_Decode, 224, 20, 88, // Opcode: SDBBP_MMR6
/* 1019 */    MCD_OPC_FilterValue, 133, 1, 9, 0, 0, // Skip to: 1034
/* 1025 */    MCD_OPC_CheckPredicate, 24, 148, 8, 0, // Skip to: 3226
/* 1030 */    MCD_OPC_Decode, 132, 20, 80, // Opcode: RDPGPR_MMR6
/* 1034 */    MCD_OPC_FilterValue, 141, 1, 16, 0, 0, // Skip to: 1056
/* 1040 */    MCD_OPC_CheckPredicate, 24, 133, 8, 0, // Skip to: 3226
/* 1045 */    MCD_OPC_CheckField, 16, 10, 0, 126, 8, 0, // Skip to: 3226
/* 1052 */    MCD_OPC_Decode, 208, 11, 10, // Opcode: DERET_MMR6
/* 1056 */    MCD_OPC_FilterValue, 197, 1, 9, 0, 0, // Skip to: 1071
/* 1062 */    MCD_OPC_CheckPredicate, 24, 111, 8, 0, // Skip to: 3226
/* 1067 */    MCD_OPC_Decode, 167, 24, 80, // Opcode: WRPGPR_MMR6
/* 1071 */    MCD_OPC_FilterValue, 205, 1, 101, 8, 0, // Skip to: 3226
/* 1077 */    MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 1080 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 1094
/* 1085 */    MCD_OPC_CheckPredicate, 24, 88, 8, 0, // Skip to: 3226
/* 1090 */    MCD_OPC_Decode, 221, 12, 10, // Opcode: ERET_MMR6
/* 1094 */    MCD_OPC_FilterValue, 1, 79, 8, 0, // Skip to: 3226
/* 1099 */    MCD_OPC_CheckPredicate, 24, 74, 8, 0, // Skip to: 3226
/* 1104 */    MCD_OPC_Decode, 218, 12, 10, // Opcode: ERETNC_MMR6
/* 1108 */    MCD_OPC_FilterValue, 63, 65, 8, 0, // Skip to: 3226
/* 1113 */    MCD_OPC_CheckPredicate, 24, 60, 8, 0, // Skip to: 3226
/* 1118 */    MCD_OPC_CheckField, 22, 4, 0, 53, 8, 0, // Skip to: 3226
/* 1125 */    MCD_OPC_Decode, 209, 21, 157, 1, // Opcode: SIGRIE_MMR6
/* 1130 */    MCD_OPC_FilterValue, 4, 26, 0, 0, // Skip to: 1161
/* 1135 */    MCD_OPC_CheckPredicate, 24, 12, 0, 0, // Skip to: 1152
/* 1140 */    MCD_OPC_CheckField, 16, 5, 0, 5, 0, 0, // Skip to: 1152
/* 1147 */    MCD_OPC_Decode, 251, 15, 158, 1, // Opcode: LUI_MMR6
/* 1152 */    MCD_OPC_CheckPredicate, 24, 21, 8, 0, // Skip to: 3226
/* 1157 */    MCD_OPC_Decode, 247, 6, 108, // Opcode: AUI_MMR6
/* 1161 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 1176
/* 1166 */    MCD_OPC_CheckPredicate, 24, 7, 8, 0, // Skip to: 3226
/* 1171 */    MCD_OPC_Decode, 166, 15, 159, 1, // Opcode: LBU_MMR6
/* 1176 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 1190
/* 1181 */    MCD_OPC_CheckPredicate, 24, 248, 7, 0, // Skip to: 3226
/* 1186 */    MCD_OPC_Decode, 203, 20, 98, // Opcode: SB_MMR6
/* 1190 */    MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 1205
/* 1195 */    MCD_OPC_CheckPredicate, 24, 234, 7, 0, // Skip to: 3226
/* 1200 */    MCD_OPC_Decode, 171, 15, 159, 1, // Opcode: LB_MMR6
/* 1205 */    MCD_OPC_FilterValue, 8, 105, 0, 0, // Skip to: 1315
/* 1210 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 1213 */    MCD_OPC_FilterValue, 0, 17, 0, 0, // Skip to: 1235
/* 1218 */    MCD_OPC_CheckPredicate, 24, 211, 7, 0, // Skip to: 3226
/* 1223 */    MCD_OPC_CheckField, 11, 1, 0, 204, 7, 0, // Skip to: 3226
/* 1230 */    MCD_OPC_Decode, 139, 16, 160, 1, // Opcode: LWC2_MMR6
/* 1235 */    MCD_OPC_FilterValue, 2, 17, 0, 0, // Skip to: 1257
/* 1240 */    MCD_OPC_CheckPredicate, 24, 189, 7, 0, // Skip to: 3226
/* 1245 */    MCD_OPC_CheckField, 11, 1, 0, 182, 7, 0, // Skip to: 3226
/* 1252 */    MCD_OPC_Decode, 186, 15, 160, 1, // Opcode: LDC2_MMR6
/* 1257 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 1271
/* 1262 */    MCD_OPC_CheckPredicate, 24, 167, 7, 0, // Skip to: 3226
/* 1267 */    MCD_OPC_Decode, 250, 8, 100, // Opcode: CACHE_MMR6
/* 1271 */    MCD_OPC_FilterValue, 8, 17, 0, 0, // Skip to: 1293
/* 1276 */    MCD_OPC_CheckPredicate, 24, 153, 7, 0, // Skip to: 3226
/* 1281 */    MCD_OPC_CheckField, 11, 1, 0, 146, 7, 0, // Skip to: 3226
/* 1288 */    MCD_OPC_Decode, 137, 23, 160, 1, // Opcode: SWC2_MMR6
/* 1293 */    MCD_OPC_FilterValue, 10, 136, 7, 0, // Skip to: 3226
/* 1298 */    MCD_OPC_CheckPredicate, 24, 131, 7, 0, // Skip to: 3226
/* 1303 */    MCD_OPC_CheckField, 11, 1, 0, 124, 7, 0, // Skip to: 3226
/* 1310 */    MCD_OPC_Decode, 233, 20, 160, 1, // Opcode: SDC2_MMR6
/* 1315 */    MCD_OPC_FilterValue, 12, 9, 0, 0, // Skip to: 1329
/* 1320 */    MCD_OPC_CheckPredicate, 24, 109, 7, 0, // Skip to: 3226
/* 1325 */    MCD_OPC_Decode, 139, 6, 97, // Opcode: ADDIU_MMR6
/* 1329 */    MCD_OPC_FilterValue, 14, 9, 0, 0, // Skip to: 1343
/* 1334 */    MCD_OPC_CheckPredicate, 24, 95, 7, 0, // Skip to: 3226
/* 1339 */    MCD_OPC_Decode, 205, 21, 98, // Opcode: SH_MMR6
/* 1343 */    MCD_OPC_FilterValue, 16, 78, 0, 0, // Skip to: 1426
/* 1348 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1351 */    MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 1366
/* 1356 */    MCD_OPC_CheckPredicate, 26, 73, 7, 0, // Skip to: 3226
/* 1361 */    MCD_OPC_Decode, 165, 7, 161, 1, // Opcode: BC1EQZC_MMR6
/* 1366 */    MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 1381
/* 1371 */    MCD_OPC_CheckPredicate, 26, 58, 7, 0, // Skip to: 3226
/* 1376 */    MCD_OPC_Decode, 170, 7, 161, 1, // Opcode: BC1NEZC_MMR6
/* 1381 */    MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 1396
/* 1386 */    MCD_OPC_CheckPredicate, 24, 43, 7, 0, // Skip to: 3226
/* 1391 */    MCD_OPC_Decode, 175, 7, 162, 1, // Opcode: BC2EQZC_MMR6
/* 1396 */    MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 1411
/* 1401 */    MCD_OPC_CheckPredicate, 24, 28, 7, 0, // Skip to: 3226
/* 1406 */    MCD_OPC_Decode, 177, 7, 162, 1, // Opcode: BC2NEZC_MMR6
/* 1411 */    MCD_OPC_FilterValue, 12, 18, 7, 0, // Skip to: 3226
/* 1416 */    MCD_OPC_CheckPredicate, 24, 13, 7, 0, // Skip to: 3226
/* 1421 */    MCD_OPC_Decode, 176, 23, 163, 1, // Opcode: SYNCI_MMR6
/* 1426 */    MCD_OPC_FilterValue, 20, 9, 0, 0, // Skip to: 1440
/* 1431 */    MCD_OPC_CheckPredicate, 24, 254, 6, 0, // Skip to: 3226
/* 1436 */    MCD_OPC_Decode, 169, 19, 108, // Opcode: ORI_MMR6
/* 1440 */    MCD_OPC_FilterValue, 21, 87, 5, 0, // Skip to: 2812
/* 1445 */    MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 1448 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 1463
/* 1453 */    MCD_OPC_CheckPredicate, 26, 232, 6, 0, // Skip to: 3226
/* 1458 */    MCD_OPC_Decode, 186, 17, 164, 1, // Opcode: MIN_S_MMR6
/* 1463 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 1478
/* 1468 */    MCD_OPC_CheckPredicate, 26, 217, 6, 0, // Skip to: 3226
/* 1473 */    MCD_OPC_Decode, 217, 9, 165, 1, // Opcode: CMP_AF_S_MMR6
/* 1478 */    MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 1493
/* 1483 */    MCD_OPC_CheckPredicate, 26, 202, 6, 0, // Skip to: 3226
/* 1488 */    MCD_OPC_Decode, 250, 16, 164, 1, // Opcode: MAX_S_MMR6
/* 1493 */    MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 1508
/* 1498 */    MCD_OPC_CheckPredicate, 26, 187, 6, 0, // Skip to: 3226
/* 1503 */    MCD_OPC_Decode, 216, 9, 166, 1, // Opcode: CMP_AF_D_MMR6
/* 1508 */    MCD_OPC_FilterValue, 32, 17, 0, 0, // Skip to: 1530
/* 1513 */    MCD_OPC_CheckPredicate, 24, 172, 6, 0, // Skip to: 3226
/* 1518 */    MCD_OPC_CheckField, 11, 5, 0, 165, 6, 0, // Skip to: 3226
/* 1525 */    MCD_OPC_Decode, 154, 20, 167, 1, // Opcode: RINT_S_MMR6
/* 1530 */    MCD_OPC_FilterValue, 35, 10, 0, 0, // Skip to: 1545
/* 1535 */    MCD_OPC_CheckPredicate, 26, 150, 6, 0, // Skip to: 3226
/* 1540 */    MCD_OPC_Decode, 167, 17, 164, 1, // Opcode: MINA_S_MMR6
/* 1545 */    MCD_OPC_FilterValue, 43, 10, 0, 0, // Skip to: 1560
/* 1550 */    MCD_OPC_CheckPredicate, 26, 135, 6, 0, // Skip to: 3226
/* 1555 */    MCD_OPC_Decode, 231, 16, 164, 1, // Opcode: MAXA_S_MMR6
/* 1560 */    MCD_OPC_FilterValue, 48, 10, 0, 0, // Skip to: 1575
/* 1565 */    MCD_OPC_CheckPredicate, 26, 120, 6, 0, // Skip to: 3226
/* 1570 */    MCD_OPC_Decode, 144, 13, 168, 1, // Opcode: FADD_S_MMR6
/* 1575 */    MCD_OPC_FilterValue, 56, 10, 0, 0, // Skip to: 1590
/* 1580 */    MCD_OPC_CheckPredicate, 24, 105, 6, 0, // Skip to: 3226
/* 1585 */    MCD_OPC_Decode, 128, 21, 164, 1, // Opcode: SELEQZ_S_MMR6
/* 1590 */    MCD_OPC_FilterValue, 59, 31, 0, 0, // Skip to: 1626
/* 1595 */    MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 1598 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 1612
/* 1603 */    MCD_OPC_CheckPredicate, 26, 82, 6, 0, // Skip to: 3226
/* 1608 */    MCD_OPC_Decode, 135, 17, 119, // Opcode: MFC1_MMR6
/* 1612 */    MCD_OPC_FilterValue, 5, 73, 6, 0, // Skip to: 3226
/* 1617 */    MCD_OPC_CheckPredicate, 26, 68, 6, 0, // Skip to: 3226
/* 1622 */    MCD_OPC_Decode, 164, 18, 125, // Opcode: MTC1_MMR6
/* 1626 */    MCD_OPC_FilterValue, 69, 10, 0, 0, // Skip to: 1641
/* 1631 */    MCD_OPC_CheckPredicate, 26, 54, 6, 0, // Skip to: 3226
/* 1636 */    MCD_OPC_Decode, 157, 10, 165, 1, // Opcode: CMP_UN_S_MMR6
/* 1641 */    MCD_OPC_FilterValue, 85, 10, 0, 0, // Skip to: 1656
/* 1646 */    MCD_OPC_CheckPredicate, 26, 39, 6, 0, // Skip to: 3226
/* 1651 */    MCD_OPC_Decode, 155, 10, 166, 1, // Opcode: CMP_UN_D_MMR6
/* 1656 */    MCD_OPC_FilterValue, 96, 17, 0, 0, // Skip to: 1678
/* 1661 */    MCD_OPC_CheckPredicate, 24, 24, 6, 0, // Skip to: 3226
/* 1666 */    MCD_OPC_CheckField, 11, 5, 0, 17, 6, 0, // Skip to: 3226
/* 1673 */    MCD_OPC_Decode, 155, 9, 167, 1, // Opcode: CLASS_S_MMR6
/* 1678 */    MCD_OPC_FilterValue, 112, 10, 0, 0, // Skip to: 1693
/* 1683 */    MCD_OPC_CheckPredicate, 26, 2, 6, 0, // Skip to: 3226
/* 1688 */    MCD_OPC_Decode, 162, 14, 168, 1, // Opcode: FSUB_S_MMR6
/* 1693 */    MCD_OPC_FilterValue, 120, 10, 0, 0, // Skip to: 1708
/* 1698 */    MCD_OPC_CheckPredicate, 24, 243, 5, 0, // Skip to: 3226
/* 1703 */    MCD_OPC_Decode, 135, 21, 164, 1, // Opcode: SELNEZ_S_MMR6
/* 1708 */    MCD_OPC_FilterValue, 123, 31, 0, 0, // Skip to: 1744
/* 1713 */    MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 1716 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 1730
/* 1721 */    MCD_OPC_CheckPredicate, 26, 220, 5, 0, // Skip to: 3226
/* 1726 */    MCD_OPC_Decode, 234, 13, 124, // Opcode: FMOV_S_MMR6
/* 1730 */    MCD_OPC_FilterValue, 4, 211, 5, 0, // Skip to: 3226
/* 1735 */    MCD_OPC_CheckPredicate, 26, 206, 5, 0, // Skip to: 3226
/* 1740 */    MCD_OPC_Decode, 231, 13, 122, // Opcode: FMOV_D_MMR6
/* 1744 */    MCD_OPC_FilterValue, 133, 1, 10, 0, 0, // Skip to: 1760
/* 1750 */    MCD_OPC_CheckPredicate, 26, 191, 5, 0, // Skip to: 3226
/* 1755 */    MCD_OPC_Decode, 223, 9, 165, 1, // Opcode: CMP_EQ_S_MMR6
/* 1760 */    MCD_OPC_FilterValue, 149, 1, 10, 0, 0, // Skip to: 1776
/* 1766 */    MCD_OPC_CheckPredicate, 26, 175, 5, 0, // Skip to: 3226
/* 1771 */    MCD_OPC_Decode, 219, 9, 166, 1, // Opcode: CMP_EQ_D_MMR6
/* 1776 */    MCD_OPC_FilterValue, 176, 1, 10, 0, 0, // Skip to: 1792
/* 1782 */    MCD_OPC_CheckPredicate, 26, 159, 5, 0, // Skip to: 3226
/* 1787 */    MCD_OPC_Decode, 245, 13, 168, 1, // Opcode: FMUL_S_MMR6
/* 1792 */    MCD_OPC_FilterValue, 184, 1, 10, 0, 0, // Skip to: 1808
/* 1798 */    MCD_OPC_CheckPredicate, 24, 143, 5, 0, // Skip to: 3226
/* 1803 */    MCD_OPC_Decode, 139, 21, 169, 1, // Opcode: SEL_S_MMR6
/* 1808 */    MCD_OPC_FilterValue, 197, 1, 10, 0, 0, // Skip to: 1824
/* 1814 */    MCD_OPC_CheckPredicate, 26, 127, 5, 0, // Skip to: 3226
/* 1819 */    MCD_OPC_Decode, 145, 10, 165, 1, // Opcode: CMP_UEQ_S_MMR6
/* 1824 */    MCD_OPC_FilterValue, 213, 1, 10, 0, 0, // Skip to: 1840
/* 1830 */    MCD_OPC_CheckPredicate, 26, 111, 5, 0, // Skip to: 3226
/* 1835 */    MCD_OPC_Decode, 143, 10, 166, 1, // Opcode: CMP_UEQ_D_MMR6
/* 1840 */    MCD_OPC_FilterValue, 240, 1, 10, 0, 0, // Skip to: 1856
/* 1846 */    MCD_OPC_CheckPredicate, 26, 95, 5, 0, // Skip to: 3226
/* 1851 */    MCD_OPC_Decode, 182, 13, 168, 1, // Opcode: FDIV_S_MMR6
/* 1856 */    MCD_OPC_FilterValue, 133, 2, 10, 0, 0, // Skip to: 1872
/* 1862 */    MCD_OPC_CheckPredicate, 26, 79, 5, 0, // Skip to: 3226
/* 1867 */    MCD_OPC_Decode, 237, 9, 165, 1, // Opcode: CMP_LT_S_MMR6
/* 1872 */    MCD_OPC_FilterValue, 149, 2, 10, 0, 0, // Skip to: 1888
/* 1878 */    MCD_OPC_CheckPredicate, 26, 63, 5, 0, // Skip to: 3226
/* 1883 */    MCD_OPC_Decode, 233, 9, 166, 1, // Opcode: CMP_LT_D_MMR6
/* 1888 */    MCD_OPC_FilterValue, 187, 2, 45, 0, 0, // Skip to: 1939
/* 1894 */    MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 1897 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 1911
/* 1902 */    MCD_OPC_CheckPredicate, 26, 39, 5, 0, // Skip to: 3226
/* 1907 */    MCD_OPC_Decode, 198, 10, 121, // Opcode: CVT_L_S_MMR6
/* 1911 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 1925
/* 1916 */    MCD_OPC_CheckPredicate, 26, 25, 5, 0, // Skip to: 3226
/* 1921 */    MCD_OPC_Decode, 219, 10, 124, // Opcode: CVT_W_S_MMR6
/* 1925 */    MCD_OPC_FilterValue, 8, 16, 5, 0, // Skip to: 3226
/* 1930 */    MCD_OPC_CheckPredicate, 26, 11, 5, 0, // Skip to: 3226
/* 1935 */    MCD_OPC_Decode, 195, 10, 122, // Opcode: CVT_L_D_MMR6
/* 1939 */    MCD_OPC_FilterValue, 197, 2, 10, 0, 0, // Skip to: 1955
/* 1945 */    MCD_OPC_CheckPredicate, 26, 252, 4, 0, // Skip to: 3226
/* 1950 */    MCD_OPC_Decode, 153, 10, 165, 1, // Opcode: CMP_ULT_S_MMR6
/* 1955 */    MCD_OPC_FilterValue, 213, 2, 10, 0, 0, // Skip to: 1971
/* 1961 */    MCD_OPC_CheckPredicate, 26, 236, 4, 0, // Skip to: 3226
/* 1966 */    MCD_OPC_Decode, 151, 10, 166, 1, // Opcode: CMP_ULT_D_MMR6
/* 1971 */    MCD_OPC_FilterValue, 133, 3, 10, 0, 0, // Skip to: 1987
/* 1977 */    MCD_OPC_CheckPredicate, 26, 220, 4, 0, // Skip to: 3226
/* 1982 */    MCD_OPC_Decode, 231, 9, 165, 1, // Opcode: CMP_LE_S_MMR6
/* 1987 */    MCD_OPC_FilterValue, 149, 3, 10, 0, 0, // Skip to: 2003
/* 1993 */    MCD_OPC_CheckPredicate, 26, 204, 4, 0, // Skip to: 3226
/* 1998 */    MCD_OPC_Decode, 227, 9, 166, 1, // Opcode: CMP_LE_D_MMR6
/* 2003 */    MCD_OPC_FilterValue, 184, 3, 10, 0, 0, // Skip to: 2019
/* 2009 */    MCD_OPC_CheckPredicate, 26, 188, 4, 0, // Skip to: 3226
/* 2014 */    MCD_OPC_Decode, 199, 16, 170, 1, // Opcode: MADDF_S_MMR6
/* 2019 */    MCD_OPC_FilterValue, 197, 3, 10, 0, 0, // Skip to: 2035
/* 2025 */    MCD_OPC_CheckPredicate, 26, 172, 4, 0, // Skip to: 3226
/* 2030 */    MCD_OPC_Decode, 149, 10, 165, 1, // Opcode: CMP_ULE_S_MMR6
/* 2035 */    MCD_OPC_FilterValue, 213, 3, 10, 0, 0, // Skip to: 2051
/* 2041 */    MCD_OPC_CheckPredicate, 26, 156, 4, 0, // Skip to: 3226
/* 2046 */    MCD_OPC_Decode, 147, 10, 166, 1, // Opcode: CMP_ULE_D_MMR6
/* 2051 */    MCD_OPC_FilterValue, 248, 3, 10, 0, 0, // Skip to: 2067
/* 2057 */    MCD_OPC_CheckPredicate, 26, 140, 4, 0, // Skip to: 3226
/* 2062 */    MCD_OPC_Decode, 135, 18, 170, 1, // Opcode: MSUBF_S_MMR6
/* 2067 */    MCD_OPC_FilterValue, 131, 4, 10, 0, 0, // Skip to: 2083
/* 2073 */    MCD_OPC_CheckPredicate, 26, 124, 4, 0, // Skip to: 3226
/* 2078 */    MCD_OPC_Decode, 181, 17, 145, 1, // Opcode: MIN_D_MMR6
/* 2083 */    MCD_OPC_FilterValue, 133, 4, 10, 0, 0, // Skip to: 2099
/* 2089 */    MCD_OPC_CheckPredicate, 26, 108, 4, 0, // Skip to: 3226
/* 2094 */    MCD_OPC_Decode, 241, 9, 165, 1, // Opcode: CMP_SAF_S_MMR6
/* 2099 */    MCD_OPC_FilterValue, 139, 4, 10, 0, 0, // Skip to: 2115
/* 2105 */    MCD_OPC_CheckPredicate, 26, 92, 4, 0, // Skip to: 3226
/* 2110 */    MCD_OPC_Decode, 245, 16, 145, 1, // Opcode: MAX_D_MMR6
/* 2115 */    MCD_OPC_FilterValue, 149, 4, 10, 0, 0, // Skip to: 2131
/* 2121 */    MCD_OPC_CheckPredicate, 26, 76, 4, 0, // Skip to: 3226
/* 2126 */    MCD_OPC_Decode, 239, 9, 166, 1, // Opcode: CMP_SAF_D_MMR6
/* 2131 */    MCD_OPC_FilterValue, 160, 4, 17, 0, 0, // Skip to: 2154
/* 2137 */    MCD_OPC_CheckPredicate, 24, 60, 4, 0, // Skip to: 3226
/* 2142 */    MCD_OPC_CheckField, 11, 5, 0, 53, 4, 0, // Skip to: 3226
/* 2149 */    MCD_OPC_Decode, 152, 20, 171, 1, // Opcode: RINT_D_MMR6
/* 2154 */    MCD_OPC_FilterValue, 163, 4, 10, 0, 0, // Skip to: 2170
/* 2160 */    MCD_OPC_CheckPredicate, 26, 37, 4, 0, // Skip to: 3226
/* 2165 */    MCD_OPC_Decode, 165, 17, 145, 1, // Opcode: MINA_D_MMR6
/* 2170 */    MCD_OPC_FilterValue, 171, 4, 10, 0, 0, // Skip to: 2186
/* 2176 */    MCD_OPC_CheckPredicate, 26, 21, 4, 0, // Skip to: 3226
/* 2181 */    MCD_OPC_Decode, 229, 16, 145, 1, // Opcode: MAXA_D_MMR6
/* 2186 */    MCD_OPC_FilterValue, 184, 4, 10, 0, 0, // Skip to: 2202
/* 2192 */    MCD_OPC_CheckPredicate, 24, 5, 4, 0, // Skip to: 3226
/* 2197 */    MCD_OPC_Decode, 253, 20, 145, 1, // Opcode: SELEQZ_D_MMR6
/* 2202 */    MCD_OPC_FilterValue, 197, 4, 10, 0, 0, // Skip to: 2218
/* 2208 */    MCD_OPC_CheckPredicate, 26, 245, 3, 0, // Skip to: 3226
/* 2213 */    MCD_OPC_Decode, 141, 10, 165, 1, // Opcode: CMP_SUN_S_MMR6
/* 2218 */    MCD_OPC_FilterValue, 213, 4, 10, 0, 0, // Skip to: 2234
/* 2224 */    MCD_OPC_CheckPredicate, 26, 229, 3, 0, // Skip to: 3226
/* 2229 */    MCD_OPC_Decode, 139, 10, 166, 1, // Opcode: CMP_SUN_D_MMR6
/* 2234 */    MCD_OPC_FilterValue, 224, 4, 17, 0, 0, // Skip to: 2257
/* 2240 */    MCD_OPC_CheckPredicate, 24, 213, 3, 0, // Skip to: 3226
/* 2245 */    MCD_OPC_CheckField, 11, 5, 0, 206, 3, 0, // Skip to: 3226
/* 2252 */    MCD_OPC_Decode, 153, 9, 171, 1, // Opcode: CLASS_D_MMR6
/* 2257 */    MCD_OPC_FilterValue, 248, 4, 10, 0, 0, // Skip to: 2273
/* 2263 */    MCD_OPC_CheckPredicate, 24, 190, 3, 0, // Skip to: 3226
/* 2268 */    MCD_OPC_Decode, 132, 21, 145, 1, // Opcode: SELNEZ_D_MMR6
/* 2273 */    MCD_OPC_FilterValue, 133, 5, 10, 0, 0, // Skip to: 2289
/* 2279 */    MCD_OPC_CheckPredicate, 26, 174, 3, 0, // Skip to: 3226
/* 2284 */    MCD_OPC_Decode, 245, 9, 165, 1, // Opcode: CMP_SEQ_S_MMR6
/* 2289 */    MCD_OPC_FilterValue, 149, 5, 10, 0, 0, // Skip to: 2305
/* 2295 */    MCD_OPC_CheckPredicate, 26, 158, 3, 0, // Skip to: 3226
/* 2300 */    MCD_OPC_Decode, 243, 9, 166, 1, // Opcode: CMP_SEQ_D_MMR6
/* 2305 */    MCD_OPC_FilterValue, 184, 5, 10, 0, 0, // Skip to: 2321
/* 2311 */    MCD_OPC_CheckPredicate, 24, 142, 3, 0, // Skip to: 3226
/* 2316 */    MCD_OPC_Decode, 137, 21, 172, 1, // Opcode: SEL_D_MMR6
/* 2321 */    MCD_OPC_FilterValue, 197, 5, 10, 0, 0, // Skip to: 2337
/* 2327 */    MCD_OPC_CheckPredicate, 26, 126, 3, 0, // Skip to: 3226
/* 2332 */    MCD_OPC_Decode, 129, 10, 165, 1, // Opcode: CMP_SUEQ_S_MMR6
/* 2337 */    MCD_OPC_FilterValue, 213, 5, 10, 0, 0, // Skip to: 2353
/* 2343 */    MCD_OPC_CheckPredicate, 26, 110, 3, 0, // Skip to: 3226
/* 2348 */    MCD_OPC_Decode, 255, 9, 166, 1, // Opcode: CMP_SUEQ_D_MMR6
/* 2353 */    MCD_OPC_FilterValue, 133, 6, 10, 0, 0, // Skip to: 2369
/* 2359 */    MCD_OPC_CheckPredicate, 26, 94, 3, 0, // Skip to: 3226
/* 2364 */    MCD_OPC_Decode, 253, 9, 165, 1, // Opcode: CMP_SLT_S_MMR6
/* 2369 */    MCD_OPC_FilterValue, 149, 6, 10, 0, 0, // Skip to: 2385
/* 2375 */    MCD_OPC_CheckPredicate, 26, 78, 3, 0, // Skip to: 3226
/* 2380 */    MCD_OPC_Decode, 251, 9, 166, 1, // Opcode: CMP_SLT_D_MMR6
/* 2385 */    MCD_OPC_FilterValue, 187, 6, 228, 0, 0, // Skip to: 2619
/* 2391 */    MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 2394 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 2408
/* 2399 */    MCD_OPC_CheckPredicate, 26, 54, 3, 0, // Skip to: 3226
/* 2404 */    MCD_OPC_Decode, 209, 13, 121, // Opcode: FLOOR_L_S_MMR6
/* 2408 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 2422
/* 2413 */    MCD_OPC_CheckPredicate, 26, 40, 3, 0, // Skip to: 3226
/* 2418 */    MCD_OPC_Decode, 216, 13, 124, // Opcode: FLOOR_W_S_MMR6
/* 2422 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 2436
/* 2427 */    MCD_OPC_CheckPredicate, 26, 26, 3, 0, // Skip to: 3226
/* 2432 */    MCD_OPC_Decode, 128, 9, 121, // Opcode: CEIL_L_S_MMR6
/* 2436 */    MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 2450
/* 2441 */    MCD_OPC_CheckPredicate, 26, 12, 3, 0, // Skip to: 3226
/* 2446 */    MCD_OPC_Decode, 135, 9, 124, // Opcode: CEIL_W_S_MMR6
/* 2450 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 2464
/* 2455 */    MCD_OPC_CheckPredicate, 26, 254, 2, 0, // Skip to: 3226
/* 2460 */    MCD_OPC_Decode, 137, 24, 121, // Opcode: TRUNC_L_S_MMR6
/* 2464 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 2478
/* 2469 */    MCD_OPC_CheckPredicate, 26, 240, 2, 0, // Skip to: 3226
/* 2474 */    MCD_OPC_Decode, 144, 24, 124, // Opcode: TRUNC_W_S_MMR6
/* 2478 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 2492
/* 2483 */    MCD_OPC_CheckPredicate, 26, 226, 2, 0, // Skip to: 3226
/* 2488 */    MCD_OPC_Decode, 165, 20, 121, // Opcode: ROUND_L_S_MMR6
/* 2492 */    MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 2506
/* 2497 */    MCD_OPC_CheckPredicate, 26, 212, 2, 0, // Skip to: 3226
/* 2502 */    MCD_OPC_Decode, 172, 20, 124, // Opcode: ROUND_W_S_MMR6
/* 2506 */    MCD_OPC_FilterValue, 8, 9, 0, 0, // Skip to: 2520
/* 2511 */    MCD_OPC_CheckPredicate, 26, 198, 2, 0, // Skip to: 3226
/* 2516 */    MCD_OPC_Decode, 207, 13, 122, // Opcode: FLOOR_L_D_MMR6
/* 2520 */    MCD_OPC_FilterValue, 9, 9, 0, 0, // Skip to: 2534
/* 2525 */    MCD_OPC_CheckPredicate, 26, 184, 2, 0, // Skip to: 3226
/* 2530 */    MCD_OPC_Decode, 212, 13, 126, // Opcode: FLOOR_W_D_MMR6
/* 2534 */    MCD_OPC_FilterValue, 10, 9, 0, 0, // Skip to: 2548
/* 2539 */    MCD_OPC_CheckPredicate, 26, 170, 2, 0, // Skip to: 3226
/* 2544 */    MCD_OPC_Decode, 254, 8, 122, // Opcode: CEIL_L_D_MMR6
/* 2548 */    MCD_OPC_FilterValue, 11, 9, 0, 0, // Skip to: 2562
/* 2553 */    MCD_OPC_CheckPredicate, 26, 156, 2, 0, // Skip to: 3226
/* 2558 */    MCD_OPC_Decode, 131, 9, 126, // Opcode: CEIL_W_D_MMR6
/* 2562 */    MCD_OPC_FilterValue, 12, 9, 0, 0, // Skip to: 2576
/* 2567 */    MCD_OPC_CheckPredicate, 26, 142, 2, 0, // Skip to: 3226
/* 2572 */    MCD_OPC_Decode, 135, 24, 122, // Opcode: TRUNC_L_D_MMR6
/* 2576 */    MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 2591
/* 2581 */    MCD_OPC_CheckPredicate, 26, 128, 2, 0, // Skip to: 3226
/* 2586 */    MCD_OPC_Decode, 140, 24, 146, 1, // Opcode: TRUNC_W_D_MMR6
/* 2591 */    MCD_OPC_FilterValue, 14, 9, 0, 0, // Skip to: 2605
/* 2596 */    MCD_OPC_CheckPredicate, 26, 113, 2, 0, // Skip to: 3226
/* 2601 */    MCD_OPC_Decode, 163, 20, 122, // Opcode: ROUND_L_D_MMR6
/* 2605 */    MCD_OPC_FilterValue, 15, 104, 2, 0, // Skip to: 3226
/* 2610 */    MCD_OPC_CheckPredicate, 26, 99, 2, 0, // Skip to: 3226
/* 2615 */    MCD_OPC_Decode, 168, 20, 122, // Opcode: ROUND_W_D_MMR6
/* 2619 */    MCD_OPC_FilterValue, 197, 6, 10, 0, 0, // Skip to: 2635
/* 2625 */    MCD_OPC_CheckPredicate, 26, 84, 2, 0, // Skip to: 3226
/* 2630 */    MCD_OPC_Decode, 137, 10, 165, 1, // Opcode: CMP_SULT_S_MMR6
/* 2635 */    MCD_OPC_FilterValue, 213, 6, 10, 0, 0, // Skip to: 2651
/* 2641 */    MCD_OPC_CheckPredicate, 26, 68, 2, 0, // Skip to: 3226
/* 2646 */    MCD_OPC_Decode, 135, 10, 166, 1, // Opcode: CMP_SULT_D_MMR6
/* 2651 */    MCD_OPC_FilterValue, 251, 6, 59, 0, 0, // Skip to: 2716
/* 2657 */    MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 2660 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 2674
/* 2665 */    MCD_OPC_CheckPredicate, 26, 44, 2, 0, // Skip to: 3226
/* 2670 */    MCD_OPC_Decode, 253, 13, 124, // Opcode: FNEG_S_MMR6
/* 2674 */    MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 2688
/* 2679 */    MCD_OPC_CheckPredicate, 26, 30, 2, 0, // Skip to: 3226
/* 2684 */    MCD_OPC_Decode, 212, 10, 124, // Opcode: CVT_S_W_MMR6
/* 2688 */    MCD_OPC_FilterValue, 10, 9, 0, 0, // Skip to: 2702
/* 2693 */    MCD_OPC_CheckPredicate, 23, 16, 2, 0, // Skip to: 3226
/* 2698 */    MCD_OPC_Decode, 192, 10, 122, // Opcode: CVT_D_L_MMR6
/* 2702 */    MCD_OPC_FilterValue, 11, 7, 2, 0, // Skip to: 3226
/* 2707 */    MCD_OPC_CheckPredicate, 23, 2, 2, 0, // Skip to: 3226
/* 2712 */    MCD_OPC_Decode, 207, 10, 121, // Opcode: CVT_S_L_MMR6
/* 2716 */    MCD_OPC_FilterValue, 133, 7, 10, 0, 0, // Skip to: 2732
/* 2722 */    MCD_OPC_CheckPredicate, 26, 243, 1, 0, // Skip to: 3226
/* 2727 */    MCD_OPC_Decode, 249, 9, 165, 1, // Opcode: CMP_SLE_S_MMR6
/* 2732 */    MCD_OPC_FilterValue, 149, 7, 10, 0, 0, // Skip to: 2748
/* 2738 */    MCD_OPC_CheckPredicate, 26, 227, 1, 0, // Skip to: 3226
/* 2743 */    MCD_OPC_Decode, 247, 9, 166, 1, // Opcode: CMP_SLE_D_MMR6
/* 2748 */    MCD_OPC_FilterValue, 184, 7, 10, 0, 0, // Skip to: 2764
/* 2754 */    MCD_OPC_CheckPredicate, 26, 211, 1, 0, // Skip to: 3226
/* 2759 */    MCD_OPC_Decode, 197, 16, 172, 1, // Opcode: MADDF_D_MMR6
/* 2764 */    MCD_OPC_FilterValue, 197, 7, 10, 0, 0, // Skip to: 2780
/* 2770 */    MCD_OPC_CheckPredicate, 26, 195, 1, 0, // Skip to: 3226
/* 2775 */    MCD_OPC_Decode, 133, 10, 165, 1, // Opcode: CMP_SULE_S_MMR6
/* 2780 */    MCD_OPC_FilterValue, 213, 7, 10, 0, 0, // Skip to: 2796
/* 2786 */    MCD_OPC_CheckPredicate, 26, 179, 1, 0, // Skip to: 3226
/* 2791 */    MCD_OPC_Decode, 131, 10, 166, 1, // Opcode: CMP_SULE_D_MMR6
/* 2796 */    MCD_OPC_FilterValue, 248, 7, 168, 1, 0, // Skip to: 3226
/* 2802 */    MCD_OPC_CheckPredicate, 26, 163, 1, 0, // Skip to: 3226
/* 2807 */    MCD_OPC_Decode, 133, 18, 172, 1, // Opcode: MSUBF_D_MMR6
/* 2812 */    MCD_OPC_FilterValue, 24, 61, 0, 0, // Skip to: 2878
/* 2817 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 2820 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 2834
/* 2825 */    MCD_OPC_CheckPredicate, 24, 140, 1, 0, // Skip to: 3226
/* 2830 */    MCD_OPC_Decode, 243, 19, 100, // Opcode: PREF_MMR6
/* 2834 */    MCD_OPC_FilterValue, 3, 17, 0, 0, // Skip to: 2856
/* 2839 */    MCD_OPC_CheckPredicate, 24, 126, 1, 0, // Skip to: 3226
/* 2844 */    MCD_OPC_CheckField, 9, 3, 0, 119, 1, 0, // Skip to: 3226
/* 2851 */    MCD_OPC_Decode, 244, 15, 134, 1, // Opcode: LL_MMR6
/* 2856 */    MCD_OPC_FilterValue, 11, 109, 1, 0, // Skip to: 3226
/* 2861 */    MCD_OPC_CheckPredicate, 24, 104, 1, 0, // Skip to: 3226
/* 2866 */    MCD_OPC_CheckField, 9, 3, 0, 97, 1, 0, // Skip to: 3226
/* 2873 */    MCD_OPC_Decode, 215, 20, 134, 1, // Opcode: SC_MMR6
/* 2878 */    MCD_OPC_FilterValue, 28, 9, 0, 0, // Skip to: 2892
/* 2883 */    MCD_OPC_CheckPredicate, 24, 82, 1, 0, // Skip to: 3226
/* 2888 */    MCD_OPC_Decode, 178, 24, 108, // Opcode: XORI_MMR6
/* 2892 */    MCD_OPC_FilterValue, 29, 27, 0, 0, // Skip to: 2924
/* 2897 */    MCD_OPC_CheckPredicate, 24, 12, 0, 0, // Skip to: 2914
/* 2902 */    MCD_OPC_CheckField, 16, 5, 0, 5, 0, 0, // Skip to: 2914
/* 2909 */    MCD_OPC_Decode, 200, 7, 173, 1, // Opcode: BEQZALC_MMR6
/* 2914 */    MCD_OPC_CheckPredicate, 24, 51, 1, 0, // Skip to: 3226
/* 2919 */    MCD_OPC_Decode, 193, 7, 173, 1, // Opcode: BEQC_MMR6
/* 2924 */    MCD_OPC_FilterValue, 30, 71, 0, 0, // Skip to: 3000
/* 2929 */    MCD_OPC_ExtractField, 19, 2,  // Inst{20-19} ...
/* 2932 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 2947
/* 2937 */    MCD_OPC_CheckPredicate, 24, 28, 1, 0, // Skip to: 3226
/* 2942 */    MCD_OPC_Decode, 131, 6, 174, 1, // Opcode: ADDIUPC_MMR6
/* 2947 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 2962
/* 2952 */    MCD_OPC_CheckPredicate, 24, 13, 1, 0, // Skip to: 3226
/* 2957 */    MCD_OPC_Decode, 159, 16, 174, 1, // Opcode: LWPC_MMR6
/* 2962 */    MCD_OPC_FilterValue, 3, 3, 1, 0, // Skip to: 3226
/* 2967 */    MCD_OPC_ExtractField, 16, 3,  // Inst{18-16} ...
/* 2970 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 2985
/* 2975 */    MCD_OPC_CheckPredicate, 24, 246, 0, 0, // Skip to: 3226
/* 2980 */    MCD_OPC_Decode, 246, 6, 175, 1, // Opcode: AUIPC_MMR6
/* 2985 */    MCD_OPC_FilterValue, 7, 236, 0, 0, // Skip to: 3226
/* 2990 */    MCD_OPC_CheckPredicate, 24, 231, 0, 0, // Skip to: 3226
/* 2995 */    MCD_OPC_Decode, 214, 6, 175, 1, // Opcode: ALUIPC_MMR6
/* 3000 */    MCD_OPC_FilterValue, 31, 27, 0, 0, // Skip to: 3032
/* 3005 */    MCD_OPC_CheckPredicate, 24, 12, 0, 0, // Skip to: 3022
/* 3010 */    MCD_OPC_CheckField, 16, 5, 0, 5, 0, 0, // Skip to: 3022
/* 3017 */    MCD_OPC_Decode, 190, 8, 176, 1, // Opcode: BNEZALC_MMR6
/* 3022 */    MCD_OPC_CheckPredicate, 24, 199, 0, 0, // Skip to: 3226
/* 3027 */    MCD_OPC_Decode, 175, 8, 176, 1, // Opcode: BNEC_MMR6
/* 3032 */    MCD_OPC_FilterValue, 32, 26, 0, 0, // Skip to: 3063
/* 3037 */    MCD_OPC_CheckPredicate, 24, 11, 0, 0, // Skip to: 3053
/* 3042 */    MCD_OPC_CheckField, 21, 5, 0, 4, 0, 0, // Skip to: 3053
/* 3049 */    MCD_OPC_Decode, 128, 15, 103, // Opcode: JIALC_MMR6
/* 3053 */    MCD_OPC_CheckPredicate, 24, 168, 0, 0, // Skip to: 3226
/* 3058 */    MCD_OPC_Decode, 206, 7, 177, 1, // Opcode: BEQZC_MMR6
/* 3063 */    MCD_OPC_FilterValue, 37, 10, 0, 0, // Skip to: 3078
/* 3068 */    MCD_OPC_CheckPredicate, 24, 153, 0, 0, // Skip to: 3226
/* 3073 */    MCD_OPC_Decode, 186, 7, 178, 1, // Opcode: BC_MMR6
/* 3078 */    MCD_OPC_FilterValue, 40, 26, 0, 0, // Skip to: 3109
/* 3083 */    MCD_OPC_CheckPredicate, 24, 11, 0, 0, // Skip to: 3099
/* 3088 */    MCD_OPC_CheckField, 21, 5, 0, 4, 0, 0, // Skip to: 3099
/* 3095 */    MCD_OPC_Decode, 131, 15, 103, // Opcode: JIC_MMR6
/* 3099 */    MCD_OPC_CheckPredicate, 24, 122, 0, 0, // Skip to: 3226
/* 3104 */    MCD_OPC_Decode, 196, 8, 177, 1, // Opcode: BNEZC_MMR6
/* 3109 */    MCD_OPC_FilterValue, 45, 10, 0, 0, // Skip to: 3124
/* 3114 */    MCD_OPC_CheckPredicate, 24, 107, 0, 0, // Skip to: 3226
/* 3119 */    MCD_OPC_Decode, 150, 7, 178, 1, // Opcode: BALC_MMR6
/* 3124 */    MCD_OPC_FilterValue, 48, 10, 0, 0, // Skip to: 3139
/* 3129 */    MCD_OPC_CheckPredicate, 24, 92, 0, 0, // Skip to: 3226
/* 3134 */    MCD_OPC_Decode, 217, 7, 179, 1, // Opcode: BGEUC_MMR6
/* 3139 */    MCD_OPC_FilterValue, 52, 9, 0, 0, // Skip to: 3153
/* 3144 */    MCD_OPC_CheckPredicate, 24, 77, 0, 0, // Skip to: 3226
/* 3149 */    MCD_OPC_Decode, 225, 6, 108, // Opcode: ANDI_MMR6
/* 3153 */    MCD_OPC_FilterValue, 53, 10, 0, 0, // Skip to: 3168
/* 3158 */    MCD_OPC_CheckPredicate, 24, 63, 0, 0, // Skip to: 3226
/* 3163 */    MCD_OPC_Decode, 145, 8, 180, 1, // Opcode: BLTC_MMR6
/* 3168 */    MCD_OPC_FilterValue, 56, 10, 0, 0, // Skip to: 3183
/* 3173 */    MCD_OPC_CheckPredicate, 24, 48, 0, 0, // Skip to: 3226
/* 3178 */    MCD_OPC_Decode, 151, 8, 181, 1, // Opcode: BLTUC_MMR6
/* 3183 */    MCD_OPC_FilterValue, 61, 10, 0, 0, // Skip to: 3198
/* 3188 */    MCD_OPC_CheckPredicate, 24, 33, 0, 0, // Skip to: 3226
/* 3193 */    MCD_OPC_Decode, 211, 7, 182, 1, // Opcode: BGEC_MMR6
/* 3198 */    MCD_OPC_FilterValue, 62, 9, 0, 0, // Skip to: 3212
/* 3203 */    MCD_OPC_CheckPredicate, 24, 18, 0, 0, // Skip to: 3226
/* 3208 */    MCD_OPC_Decode, 170, 23, 98, // Opcode: SW_MMR6
/* 3212 */    MCD_OPC_FilterValue, 63, 9, 0, 0, // Skip to: 3226
/* 3217 */    MCD_OPC_CheckPredicate, 24, 4, 0, 0, // Skip to: 3226
/* 3222 */    MCD_OPC_Decode, 180, 16, 98, // Opcode: LW_MMR6
/* 3226 */    MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMicroMipsR6_Ambiguous32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 18
/* 8 */       MCD_OPC_CheckPredicate, 24, 84, 0, 0, // Skip to: 97
/* 13 */      MCD_OPC_Decode, 207, 8, 173, 1, // Opcode: BOVC_MMR6
/* 18 */      MCD_OPC_FilterValue, 31, 10, 0, 0, // Skip to: 33
/* 23 */      MCD_OPC_CheckPredicate, 24, 69, 0, 0, // Skip to: 97
/* 28 */      MCD_OPC_Decode, 200, 8, 176, 1, // Opcode: BNVC_MMR6
/* 33 */      MCD_OPC_FilterValue, 48, 27, 0, 0, // Skip to: 65
/* 38 */      MCD_OPC_CheckPredicate, 24, 12, 0, 0, // Skip to: 55
/* 43 */      MCD_OPC_CheckField, 16, 5, 0, 5, 0, 0, // Skip to: 55
/* 50 */      MCD_OPC_Decode, 137, 8, 179, 1, // Opcode: BLEZALC_MMR6
/* 55 */      MCD_OPC_CheckPredicate, 24, 37, 0, 0, // Skip to: 97
/* 60 */      MCD_OPC_Decode, 223, 7, 179, 1, // Opcode: BGEZALC_MMR6
/* 65 */      MCD_OPC_FilterValue, 56, 27, 0, 0, // Skip to: 97
/* 70 */      MCD_OPC_CheckPredicate, 24, 12, 0, 0, // Skip to: 87
/* 75 */      MCD_OPC_CheckField, 16, 5, 0, 5, 0, 0, // Skip to: 87
/* 82 */      MCD_OPC_Decode, 235, 7, 181, 1, // Opcode: BGTZALC_MMR6
/* 87 */      MCD_OPC_CheckPredicate, 24, 5, 0, 0, // Skip to: 97
/* 92 */      MCD_OPC_Decode, 157, 8, 181, 1, // Opcode: BLTZALC_MMR6
/* 97 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMips32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 101, 4, 0, // Skip to: 1133
/* 8 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 11 */      MCD_OPC_FilterValue, 0, 63, 0, 0, // Skip to: 79
/* 16 */      MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 19 */      MCD_OPC_FilterValue, 0, 178, 66, 0, // Skip to: 17098
/* 24 */      MCD_OPC_ExtractField, 6, 15,  // Inst{20-6} ...
/* 27 */      MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 41
/* 32 */      MCD_OPC_CheckPredicate, 27, 32, 0, 0, // Skip to: 69
/* 37 */      MCD_OPC_Decode, 185, 22, 10, // Opcode: SSNOP
/* 41 */      MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 55
/* 46 */      MCD_OPC_CheckPredicate, 27, 18, 0, 0, // Skip to: 69
/* 51 */      MCD_OPC_Decode, 206, 12, 10, // Opcode: EHB
/* 55 */      MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 69
/* 60 */      MCD_OPC_CheckPredicate, 28, 4, 0, 0, // Skip to: 69
/* 65 */      MCD_OPC_Decode, 181, 19, 10, // Opcode: PAUSE
/* 69 */      MCD_OPC_CheckPredicate, 27, 128, 66, 0, // Skip to: 17098
/* 74 */      MCD_OPC_Decode, 219, 21, 183, 1, // Opcode: SLL
/* 79 */      MCD_OPC_FilterValue, 1, 47, 0, 0, // Skip to: 131
/* 84 */      MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 87 */      MCD_OPC_FilterValue, 0, 17, 0, 0, // Skip to: 109
/* 92 */      MCD_OPC_CheckPredicate, 29, 105, 66, 0, // Skip to: 17098
/* 97 */      MCD_OPC_CheckField, 6, 5, 0, 98, 66, 0, // Skip to: 17098
/* 104 */     MCD_OPC_Decode, 220, 17, 184, 1, // Opcode: MOVF_I
/* 109 */     MCD_OPC_FilterValue, 1, 88, 66, 0, // Skip to: 17098
/* 114 */     MCD_OPC_CheckPredicate, 29, 83, 66, 0, // Skip to: 17098
/* 119 */     MCD_OPC_CheckField, 6, 5, 0, 76, 66, 0, // Skip to: 17098
/* 126 */     MCD_OPC_Decode, 241, 17, 184, 1, // Opcode: MOVT_I
/* 131 */     MCD_OPC_FilterValue, 2, 33, 0, 0, // Skip to: 169
/* 136 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 139 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 154
/* 144 */     MCD_OPC_CheckPredicate, 27, 53, 66, 0, // Skip to: 17098
/* 149 */     MCD_OPC_Decode, 160, 22, 183, 1, // Opcode: SRL
/* 154 */     MCD_OPC_FilterValue, 1, 43, 66, 0, // Skip to: 17098
/* 159 */     MCD_OPC_CheckPredicate, 28, 38, 66, 0, // Skip to: 17098
/* 164 */     MCD_OPC_Decode, 155, 20, 183, 1, // Opcode: ROTR
/* 169 */     MCD_OPC_FilterValue, 3, 17, 0, 0, // Skip to: 191
/* 174 */     MCD_OPC_CheckPredicate, 27, 23, 66, 0, // Skip to: 17098
/* 179 */     MCD_OPC_CheckField, 21, 5, 0, 16, 66, 0, // Skip to: 17098
/* 186 */     MCD_OPC_Decode, 138, 22, 183, 1, // Opcode: SRA
/* 191 */     MCD_OPC_FilterValue, 4, 16, 0, 0, // Skip to: 212
/* 196 */     MCD_OPC_CheckPredicate, 27, 1, 66, 0, // Skip to: 17098
/* 201 */     MCD_OPC_CheckField, 6, 5, 0, 250, 65, 0, // Skip to: 17098
/* 208 */     MCD_OPC_Decode, 229, 21, 55, // Opcode: SLLV
/* 212 */     MCD_OPC_FilterValue, 5, 17, 0, 0, // Skip to: 234
/* 217 */     MCD_OPC_CheckPredicate, 30, 236, 65, 0, // Skip to: 17098
/* 222 */     MCD_OPC_CheckField, 8, 3, 0, 229, 65, 0, // Skip to: 17098
/* 229 */     MCD_OPC_Decode, 247, 15, 185, 1, // Opcode: LSA
/* 234 */     MCD_OPC_FilterValue, 6, 31, 0, 0, // Skip to: 270
/* 239 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 242 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 256
/* 247 */     MCD_OPC_CheckPredicate, 27, 206, 65, 0, // Skip to: 17098
/* 252 */     MCD_OPC_Decode, 176, 22, 55, // Opcode: SRLV
/* 256 */     MCD_OPC_FilterValue, 1, 197, 65, 0, // Skip to: 17098
/* 261 */     MCD_OPC_CheckPredicate, 28, 192, 65, 0, // Skip to: 17098
/* 266 */     MCD_OPC_Decode, 156, 20, 55, // Opcode: ROTRV
/* 270 */     MCD_OPC_FilterValue, 7, 16, 0, 0, // Skip to: 291
/* 275 */     MCD_OPC_CheckPredicate, 27, 178, 65, 0, // Skip to: 17098
/* 280 */     MCD_OPC_CheckField, 6, 5, 0, 171, 65, 0, // Skip to: 17098
/* 287 */     MCD_OPC_Decode, 151, 22, 55, // Opcode: SRAV
/* 291 */     MCD_OPC_FilterValue, 8, 33, 0, 0, // Skip to: 329
/* 296 */     MCD_OPC_ExtractField, 6, 15,  // Inst{20-6} ...
/* 299 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 314
/* 304 */     MCD_OPC_CheckPredicate, 31, 149, 65, 0, // Skip to: 17098
/* 309 */     MCD_OPC_Decode, 132, 15, 186, 1, // Opcode: JR
/* 314 */     MCD_OPC_FilterValue, 16, 139, 65, 0, // Skip to: 17098
/* 319 */     MCD_OPC_CheckPredicate, 32, 134, 65, 0, // Skip to: 17098
/* 324 */     MCD_OPC_Decode, 140, 15, 186, 1, // Opcode: JR_HB
/* 329 */     MCD_OPC_FilterValue, 9, 45, 0, 0, // Skip to: 379
/* 334 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 337 */     MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 358
/* 342 */     MCD_OPC_CheckPredicate, 33, 111, 65, 0, // Skip to: 17098
/* 347 */     MCD_OPC_CheckField, 16, 5, 0, 104, 65, 0, // Skip to: 17098
/* 354 */     MCD_OPC_Decode, 236, 14, 25, // Opcode: JALR
/* 358 */     MCD_OPC_FilterValue, 16, 95, 65, 0, // Skip to: 17098
/* 363 */     MCD_OPC_CheckPredicate, 34, 90, 65, 0, // Skip to: 17098
/* 368 */     MCD_OPC_CheckField, 16, 5, 0, 83, 65, 0, // Skip to: 17098
/* 375 */     MCD_OPC_Decode, 247, 14, 25, // Opcode: JALR_HB
/* 379 */     MCD_OPC_FilterValue, 10, 17, 0, 0, // Skip to: 401
/* 384 */     MCD_OPC_CheckPredicate, 35, 69, 65, 0, // Skip to: 17098
/* 389 */     MCD_OPC_CheckField, 6, 5, 0, 62, 65, 0, // Skip to: 17098
/* 396 */     MCD_OPC_Decode, 253, 17, 187, 1, // Opcode: MOVZ_I_I
/* 401 */     MCD_OPC_FilterValue, 11, 17, 0, 0, // Skip to: 423
/* 406 */     MCD_OPC_CheckPredicate, 35, 47, 65, 0, // Skip to: 17098
/* 411 */     MCD_OPC_CheckField, 6, 5, 0, 40, 65, 0, // Skip to: 17098
/* 418 */     MCD_OPC_Decode, 232, 17, 187, 1, // Opcode: MOVN_I_I
/* 423 */     MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 438
/* 428 */     MCD_OPC_CheckPredicate, 27, 25, 65, 0, // Skip to: 17098
/* 433 */     MCD_OPC_Decode, 182, 23, 188, 1, // Opcode: SYSCALL
/* 438 */     MCD_OPC_FilterValue, 13, 9, 0, 0, // Skip to: 452
/* 443 */     MCD_OPC_CheckPredicate, 27, 10, 65, 0, // Skip to: 17098
/* 448 */     MCD_OPC_Decode, 211, 8, 56, // Opcode: BREAK
/* 452 */     MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 467
/* 457 */     MCD_OPC_CheckPredicate, 36, 252, 64, 0, // Skip to: 17098
/* 462 */     MCD_OPC_Decode, 173, 23, 189, 1, // Opcode: SYNC
/* 467 */     MCD_OPC_FilterValue, 16, 51, 0, 0, // Skip to: 523
/* 472 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 475 */     MCD_OPC_FilterValue, 0, 234, 64, 0, // Skip to: 17098
/* 480 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 483 */     MCD_OPC_FilterValue, 0, 226, 64, 0, // Skip to: 17098
/* 488 */     MCD_OPC_ExtractField, 23, 3,  // Inst{25-23} ...
/* 491 */     MCD_OPC_FilterValue, 0, 218, 64, 0, // Skip to: 17098
/* 496 */     MCD_OPC_CheckPredicate, 31, 12, 0, 0, // Skip to: 513
/* 501 */     MCD_OPC_CheckField, 21, 2, 0, 5, 0, 0, // Skip to: 513
/* 508 */     MCD_OPC_Decode, 150, 17, 190, 1, // Opcode: MFHI
/* 513 */     MCD_OPC_CheckPredicate, 37, 196, 64, 0, // Skip to: 17098
/* 518 */     MCD_OPC_Decode, 153, 17, 191, 1, // Opcode: MFHI_DSP
/* 523 */     MCD_OPC_FilterValue, 17, 43, 0, 0, // Skip to: 571
/* 528 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 531 */     MCD_OPC_FilterValue, 0, 178, 64, 0, // Skip to: 17098
/* 536 */     MCD_OPC_ExtractField, 13, 8,  // Inst{20-13} ...
/* 539 */     MCD_OPC_FilterValue, 0, 170, 64, 0, // Skip to: 17098
/* 544 */     MCD_OPC_CheckPredicate, 31, 12, 0, 0, // Skip to: 561
/* 549 */     MCD_OPC_CheckField, 11, 2, 0, 5, 0, 0, // Skip to: 561
/* 556 */     MCD_OPC_Decode, 179, 18, 186, 1, // Opcode: MTHI
/* 561 */     MCD_OPC_CheckPredicate, 37, 148, 64, 0, // Skip to: 17098
/* 566 */     MCD_OPC_Decode, 181, 18, 192, 1, // Opcode: MTHI_DSP
/* 571 */     MCD_OPC_FilterValue, 18, 51, 0, 0, // Skip to: 627
/* 576 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 579 */     MCD_OPC_FilterValue, 0, 130, 64, 0, // Skip to: 17098
/* 584 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 587 */     MCD_OPC_FilterValue, 0, 122, 64, 0, // Skip to: 17098
/* 592 */     MCD_OPC_ExtractField, 23, 3,  // Inst{25-23} ...
/* 595 */     MCD_OPC_FilterValue, 0, 114, 64, 0, // Skip to: 17098
/* 600 */     MCD_OPC_CheckPredicate, 31, 12, 0, 0, // Skip to: 617
/* 605 */     MCD_OPC_CheckField, 21, 2, 0, 5, 0, 0, // Skip to: 617
/* 612 */     MCD_OPC_Decode, 156, 17, 190, 1, // Opcode: MFLO
/* 617 */     MCD_OPC_CheckPredicate, 37, 92, 64, 0, // Skip to: 17098
/* 622 */     MCD_OPC_Decode, 159, 17, 191, 1, // Opcode: MFLO_DSP
/* 627 */     MCD_OPC_FilterValue, 19, 43, 0, 0, // Skip to: 675
/* 632 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 635 */     MCD_OPC_FilterValue, 0, 74, 64, 0, // Skip to: 17098
/* 640 */     MCD_OPC_ExtractField, 13, 8,  // Inst{20-13} ...
/* 643 */     MCD_OPC_FilterValue, 0, 66, 64, 0, // Skip to: 17098
/* 648 */     MCD_OPC_CheckPredicate, 31, 12, 0, 0, // Skip to: 665
/* 653 */     MCD_OPC_CheckField, 11, 2, 0, 5, 0, 0, // Skip to: 665
/* 660 */     MCD_OPC_Decode, 186, 18, 186, 1, // Opcode: MTLO
/* 665 */     MCD_OPC_CheckPredicate, 37, 44, 64, 0, // Skip to: 17098
/* 670 */     MCD_OPC_Decode, 188, 18, 193, 1, // Opcode: MTLO_DSP
/* 675 */     MCD_OPC_FilterValue, 21, 17, 0, 0, // Skip to: 697
/* 680 */     MCD_OPC_CheckPredicate, 38, 29, 64, 0, // Skip to: 17098
/* 685 */     MCD_OPC_CheckField, 8, 3, 0, 22, 64, 0, // Skip to: 17098
/* 692 */     MCD_OPC_Decode, 235, 11, 194, 1, // Opcode: DLSA
/* 697 */     MCD_OPC_FilterValue, 24, 42, 0, 0, // Skip to: 744
/* 702 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 705 */     MCD_OPC_FilterValue, 0, 4, 64, 0, // Skip to: 17098
/* 710 */     MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 713 */     MCD_OPC_FilterValue, 0, 252, 63, 0, // Skip to: 17098
/* 718 */     MCD_OPC_CheckPredicate, 31, 11, 0, 0, // Skip to: 734
/* 723 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 734
/* 730 */     MCD_OPC_Decode, 230, 18, 80, // Opcode: MULT
/* 734 */     MCD_OPC_CheckPredicate, 37, 231, 63, 0, // Skip to: 17098
/* 739 */     MCD_OPC_Decode, 233, 18, 195, 1, // Opcode: MULT_DSP
/* 744 */     MCD_OPC_FilterValue, 25, 42, 0, 0, // Skip to: 791
/* 749 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 752 */     MCD_OPC_FilterValue, 0, 213, 63, 0, // Skip to: 17098
/* 757 */     MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 760 */     MCD_OPC_FilterValue, 0, 205, 63, 0, // Skip to: 17098
/* 765 */     MCD_OPC_CheckPredicate, 31, 11, 0, 0, // Skip to: 781
/* 770 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 781
/* 777 */     MCD_OPC_Decode, 236, 18, 80, // Opcode: MULTu
/* 781 */     MCD_OPC_CheckPredicate, 37, 184, 63, 0, // Skip to: 17098
/* 786 */     MCD_OPC_Decode, 231, 18, 195, 1, // Opcode: MULTU_DSP
/* 791 */     MCD_OPC_FilterValue, 26, 16, 0, 0, // Skip to: 812
/* 796 */     MCD_OPC_CheckPredicate, 31, 169, 63, 0, // Skip to: 17098
/* 801 */     MCD_OPC_CheckField, 6, 10, 0, 162, 63, 0, // Skip to: 17098
/* 808 */     MCD_OPC_Decode, 236, 20, 80, // Opcode: SDIV
/* 812 */     MCD_OPC_FilterValue, 27, 16, 0, 0, // Skip to: 833
/* 817 */     MCD_OPC_CheckPredicate, 31, 148, 63, 0, // Skip to: 17098
/* 822 */     MCD_OPC_CheckField, 6, 10, 0, 141, 63, 0, // Skip to: 17098
/* 829 */     MCD_OPC_Decode, 152, 24, 80, // Opcode: UDIV
/* 833 */     MCD_OPC_FilterValue, 32, 16, 0, 0, // Skip to: 854
/* 838 */     MCD_OPC_CheckPredicate, 27, 127, 63, 0, // Skip to: 17098
/* 843 */     MCD_OPC_CheckField, 6, 5, 0, 120, 63, 0, // Skip to: 17098
/* 850 */     MCD_OPC_Decode, 251, 5, 61, // Opcode: ADD
/* 854 */     MCD_OPC_FilterValue, 33, 16, 0, 0, // Skip to: 875
/* 859 */     MCD_OPC_CheckPredicate, 27, 106, 63, 0, // Skip to: 17098
/* 864 */     MCD_OPC_CheckField, 6, 5, 0, 99, 63, 0, // Skip to: 17098
/* 871 */     MCD_OPC_Decode, 206, 6, 61, // Opcode: ADDu
/* 875 */     MCD_OPC_FilterValue, 34, 16, 0, 0, // Skip to: 896
/* 880 */     MCD_OPC_CheckPredicate, 27, 85, 63, 0, // Skip to: 17098
/* 885 */     MCD_OPC_CheckField, 6, 5, 0, 78, 63, 0, // Skip to: 17098
/* 892 */     MCD_OPC_Decode, 192, 22, 61, // Opcode: SUB
/* 896 */     MCD_OPC_FilterValue, 35, 16, 0, 0, // Skip to: 917
/* 901 */     MCD_OPC_CheckPredicate, 27, 64, 63, 0, // Skip to: 17098
/* 906 */     MCD_OPC_CheckField, 6, 5, 0, 57, 63, 0, // Skip to: 17098
/* 913 */     MCD_OPC_Decode, 249, 22, 61, // Opcode: SUBu
/* 917 */     MCD_OPC_FilterValue, 36, 16, 0, 0, // Skip to: 938
/* 922 */     MCD_OPC_CheckPredicate, 27, 43, 63, 0, // Skip to: 17098
/* 927 */     MCD_OPC_CheckField, 6, 5, 0, 36, 63, 0, // Skip to: 17098
/* 934 */     MCD_OPC_Decode, 216, 6, 61, // Opcode: AND
/* 938 */     MCD_OPC_FilterValue, 37, 16, 0, 0, // Skip to: 959
/* 943 */     MCD_OPC_CheckPredicate, 27, 22, 63, 0, // Skip to: 17098
/* 948 */     MCD_OPC_CheckField, 6, 5, 0, 15, 63, 0, // Skip to: 17098
/* 955 */     MCD_OPC_Decode, 163, 19, 61, // Opcode: OR
/* 959 */     MCD_OPC_FilterValue, 38, 16, 0, 0, // Skip to: 980
/* 964 */     MCD_OPC_CheckPredicate, 27, 1, 63, 0, // Skip to: 17098
/* 969 */     MCD_OPC_CheckField, 6, 5, 0, 250, 62, 0, // Skip to: 17098
/* 976 */     MCD_OPC_Decode, 172, 24, 61, // Opcode: XOR
/* 980 */     MCD_OPC_FilterValue, 39, 16, 0, 0, // Skip to: 1001
/* 985 */     MCD_OPC_CheckPredicate, 27, 236, 62, 0, // Skip to: 17098
/* 990 */     MCD_OPC_CheckField, 6, 5, 0, 229, 62, 0, // Skip to: 17098
/* 997 */     MCD_OPC_Decode, 151, 19, 61, // Opcode: NOR
/* 1001 */    MCD_OPC_FilterValue, 42, 16, 0, 0, // Skip to: 1022
/* 1006 */    MCD_OPC_CheckPredicate, 27, 215, 62, 0, // Skip to: 17098
/* 1011 */    MCD_OPC_CheckField, 6, 5, 0, 208, 62, 0, // Skip to: 17098
/* 1018 */    MCD_OPC_Decode, 239, 21, 61, // Opcode: SLT
/* 1022 */    MCD_OPC_FilterValue, 43, 16, 0, 0, // Skip to: 1043
/* 1027 */    MCD_OPC_CheckPredicate, 27, 194, 62, 0, // Skip to: 17098
/* 1032 */    MCD_OPC_CheckField, 6, 5, 0, 187, 62, 0, // Skip to: 17098
/* 1039 */    MCD_OPC_Decode, 252, 21, 61, // Opcode: SLTu
/* 1043 */    MCD_OPC_FilterValue, 48, 10, 0, 0, // Skip to: 1058
/* 1048 */    MCD_OPC_CheckPredicate, 36, 173, 62, 0, // Skip to: 17098
/* 1053 */    MCD_OPC_Decode, 212, 23, 196, 1, // Opcode: TGE
/* 1058 */    MCD_OPC_FilterValue, 49, 10, 0, 0, // Skip to: 1073
/* 1063 */    MCD_OPC_CheckPredicate, 36, 158, 62, 0, // Skip to: 17098
/* 1068 */    MCD_OPC_Decode, 217, 23, 196, 1, // Opcode: TGEU
/* 1073 */    MCD_OPC_FilterValue, 50, 10, 0, 0, // Skip to: 1088
/* 1078 */    MCD_OPC_CheckPredicate, 36, 143, 62, 0, // Skip to: 17098
/* 1083 */    MCD_OPC_Decode, 250, 23, 196, 1, // Opcode: TLT
/* 1088 */    MCD_OPC_FilterValue, 51, 10, 0, 0, // Skip to: 1103
/* 1093 */    MCD_OPC_CheckPredicate, 36, 128, 62, 0, // Skip to: 17098
/* 1098 */    MCD_OPC_Decode, 254, 23, 196, 1, // Opcode: TLTU
/* 1103 */    MCD_OPC_FilterValue, 52, 10, 0, 0, // Skip to: 1118
/* 1108 */    MCD_OPC_CheckPredicate, 36, 113, 62, 0, // Skip to: 17098
/* 1113 */    MCD_OPC_Decode, 207, 23, 196, 1, // Opcode: TEQ
/* 1118 */    MCD_OPC_FilterValue, 54, 103, 62, 0, // Skip to: 17098
/* 1123 */    MCD_OPC_CheckPredicate, 36, 98, 62, 0, // Skip to: 17098
/* 1128 */    MCD_OPC_Decode, 129, 24, 196, 1, // Opcode: TNE
/* 1133 */    MCD_OPC_FilterValue, 1, 250, 0, 0, // Skip to: 1388
/* 1138 */    MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 1141 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 1156
/* 1146 */    MCD_OPC_CheckPredicate, 27, 75, 62, 0, // Skip to: 17098
/* 1151 */    MCD_OPC_Decode, 153, 8, 197, 1, // Opcode: BLTZ
/* 1156 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 1171
/* 1161 */    MCD_OPC_CheckPredicate, 27, 60, 62, 0, // Skip to: 17098
/* 1166 */    MCD_OPC_Decode, 219, 7, 197, 1, // Opcode: BGEZ
/* 1171 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 1186
/* 1176 */    MCD_OPC_CheckPredicate, 39, 45, 62, 0, // Skip to: 17098
/* 1181 */    MCD_OPC_Decode, 164, 8, 197, 1, // Opcode: BLTZL
/* 1186 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 1201
/* 1191 */    MCD_OPC_CheckPredicate, 39, 30, 62, 0, // Skip to: 17098
/* 1196 */    MCD_OPC_Decode, 230, 7, 197, 1, // Opcode: BGEZL
/* 1201 */    MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 1216
/* 1206 */    MCD_OPC_CheckPredicate, 39, 15, 62, 0, // Skip to: 17098
/* 1211 */    MCD_OPC_Decode, 213, 23, 175, 1, // Opcode: TGEI
/* 1216 */    MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 1231
/* 1221 */    MCD_OPC_CheckPredicate, 39, 0, 62, 0, // Skip to: 17098
/* 1226 */    MCD_OPC_Decode, 214, 23, 175, 1, // Opcode: TGEIU
/* 1231 */    MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 1246
/* 1236 */    MCD_OPC_CheckPredicate, 39, 241, 61, 0, // Skip to: 17098
/* 1241 */    MCD_OPC_Decode, 251, 23, 175, 1, // Opcode: TLTI
/* 1246 */    MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 1261
/* 1251 */    MCD_OPC_CheckPredicate, 39, 226, 61, 0, // Skip to: 17098
/* 1256 */    MCD_OPC_Decode, 145, 24, 175, 1, // Opcode: TTLTIU
/* 1261 */    MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 1276
/* 1266 */    MCD_OPC_CheckPredicate, 39, 211, 61, 0, // Skip to: 17098
/* 1271 */    MCD_OPC_Decode, 208, 23, 175, 1, // Opcode: TEQI
/* 1276 */    MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 1291
/* 1281 */    MCD_OPC_CheckPredicate, 39, 196, 61, 0, // Skip to: 17098
/* 1286 */    MCD_OPC_Decode, 130, 24, 175, 1, // Opcode: TNEI
/* 1291 */    MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 1306
/* 1296 */    MCD_OPC_CheckPredicate, 31, 181, 61, 0, // Skip to: 17098
/* 1301 */    MCD_OPC_Decode, 155, 8, 197, 1, // Opcode: BLTZAL
/* 1306 */    MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 1321
/* 1311 */    MCD_OPC_CheckPredicate, 31, 166, 61, 0, // Skip to: 17098
/* 1316 */    MCD_OPC_Decode, 221, 7, 197, 1, // Opcode: BGEZAL
/* 1321 */    MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 1336
/* 1326 */    MCD_OPC_CheckPredicate, 39, 151, 61, 0, // Skip to: 17098
/* 1331 */    MCD_OPC_Decode, 158, 8, 197, 1, // Opcode: BLTZALL
/* 1336 */    MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 1351
/* 1341 */    MCD_OPC_CheckPredicate, 39, 136, 61, 0, // Skip to: 17098
/* 1346 */    MCD_OPC_Decode, 224, 7, 197, 1, // Opcode: BGEZALL
/* 1351 */    MCD_OPC_FilterValue, 28, 17, 0, 0, // Skip to: 1373
/* 1356 */    MCD_OPC_CheckPredicate, 40, 121, 61, 0, // Skip to: 17098
/* 1361 */    MCD_OPC_CheckField, 21, 5, 0, 114, 61, 0, // Skip to: 17098
/* 1368 */    MCD_OPC_Decode, 208, 8, 198, 1, // Opcode: BPOSGE32
/* 1373 */    MCD_OPC_FilterValue, 31, 104, 61, 0, // Skip to: 17098
/* 1378 */    MCD_OPC_CheckPredicate, 28, 99, 61, 0, // Skip to: 17098
/* 1383 */    MCD_OPC_Decode, 174, 23, 199, 1, // Opcode: SYNCI
/* 1388 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 1403
/* 1393 */    MCD_OPC_CheckPredicate, 27, 84, 61, 0, // Skip to: 17098
/* 1398 */    MCD_OPC_Decode, 234, 14, 200, 1, // Opcode: J
/* 1403 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 1418
/* 1408 */    MCD_OPC_CheckPredicate, 27, 69, 61, 0, // Skip to: 17098
/* 1413 */    MCD_OPC_Decode, 235, 14, 200, 1, // Opcode: JAL
/* 1418 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 1433
/* 1423 */    MCD_OPC_CheckPredicate, 27, 54, 61, 0, // Skip to: 17098
/* 1428 */    MCD_OPC_Decode, 188, 7, 201, 1, // Opcode: BEQ
/* 1433 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 1448
/* 1438 */    MCD_OPC_CheckPredicate, 27, 39, 61, 0, // Skip to: 17098
/* 1443 */    MCD_OPC_Decode, 170, 8, 201, 1, // Opcode: BNE
/* 1448 */    MCD_OPC_FilterValue, 6, 17, 0, 0, // Skip to: 1470
/* 1453 */    MCD_OPC_CheckPredicate, 27, 24, 61, 0, // Skip to: 17098
/* 1458 */    MCD_OPC_CheckField, 16, 5, 0, 17, 61, 0, // Skip to: 17098
/* 1465 */    MCD_OPC_Decode, 134, 8, 197, 1, // Opcode: BLEZ
/* 1470 */    MCD_OPC_FilterValue, 7, 17, 0, 0, // Skip to: 1492
/* 1475 */    MCD_OPC_CheckPredicate, 27, 2, 61, 0, // Skip to: 17098
/* 1480 */    MCD_OPC_CheckField, 16, 5, 0, 251, 60, 0, // Skip to: 17098
/* 1487 */    MCD_OPC_Decode, 232, 7, 197, 1, // Opcode: BGTZ
/* 1492 */    MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 1507
/* 1497 */    MCD_OPC_CheckPredicate, 31, 236, 60, 0, // Skip to: 17098
/* 1502 */    MCD_OPC_Decode, 202, 6, 202, 1, // Opcode: ADDi
/* 1507 */    MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 1522
/* 1512 */    MCD_OPC_CheckPredicate, 27, 221, 60, 0, // Skip to: 17098
/* 1517 */    MCD_OPC_Decode, 204, 6, 202, 1, // Opcode: ADDiu
/* 1522 */    MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 1537
/* 1527 */    MCD_OPC_CheckPredicate, 27, 206, 60, 0, // Skip to: 17098
/* 1532 */    MCD_OPC_Decode, 246, 21, 202, 1, // Opcode: SLTi
/* 1537 */    MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 1552
/* 1542 */    MCD_OPC_CheckPredicate, 27, 191, 60, 0, // Skip to: 17098
/* 1547 */    MCD_OPC_Decode, 249, 21, 202, 1, // Opcode: SLTiu
/* 1552 */    MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 1567
/* 1557 */    MCD_OPC_CheckPredicate, 27, 176, 60, 0, // Skip to: 17098
/* 1562 */    MCD_OPC_Decode, 231, 6, 203, 1, // Opcode: ANDi
/* 1567 */    MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 1582
/* 1572 */    MCD_OPC_CheckPredicate, 27, 161, 60, 0, // Skip to: 17098
/* 1577 */    MCD_OPC_Decode, 175, 19, 203, 1, // Opcode: ORi
/* 1582 */    MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 1597
/* 1587 */    MCD_OPC_CheckPredicate, 27, 146, 60, 0, // Skip to: 17098
/* 1592 */    MCD_OPC_Decode, 184, 24, 203, 1, // Opcode: XORi
/* 1597 */    MCD_OPC_FilterValue, 15, 16, 0, 0, // Skip to: 1618
/* 1602 */    MCD_OPC_CheckPredicate, 27, 131, 60, 0, // Skip to: 17098
/* 1607 */    MCD_OPC_CheckField, 21, 5, 0, 124, 60, 0, // Skip to: 17098
/* 1614 */    MCD_OPC_Decode, 128, 16, 103, // Opcode: LUi
/* 1618 */    MCD_OPC_FilterValue, 16, 187, 2, 0, // Skip to: 2322
/* 1623 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 1626 */    MCD_OPC_FilterValue, 0, 190, 1, 0, // Skip to: 2077
/* 1631 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1634 */    MCD_OPC_FilterValue, 0, 17, 0, 0, // Skip to: 1656
/* 1639 */    MCD_OPC_CheckPredicate, 27, 94, 60, 0, // Skip to: 17098
/* 1644 */    MCD_OPC_CheckField, 4, 7, 0, 87, 60, 0, // Skip to: 17098
/* 1651 */    MCD_OPC_Decode, 128, 17, 204, 1, // Opcode: MFC0
/* 1656 */    MCD_OPC_FilterValue, 3, 63, 0, 0, // Skip to: 1724
/* 1661 */    MCD_OPC_ExtractField, 4, 7,  // Inst{10-4} ...
/* 1664 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 1679
/* 1669 */    MCD_OPC_CheckPredicate, 41, 64, 60, 0, // Skip to: 17098
/* 1674 */    MCD_OPC_Decode, 138, 17, 204, 1, // Opcode: MFGC0
/* 1679 */    MCD_OPC_FilterValue, 32, 10, 0, 0, // Skip to: 1694
/* 1684 */    MCD_OPC_CheckPredicate, 41, 49, 60, 0, // Skip to: 17098
/* 1689 */    MCD_OPC_Decode, 167, 18, 205, 1, // Opcode: MTGC0
/* 1694 */    MCD_OPC_FilterValue, 64, 10, 0, 0, // Skip to: 1709
/* 1699 */    MCD_OPC_CheckPredicate, 41, 34, 60, 0, // Skip to: 17098
/* 1704 */    MCD_OPC_Decode, 148, 17, 204, 1, // Opcode: MFHGC0
/* 1709 */    MCD_OPC_FilterValue, 96, 24, 60, 0, // Skip to: 17098
/* 1714 */    MCD_OPC_CheckPredicate, 41, 19, 60, 0, // Skip to: 17098
/* 1719 */    MCD_OPC_Decode, 177, 18, 205, 1, // Opcode: MTHGC0
/* 1724 */    MCD_OPC_FilterValue, 4, 17, 0, 0, // Skip to: 1746
/* 1729 */    MCD_OPC_CheckPredicate, 27, 4, 60, 0, // Skip to: 17098
/* 1734 */    MCD_OPC_CheckField, 4, 7, 0, 253, 59, 0, // Skip to: 17098
/* 1741 */    MCD_OPC_Decode, 156, 18, 205, 1, // Opcode: MTC0
/* 1746 */    MCD_OPC_FilterValue, 8, 17, 0, 0, // Skip to: 1768
/* 1751 */    MCD_OPC_CheckPredicate, 42, 238, 59, 0, // Skip to: 17098
/* 1756 */    MCD_OPC_CheckField, 6, 5, 0, 231, 59, 0, // Skip to: 17098
/* 1763 */    MCD_OPC_Decode, 162, 17, 206, 1, // Opcode: MFTR
/* 1768 */    MCD_OPC_FilterValue, 11, 133, 0, 0, // Skip to: 1906
/* 1773 */    MCD_OPC_ExtractField, 4, 12,  // Inst{15-4} ...
/* 1776 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 1797
/* 1781 */    MCD_OPC_CheckPredicate, 42, 208, 59, 0, // Skip to: 17098
/* 1786 */    MCD_OPC_CheckField, 0, 3, 1, 201, 59, 0, // Skip to: 17098
/* 1793 */    MCD_OPC_Decode, 201, 12, 92, // Opcode: DVPE
/* 1797 */    MCD_OPC_FilterValue, 2, 16, 0, 0, // Skip to: 1818
/* 1802 */    MCD_OPC_CheckPredicate, 42, 187, 59, 0, // Skip to: 17098
/* 1807 */    MCD_OPC_CheckField, 0, 3, 1, 180, 59, 0, // Skip to: 17098
/* 1814 */    MCD_OPC_Decode, 224, 12, 92, // Opcode: EVPE
/* 1818 */    MCD_OPC_FilterValue, 188, 1, 16, 0, 0, // Skip to: 1840
/* 1824 */    MCD_OPC_CheckPredicate, 42, 165, 59, 0, // Skip to: 17098
/* 1829 */    MCD_OPC_CheckField, 0, 3, 1, 158, 59, 0, // Skip to: 17098
/* 1836 */    MCD_OPC_Decode, 244, 11, 92, // Opcode: DMT
/* 1840 */    MCD_OPC_FilterValue, 190, 1, 16, 0, 0, // Skip to: 1862
/* 1846 */    MCD_OPC_CheckPredicate, 42, 143, 59, 0, // Skip to: 17098
/* 1851 */    MCD_OPC_CheckField, 0, 3, 1, 136, 59, 0, // Skip to: 17098
/* 1858 */    MCD_OPC_Decode, 214, 12, 92, // Opcode: EMT
/* 1862 */    MCD_OPC_FilterValue, 128, 12, 16, 0, 0, // Skip to: 1884
/* 1868 */    MCD_OPC_CheckPredicate, 28, 121, 59, 0, // Skip to: 17098
/* 1873 */    MCD_OPC_CheckField, 0, 3, 0, 114, 59, 0, // Skip to: 17098
/* 1880 */    MCD_OPC_Decode, 214, 11, 92, // Opcode: DI
/* 1884 */    MCD_OPC_FilterValue, 130, 12, 104, 59, 0, // Skip to: 17098
/* 1890 */    MCD_OPC_CheckPredicate, 28, 99, 59, 0, // Skip to: 17098
/* 1895 */    MCD_OPC_CheckField, 0, 3, 0, 92, 59, 0, // Skip to: 17098
/* 1902 */    MCD_OPC_Decode, 210, 12, 92, // Opcode: EI
/* 1906 */    MCD_OPC_FilterValue, 12, 17, 0, 0, // Skip to: 1928
/* 1911 */    MCD_OPC_CheckPredicate, 42, 78, 59, 0, // Skip to: 17098
/* 1916 */    MCD_OPC_CheckField, 6, 5, 0, 71, 59, 0, // Skip to: 17098
/* 1923 */    MCD_OPC_Decode, 197, 18, 206, 1, // Opcode: MTTR
/* 1928 */    MCD_OPC_FilterValue, 16, 61, 59, 0, // Skip to: 17098
/* 1933 */    MCD_OPC_ExtractField, 0, 3,  // Inst{2-0} ...
/* 1936 */    MCD_OPC_FilterValue, 0, 31, 0, 0, // Skip to: 1972
/* 1941 */    MCD_OPC_ExtractField, 4, 17,  // Inst{20-4} ...
/* 1944 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 1958
/* 1949 */    MCD_OPC_CheckPredicate, 41, 40, 59, 0, // Skip to: 17098
/* 1954 */    MCD_OPC_Decode, 224, 23, 10, // Opcode: TLBGP
/* 1958 */    MCD_OPC_FilterValue, 2, 31, 59, 0, // Skip to: 17098
/* 1963 */    MCD_OPC_CheckPredicate, 43, 26, 59, 0, // Skip to: 17098
/* 1968 */    MCD_OPC_Decode, 161, 24, 10, // Opcode: WAIT
/* 1972 */    MCD_OPC_FilterValue, 1, 16, 0, 0, // Skip to: 1993
/* 1977 */    MCD_OPC_CheckPredicate, 27, 12, 59, 0, // Skip to: 17098
/* 1982 */    MCD_OPC_CheckField, 4, 17, 0, 5, 59, 0, // Skip to: 17098
/* 1989 */    MCD_OPC_Decode, 241, 23, 10, // Opcode: TLBR
/* 1993 */    MCD_OPC_FilterValue, 2, 16, 0, 0, // Skip to: 2014
/* 1998 */    MCD_OPC_CheckPredicate, 27, 247, 58, 0, // Skip to: 17098
/* 2003 */    MCD_OPC_CheckField, 4, 17, 0, 240, 58, 0, // Skip to: 17098
/* 2010 */    MCD_OPC_Decode, 244, 23, 10, // Opcode: TLBWI
/* 2014 */    MCD_OPC_FilterValue, 3, 16, 0, 0, // Skip to: 2035
/* 2019 */    MCD_OPC_CheckPredicate, 44, 226, 58, 0, // Skip to: 17098
/* 2024 */    MCD_OPC_CheckField, 4, 17, 0, 219, 58, 0, // Skip to: 17098
/* 2031 */    MCD_OPC_Decode, 232, 23, 10, // Opcode: TLBINV
/* 2035 */    MCD_OPC_FilterValue, 4, 16, 0, 0, // Skip to: 2056
/* 2040 */    MCD_OPC_CheckPredicate, 44, 205, 58, 0, // Skip to: 17098
/* 2045 */    MCD_OPC_CheckField, 4, 17, 0, 198, 58, 0, // Skip to: 17098
/* 2052 */    MCD_OPC_Decode, 233, 23, 10, // Opcode: TLBINVF
/* 2056 */    MCD_OPC_FilterValue, 6, 189, 58, 0, // Skip to: 17098
/* 2061 */    MCD_OPC_CheckPredicate, 27, 184, 58, 0, // Skip to: 17098
/* 2066 */    MCD_OPC_CheckField, 4, 17, 0, 177, 58, 0, // Skip to: 17098
/* 2073 */    MCD_OPC_Decode, 247, 23, 10, // Opcode: TLBWR
/* 2077 */    MCD_OPC_FilterValue, 1, 168, 58, 0, // Skip to: 17098
/* 2082 */    MCD_OPC_ExtractField, 0, 3,  // Inst{2-0} ...
/* 2085 */    MCD_OPC_FilterValue, 0, 88, 0, 0, // Skip to: 2178
/* 2090 */    MCD_OPC_ExtractField, 4, 2,  // Inst{5-4} ...
/* 2093 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 2116
/* 2098 */    MCD_OPC_CheckPredicate, 27, 147, 58, 0, // Skip to: 17098
/* 2103 */    MCD_OPC_CheckField, 6, 20, 128, 128, 32, 138, 58, 0, // Skip to: 17098
/* 2112 */    MCD_OPC_Decode, 238, 23, 10, // Opcode: TLBP
/* 2116 */    MCD_OPC_FilterValue, 1, 35, 0, 0, // Skip to: 2156
/* 2121 */    MCD_OPC_ExtractField, 6, 20,  // Inst{25-6} ...
/* 2124 */    MCD_OPC_FilterValue, 128, 128, 32, 9, 0, 0, // Skip to: 2140
/* 2131 */    MCD_OPC_CheckPredicate, 43, 114, 58, 0, // Skip to: 17098
/* 2136 */    MCD_OPC_Decode, 216, 12, 10, // Opcode: ERET
/* 2140 */    MCD_OPC_FilterValue, 129, 128, 32, 103, 58, 0, // Skip to: 17098
/* 2147 */    MCD_OPC_CheckPredicate, 45, 98, 58, 0, // Skip to: 17098
/* 2152 */    MCD_OPC_Decode, 217, 12, 10, // Opcode: ERETNC
/* 2156 */    MCD_OPC_FilterValue, 2, 89, 58, 0, // Skip to: 17098
/* 2161 */    MCD_OPC_CheckPredicate, 41, 84, 58, 0, // Skip to: 17098
/* 2166 */    MCD_OPC_CheckField, 25, 1, 1, 77, 58, 0, // Skip to: 17098
/* 2173 */    MCD_OPC_Decode, 202, 14, 207, 1, // Opcode: HYPCALL
/* 2178 */    MCD_OPC_FilterValue, 1, 19, 0, 0, // Skip to: 2202
/* 2183 */    MCD_OPC_CheckPredicate, 41, 62, 58, 0, // Skip to: 17098
/* 2188 */    MCD_OPC_CheckField, 4, 22, 128, 128, 128, 1, 52, 58, 0, // Skip to: 17098
/* 2198 */    MCD_OPC_Decode, 226, 23, 10, // Opcode: TLBGR
/* 2202 */    MCD_OPC_FilterValue, 2, 19, 0, 0, // Skip to: 2226
/* 2207 */    MCD_OPC_CheckPredicate, 41, 38, 58, 0, // Skip to: 17098
/* 2212 */    MCD_OPC_CheckField, 4, 22, 128, 128, 128, 1, 28, 58, 0, // Skip to: 17098
/* 2222 */    MCD_OPC_Decode, 228, 23, 10, // Opcode: TLBGWI
/* 2226 */    MCD_OPC_FilterValue, 3, 19, 0, 0, // Skip to: 2250
/* 2231 */    MCD_OPC_CheckPredicate, 41, 14, 58, 0, // Skip to: 17098
/* 2236 */    MCD_OPC_CheckField, 4, 22, 128, 128, 128, 1, 4, 58, 0, // Skip to: 17098
/* 2246 */    MCD_OPC_Decode, 220, 23, 10, // Opcode: TLBGINV
/* 2250 */    MCD_OPC_FilterValue, 4, 19, 0, 0, // Skip to: 2274
/* 2255 */    MCD_OPC_CheckPredicate, 41, 246, 57, 0, // Skip to: 17098
/* 2260 */    MCD_OPC_CheckField, 4, 22, 128, 128, 128, 1, 236, 57, 0, // Skip to: 17098
/* 2270 */    MCD_OPC_Decode, 221, 23, 10, // Opcode: TLBGINVF
/* 2274 */    MCD_OPC_FilterValue, 6, 19, 0, 0, // Skip to: 2298
/* 2279 */    MCD_OPC_CheckPredicate, 41, 222, 57, 0, // Skip to: 17098
/* 2284 */    MCD_OPC_CheckField, 4, 22, 128, 128, 128, 1, 212, 57, 0, // Skip to: 17098
/* 2294 */    MCD_OPC_Decode, 230, 23, 10, // Opcode: TLBGWR
/* 2298 */    MCD_OPC_FilterValue, 7, 203, 57, 0, // Skip to: 17098
/* 2303 */    MCD_OPC_CheckPredicate, 46, 198, 57, 0, // Skip to: 17098
/* 2308 */    MCD_OPC_CheckField, 4, 22, 129, 128, 128, 1, 188, 57, 0, // Skip to: 17098
/* 2318 */    MCD_OPC_Decode, 206, 11, 10, // Opcode: DERET
/* 2322 */    MCD_OPC_FilterValue, 17, 205, 7, 0, // Skip to: 4324
/* 2327 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 2330 */    MCD_OPC_FilterValue, 0, 17, 0, 0, // Skip to: 2352
/* 2335 */    MCD_OPC_CheckPredicate, 47, 166, 57, 0, // Skip to: 17098
/* 2340 */    MCD_OPC_CheckField, 0, 11, 0, 159, 57, 0, // Skip to: 17098
/* 2347 */    MCD_OPC_Decode, 132, 17, 208, 1, // Opcode: MFC1
/* 2352 */    MCD_OPC_FilterValue, 1, 17, 0, 0, // Skip to: 2374
/* 2357 */    MCD_OPC_CheckPredicate, 48, 144, 57, 0, // Skip to: 17098
/* 2362 */    MCD_OPC_CheckField, 0, 11, 0, 137, 57, 0, // Skip to: 17098
/* 2369 */    MCD_OPC_Decode, 238, 11, 209, 1, // Opcode: DMFC1
/* 2374 */    MCD_OPC_FilterValue, 2, 17, 0, 0, // Skip to: 2396
/* 2379 */    MCD_OPC_CheckPredicate, 47, 122, 57, 0, // Skip to: 17098
/* 2384 */    MCD_OPC_CheckField, 0, 11, 0, 115, 57, 0, // Skip to: 17098
/* 2391 */    MCD_OPC_Decode, 144, 9, 210, 1, // Opcode: CFC1
/* 2396 */    MCD_OPC_FilterValue, 3, 17, 0, 0, // Skip to: 2418
/* 2401 */    MCD_OPC_CheckPredicate, 49, 100, 57, 0, // Skip to: 17098
/* 2406 */    MCD_OPC_CheckField, 0, 11, 0, 93, 57, 0, // Skip to: 17098
/* 2413 */    MCD_OPC_Decode, 143, 17, 211, 1, // Opcode: MFHC1_D32
/* 2418 */    MCD_OPC_FilterValue, 4, 17, 0, 0, // Skip to: 2440
/* 2423 */    MCD_OPC_CheckPredicate, 47, 78, 57, 0, // Skip to: 17098
/* 2428 */    MCD_OPC_CheckField, 0, 11, 0, 71, 57, 0, // Skip to: 17098
/* 2435 */    MCD_OPC_Decode, 160, 18, 212, 1, // Opcode: MTC1
/* 2440 */    MCD_OPC_FilterValue, 5, 17, 0, 0, // Skip to: 2462
/* 2445 */    MCD_OPC_CheckPredicate, 48, 56, 57, 0, // Skip to: 17098
/* 2450 */    MCD_OPC_CheckField, 0, 11, 0, 49, 57, 0, // Skip to: 17098
/* 2457 */    MCD_OPC_Decode, 246, 11, 213, 1, // Opcode: DMTC1
/* 2462 */    MCD_OPC_FilterValue, 6, 17, 0, 0, // Skip to: 2484
/* 2467 */    MCD_OPC_CheckPredicate, 47, 34, 57, 0, // Skip to: 17098
/* 2472 */    MCD_OPC_CheckField, 0, 11, 0, 27, 57, 0, // Skip to: 17098
/* 2479 */    MCD_OPC_Decode, 179, 10, 214, 1, // Opcode: CTC1
/* 2484 */    MCD_OPC_FilterValue, 7, 17, 0, 0, // Skip to: 2506
/* 2489 */    MCD_OPC_CheckPredicate, 49, 12, 57, 0, // Skip to: 17098
/* 2494 */    MCD_OPC_CheckField, 0, 11, 0, 5, 57, 0, // Skip to: 17098
/* 2501 */    MCD_OPC_Decode, 172, 18, 215, 1, // Opcode: MTHC1_D32
/* 2506 */    MCD_OPC_FilterValue, 8, 63, 0, 0, // Skip to: 2574
/* 2511 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 2514 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 2529
/* 2519 */    MCD_OPC_CheckPredicate, 50, 238, 56, 0, // Skip to: 17098
/* 2524 */    MCD_OPC_Decode, 166, 7, 216, 1, // Opcode: BC1F
/* 2529 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 2544
/* 2534 */    MCD_OPC_CheckPredicate, 50, 223, 56, 0, // Skip to: 17098
/* 2539 */    MCD_OPC_Decode, 171, 7, 216, 1, // Opcode: BC1T
/* 2544 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 2559
/* 2549 */    MCD_OPC_CheckPredicate, 51, 208, 56, 0, // Skip to: 17098
/* 2554 */    MCD_OPC_Decode, 167, 7, 216, 1, // Opcode: BC1FL
/* 2559 */    MCD_OPC_FilterValue, 3, 198, 56, 0, // Skip to: 17098
/* 2564 */    MCD_OPC_CheckPredicate, 51, 193, 56, 0, // Skip to: 17098
/* 2569 */    MCD_OPC_Decode, 172, 7, 216, 1, // Opcode: BC1TL
/* 2574 */    MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 2589
/* 2579 */    MCD_OPC_CheckPredicate, 30, 178, 56, 0, // Skip to: 17098
/* 2584 */    MCD_OPC_Decode, 233, 8, 217, 1, // Opcode: BZ_V
/* 2589 */    MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 2604
/* 2594 */    MCD_OPC_CheckPredicate, 30, 163, 56, 0, // Skip to: 17098
/* 2599 */    MCD_OPC_Decode, 204, 8, 217, 1, // Opcode: BNZ_V
/* 2604 */    MCD_OPC_FilterValue, 16, 1, 3, 0, // Skip to: 3378
/* 2609 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2612 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 2627
/* 2617 */    MCD_OPC_CheckPredicate, 47, 140, 56, 0, // Skip to: 17098
/* 2622 */    MCD_OPC_Decode, 142, 13, 218, 1, // Opcode: FADD_S
/* 2627 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 2642
/* 2632 */    MCD_OPC_CheckPredicate, 47, 125, 56, 0, // Skip to: 17098
/* 2637 */    MCD_OPC_Decode, 160, 14, 218, 1, // Opcode: FSUB_S
/* 2642 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 2657
/* 2647 */    MCD_OPC_CheckPredicate, 47, 110, 56, 0, // Skip to: 17098
/* 2652 */    MCD_OPC_Decode, 243, 13, 218, 1, // Opcode: FMUL_S
/* 2657 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 2672
/* 2662 */    MCD_OPC_CheckPredicate, 47, 95, 56, 0, // Skip to: 17098
/* 2667 */    MCD_OPC_Decode, 180, 13, 218, 1, // Opcode: FDIV_S
/* 2672 */    MCD_OPC_FilterValue, 4, 17, 0, 0, // Skip to: 2694
/* 2677 */    MCD_OPC_CheckPredicate, 52, 80, 56, 0, // Skip to: 17098
/* 2682 */    MCD_OPC_CheckField, 16, 5, 0, 73, 56, 0, // Skip to: 17098
/* 2689 */    MCD_OPC_Decode, 151, 14, 219, 1, // Opcode: FSQRT_S
/* 2694 */    MCD_OPC_FilterValue, 5, 17, 0, 0, // Skip to: 2716
/* 2699 */    MCD_OPC_CheckPredicate, 47, 58, 56, 0, // Skip to: 17098
/* 2704 */    MCD_OPC_CheckField, 16, 5, 0, 51, 56, 0, // Skip to: 17098
/* 2711 */    MCD_OPC_Decode, 134, 13, 219, 1, // Opcode: FABS_S
/* 2716 */    MCD_OPC_FilterValue, 6, 17, 0, 0, // Skip to: 2738
/* 2721 */    MCD_OPC_CheckPredicate, 47, 36, 56, 0, // Skip to: 17098
/* 2726 */    MCD_OPC_CheckField, 16, 5, 0, 29, 56, 0, // Skip to: 17098
/* 2733 */    MCD_OPC_Decode, 232, 13, 219, 1, // Opcode: FMOV_S
/* 2738 */    MCD_OPC_FilterValue, 7, 17, 0, 0, // Skip to: 2760
/* 2743 */    MCD_OPC_CheckPredicate, 53, 14, 56, 0, // Skip to: 17098
/* 2748 */    MCD_OPC_CheckField, 16, 5, 0, 7, 56, 0, // Skip to: 17098
/* 2755 */    MCD_OPC_Decode, 251, 13, 219, 1, // Opcode: FNEG_S
/* 2760 */    MCD_OPC_FilterValue, 12, 17, 0, 0, // Skip to: 2782
/* 2765 */    MCD_OPC_CheckPredicate, 52, 248, 55, 0, // Skip to: 17098
/* 2770 */    MCD_OPC_CheckField, 16, 5, 0, 241, 55, 0, // Skip to: 17098
/* 2777 */    MCD_OPC_Decode, 170, 20, 219, 1, // Opcode: ROUND_W_S
/* 2782 */    MCD_OPC_FilterValue, 13, 17, 0, 0, // Skip to: 2804
/* 2787 */    MCD_OPC_CheckPredicate, 52, 226, 55, 0, // Skip to: 17098
/* 2792 */    MCD_OPC_CheckField, 16, 5, 0, 219, 55, 0, // Skip to: 17098
/* 2799 */    MCD_OPC_Decode, 142, 24, 219, 1, // Opcode: TRUNC_W_S
/* 2804 */    MCD_OPC_FilterValue, 14, 17, 0, 0, // Skip to: 2826
/* 2809 */    MCD_OPC_CheckPredicate, 52, 204, 55, 0, // Skip to: 17098
/* 2814 */    MCD_OPC_CheckField, 16, 5, 0, 197, 55, 0, // Skip to: 17098
/* 2821 */    MCD_OPC_Decode, 133, 9, 219, 1, // Opcode: CEIL_W_S
/* 2826 */    MCD_OPC_FilterValue, 15, 17, 0, 0, // Skip to: 2848
/* 2831 */    MCD_OPC_CheckPredicate, 52, 182, 55, 0, // Skip to: 17098
/* 2836 */    MCD_OPC_CheckField, 16, 5, 0, 175, 55, 0, // Skip to: 17098
/* 2843 */    MCD_OPC_Decode, 214, 13, 219, 1, // Opcode: FLOOR_W_S
/* 2848 */    MCD_OPC_FilterValue, 17, 33, 0, 0, // Skip to: 2886
/* 2853 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 2856 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 2871
/* 2861 */    MCD_OPC_CheckPredicate, 29, 152, 55, 0, // Skip to: 17098
/* 2866 */    MCD_OPC_Decode, 223, 17, 220, 1, // Opcode: MOVF_S
/* 2871 */    MCD_OPC_FilterValue, 1, 142, 55, 0, // Skip to: 17098
/* 2876 */    MCD_OPC_CheckPredicate, 29, 137, 55, 0, // Skip to: 17098
/* 2881 */    MCD_OPC_Decode, 244, 17, 220, 1, // Opcode: MOVT_S
/* 2886 */    MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 2901
/* 2891 */    MCD_OPC_CheckPredicate, 29, 122, 55, 0, // Skip to: 17098
/* 2896 */    MCD_OPC_Decode, 128, 18, 221, 1, // Opcode: MOVZ_I_S
/* 2901 */    MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 2916
/* 2906 */    MCD_OPC_CheckPredicate, 29, 107, 55, 0, // Skip to: 17098
/* 2911 */    MCD_OPC_Decode, 235, 17, 221, 1, // Opcode: MOVN_I_S
/* 2916 */    MCD_OPC_FilterValue, 21, 17, 0, 0, // Skip to: 2938
/* 2921 */    MCD_OPC_CheckPredicate, 54, 92, 55, 0, // Skip to: 17098
/* 2926 */    MCD_OPC_CheckField, 16, 5, 0, 85, 55, 0, // Skip to: 17098
/* 2933 */    MCD_OPC_Decode, 138, 20, 219, 1, // Opcode: RECIP_S
/* 2938 */    MCD_OPC_FilterValue, 22, 17, 0, 0, // Skip to: 2960
/* 2943 */    MCD_OPC_CheckPredicate, 54, 70, 55, 0, // Skip to: 17098
/* 2948 */    MCD_OPC_CheckField, 16, 5, 0, 63, 55, 0, // Skip to: 17098
/* 2955 */    MCD_OPC_Decode, 177, 20, 219, 1, // Opcode: RSQRT_S
/* 2960 */    MCD_OPC_FilterValue, 33, 17, 0, 0, // Skip to: 2982
/* 2965 */    MCD_OPC_CheckPredicate, 55, 48, 55, 0, // Skip to: 17098
/* 2970 */    MCD_OPC_CheckField, 16, 5, 0, 41, 55, 0, // Skip to: 17098
/* 2977 */    MCD_OPC_Decode, 183, 10, 222, 1, // Opcode: CVT_D32_S
/* 2982 */    MCD_OPC_FilterValue, 36, 17, 0, 0, // Skip to: 3004
/* 2987 */    MCD_OPC_CheckPredicate, 47, 26, 55, 0, // Skip to: 17098
/* 2992 */    MCD_OPC_CheckField, 16, 5, 0, 19, 55, 0, // Skip to: 17098
/* 2999 */    MCD_OPC_Decode, 217, 10, 219, 1, // Opcode: CVT_W_S
/* 3004 */    MCD_OPC_FilterValue, 37, 17, 0, 0, // Skip to: 3026
/* 3009 */    MCD_OPC_CheckPredicate, 56, 4, 55, 0, // Skip to: 17098
/* 3014 */    MCD_OPC_CheckField, 16, 5, 0, 253, 54, 0, // Skip to: 17098
/* 3021 */    MCD_OPC_Decode, 196, 10, 223, 1, // Opcode: CVT_L_S
/* 3026 */    MCD_OPC_FilterValue, 48, 17, 0, 0, // Skip to: 3048
/* 3031 */    MCD_OPC_CheckPredicate, 50, 238, 54, 0, // Skip to: 17098
/* 3036 */    MCD_OPC_CheckField, 6, 2, 0, 231, 54, 0, // Skip to: 17098
/* 3043 */    MCD_OPC_Decode, 230, 10, 224, 1, // Opcode: C_F_S
/* 3048 */    MCD_OPC_FilterValue, 49, 17, 0, 0, // Skip to: 3070
/* 3053 */    MCD_OPC_CheckPredicate, 50, 216, 54, 0, // Skip to: 17098
/* 3058 */    MCD_OPC_CheckField, 6, 2, 0, 209, 54, 0, // Skip to: 17098
/* 3065 */    MCD_OPC_Decode, 186, 11, 224, 1, // Opcode: C_UN_S
/* 3070 */    MCD_OPC_FilterValue, 50, 17, 0, 0, // Skip to: 3092
/* 3075 */    MCD_OPC_CheckPredicate, 50, 194, 54, 0, // Skip to: 17098
/* 3080 */    MCD_OPC_CheckField, 6, 2, 0, 187, 54, 0, // Skip to: 17098
/* 3087 */    MCD_OPC_Decode, 224, 10, 224, 1, // Opcode: C_EQ_S
/* 3092 */    MCD_OPC_FilterValue, 51, 17, 0, 0, // Skip to: 3114
/* 3097 */    MCD_OPC_CheckPredicate, 50, 172, 54, 0, // Skip to: 17098
/* 3102 */    MCD_OPC_CheckField, 6, 2, 0, 165, 54, 0, // Skip to: 17098
/* 3109 */    MCD_OPC_Decode, 168, 11, 224, 1, // Opcode: C_UEQ_S
/* 3114 */    MCD_OPC_FilterValue, 52, 17, 0, 0, // Skip to: 3136
/* 3119 */    MCD_OPC_CheckPredicate, 50, 150, 54, 0, // Skip to: 17098
/* 3124 */    MCD_OPC_CheckField, 6, 2, 0, 143, 54, 0, // Skip to: 17098
/* 3131 */    MCD_OPC_Decode, 150, 11, 224, 1, // Opcode: C_OLT_S
/* 3136 */    MCD_OPC_FilterValue, 53, 17, 0, 0, // Skip to: 3158
/* 3141 */    MCD_OPC_CheckPredicate, 50, 128, 54, 0, // Skip to: 17098
/* 3146 */    MCD_OPC_CheckField, 6, 2, 0, 121, 54, 0, // Skip to: 17098
/* 3153 */    MCD_OPC_Decode, 180, 11, 224, 1, // Opcode: C_ULT_S
/* 3158 */    MCD_OPC_FilterValue, 54, 17, 0, 0, // Skip to: 3180
/* 3163 */    MCD_OPC_CheckPredicate, 50, 106, 54, 0, // Skip to: 17098
/* 3168 */    MCD_OPC_CheckField, 6, 2, 0, 99, 54, 0, // Skip to: 17098
/* 3175 */    MCD_OPC_Decode, 144, 11, 224, 1, // Opcode: C_OLE_S
/* 3180 */    MCD_OPC_FilterValue, 55, 17, 0, 0, // Skip to: 3202
/* 3185 */    MCD_OPC_CheckPredicate, 50, 84, 54, 0, // Skip to: 17098
/* 3190 */    MCD_OPC_CheckField, 6, 2, 0, 77, 54, 0, // Skip to: 17098
/* 3197 */    MCD_OPC_Decode, 174, 11, 224, 1, // Opcode: C_ULE_S
/* 3202 */    MCD_OPC_FilterValue, 56, 17, 0, 0, // Skip to: 3224
/* 3207 */    MCD_OPC_CheckPredicate, 50, 62, 54, 0, // Skip to: 17098
/* 3212 */    MCD_OPC_CheckField, 6, 2, 0, 55, 54, 0, // Skip to: 17098
/* 3219 */    MCD_OPC_Decode, 162, 11, 224, 1, // Opcode: C_SF_S
/* 3224 */    MCD_OPC_FilterValue, 57, 17, 0, 0, // Skip to: 3246
/* 3229 */    MCD_OPC_CheckPredicate, 50, 40, 54, 0, // Skip to: 17098
/* 3234 */    MCD_OPC_CheckField, 6, 2, 0, 33, 54, 0, // Skip to: 17098
/* 3241 */    MCD_OPC_Decode, 254, 10, 224, 1, // Opcode: C_NGLE_S
/* 3246 */    MCD_OPC_FilterValue, 58, 17, 0, 0, // Skip to: 3268
/* 3251 */    MCD_OPC_CheckPredicate, 50, 18, 54, 0, // Skip to: 17098
/* 3256 */    MCD_OPC_CheckField, 6, 2, 0, 11, 54, 0, // Skip to: 17098
/* 3263 */    MCD_OPC_Decode, 156, 11, 224, 1, // Opcode: C_SEQ_S
/* 3268 */    MCD_OPC_FilterValue, 59, 17, 0, 0, // Skip to: 3290
/* 3273 */    MCD_OPC_CheckPredicate, 50, 252, 53, 0, // Skip to: 17098
/* 3278 */    MCD_OPC_CheckField, 6, 2, 0, 245, 53, 0, // Skip to: 17098
/* 3285 */    MCD_OPC_Decode, 132, 11, 224, 1, // Opcode: C_NGL_S
/* 3290 */    MCD_OPC_FilterValue, 60, 17, 0, 0, // Skip to: 3312
/* 3295 */    MCD_OPC_CheckPredicate, 50, 230, 53, 0, // Skip to: 17098
/* 3300 */    MCD_OPC_CheckField, 6, 2, 0, 223, 53, 0, // Skip to: 17098
/* 3307 */    MCD_OPC_Decode, 242, 10, 224, 1, // Opcode: C_LT_S
/* 3312 */    MCD_OPC_FilterValue, 61, 17, 0, 0, // Skip to: 3334
/* 3317 */    MCD_OPC_CheckPredicate, 50, 208, 53, 0, // Skip to: 17098
/* 3322 */    MCD_OPC_CheckField, 6, 2, 0, 201, 53, 0, // Skip to: 17098
/* 3329 */    MCD_OPC_Decode, 248, 10, 224, 1, // Opcode: C_NGE_S
/* 3334 */    MCD_OPC_FilterValue, 62, 17, 0, 0, // Skip to: 3356
/* 3339 */    MCD_OPC_CheckPredicate, 50, 186, 53, 0, // Skip to: 17098
/* 3344 */    MCD_OPC_CheckField, 6, 2, 0, 179, 53, 0, // Skip to: 17098
/* 3351 */    MCD_OPC_Decode, 236, 10, 224, 1, // Opcode: C_LE_S
/* 3356 */    MCD_OPC_FilterValue, 63, 169, 53, 0, // Skip to: 17098
/* 3361 */    MCD_OPC_CheckPredicate, 50, 164, 53, 0, // Skip to: 17098
/* 3366 */    MCD_OPC_CheckField, 6, 2, 0, 157, 53, 0, // Skip to: 17098
/* 3373 */    MCD_OPC_Decode, 138, 11, 224, 1, // Opcode: C_NGT_S
/* 3378 */    MCD_OPC_FilterValue, 17, 1, 3, 0, // Skip to: 4152
/* 3383 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 3386 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 3401
/* 3391 */    MCD_OPC_CheckPredicate, 55, 134, 53, 0, // Skip to: 17098
/* 3396 */    MCD_OPC_Decode, 137, 13, 225, 1, // Opcode: FADD_D32
/* 3401 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 3416
/* 3406 */    MCD_OPC_CheckPredicate, 55, 119, 53, 0, // Skip to: 17098
/* 3411 */    MCD_OPC_Decode, 155, 14, 225, 1, // Opcode: FSUB_D32
/* 3416 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 3431
/* 3421 */    MCD_OPC_CheckPredicate, 55, 104, 53, 0, // Skip to: 17098
/* 3426 */    MCD_OPC_Decode, 238, 13, 225, 1, // Opcode: FMUL_D32
/* 3431 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 3446
/* 3436 */    MCD_OPC_CheckPredicate, 55, 89, 53, 0, // Skip to: 17098
/* 3441 */    MCD_OPC_Decode, 176, 13, 225, 1, // Opcode: FDIV_D32
/* 3446 */    MCD_OPC_FilterValue, 4, 17, 0, 0, // Skip to: 3468
/* 3451 */    MCD_OPC_CheckPredicate, 57, 74, 53, 0, // Skip to: 17098
/* 3456 */    MCD_OPC_CheckField, 16, 5, 0, 67, 53, 0, // Skip to: 17098
/* 3463 */    MCD_OPC_Decode, 147, 14, 226, 1, // Opcode: FSQRT_D32
/* 3468 */    MCD_OPC_FilterValue, 5, 17, 0, 0, // Skip to: 3490
/* 3473 */    MCD_OPC_CheckPredicate, 55, 52, 53, 0, // Skip to: 17098
/* 3478 */    MCD_OPC_CheckField, 16, 5, 0, 45, 53, 0, // Skip to: 17098
/* 3485 */    MCD_OPC_Decode, 130, 13, 226, 1, // Opcode: FABS_D32
/* 3490 */    MCD_OPC_FilterValue, 6, 17, 0, 0, // Skip to: 3512
/* 3495 */    MCD_OPC_CheckPredicate, 55, 30, 53, 0, // Skip to: 17098
/* 3500 */    MCD_OPC_CheckField, 16, 5, 0, 23, 53, 0, // Skip to: 17098
/* 3507 */    MCD_OPC_Decode, 227, 13, 226, 1, // Opcode: FMOV_D32
/* 3512 */    MCD_OPC_FilterValue, 7, 17, 0, 0, // Skip to: 3534
/* 3517 */    MCD_OPC_CheckPredicate, 55, 8, 53, 0, // Skip to: 17098
/* 3522 */    MCD_OPC_CheckField, 16, 5, 0, 1, 53, 0, // Skip to: 17098
/* 3529 */    MCD_OPC_Decode, 247, 13, 226, 1, // Opcode: FNEG_D32
/* 3534 */    MCD_OPC_FilterValue, 12, 17, 0, 0, // Skip to: 3556
/* 3539 */    MCD_OPC_CheckPredicate, 57, 242, 52, 0, // Skip to: 17098
/* 3544 */    MCD_OPC_CheckField, 16, 5, 0, 235, 52, 0, // Skip to: 17098
/* 3551 */    MCD_OPC_Decode, 166, 20, 227, 1, // Opcode: ROUND_W_D32
/* 3556 */    MCD_OPC_FilterValue, 13, 17, 0, 0, // Skip to: 3578
/* 3561 */    MCD_OPC_CheckPredicate, 57, 220, 52, 0, // Skip to: 17098
/* 3566 */    MCD_OPC_CheckField, 16, 5, 0, 213, 52, 0, // Skip to: 17098
/* 3573 */    MCD_OPC_Decode, 138, 24, 227, 1, // Opcode: TRUNC_W_D32
/* 3578 */    MCD_OPC_FilterValue, 14, 17, 0, 0, // Skip to: 3600
/* 3583 */    MCD_OPC_CheckPredicate, 57, 198, 52, 0, // Skip to: 17098
/* 3588 */    MCD_OPC_CheckField, 16, 5, 0, 191, 52, 0, // Skip to: 17098
/* 3595 */    MCD_OPC_Decode, 129, 9, 227, 1, // Opcode: CEIL_W_D32
/* 3600 */    MCD_OPC_FilterValue, 15, 17, 0, 0, // Skip to: 3622
/* 3605 */    MCD_OPC_CheckPredicate, 57, 176, 52, 0, // Skip to: 17098
/* 3610 */    MCD_OPC_CheckField, 16, 5, 0, 169, 52, 0, // Skip to: 17098
/* 3617 */    MCD_OPC_Decode, 210, 13, 227, 1, // Opcode: FLOOR_W_D32
/* 3622 */    MCD_OPC_FilterValue, 17, 33, 0, 0, // Skip to: 3660
/* 3627 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 3630 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 3645
/* 3635 */    MCD_OPC_CheckPredicate, 58, 146, 52, 0, // Skip to: 17098
/* 3640 */    MCD_OPC_Decode, 217, 17, 228, 1, // Opcode: MOVF_D32
/* 3645 */    MCD_OPC_FilterValue, 1, 136, 52, 0, // Skip to: 17098
/* 3650 */    MCD_OPC_CheckPredicate, 58, 131, 52, 0, // Skip to: 17098
/* 3655 */    MCD_OPC_Decode, 238, 17, 228, 1, // Opcode: MOVT_D32
/* 3660 */    MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 3675
/* 3665 */    MCD_OPC_CheckPredicate, 58, 116, 52, 0, // Skip to: 17098
/* 3670 */    MCD_OPC_Decode, 250, 17, 229, 1, // Opcode: MOVZ_I_D32
/* 3675 */    MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 3690
/* 3680 */    MCD_OPC_CheckPredicate, 58, 101, 52, 0, // Skip to: 17098
/* 3685 */    MCD_OPC_Decode, 229, 17, 229, 1, // Opcode: MOVN_I_D32
/* 3690 */    MCD_OPC_FilterValue, 21, 17, 0, 0, // Skip to: 3712
/* 3695 */    MCD_OPC_CheckPredicate, 59, 86, 52, 0, // Skip to: 17098
/* 3700 */    MCD_OPC_CheckField, 16, 5, 0, 79, 52, 0, // Skip to: 17098
/* 3707 */    MCD_OPC_Decode, 134, 20, 226, 1, // Opcode: RECIP_D32
/* 3712 */    MCD_OPC_FilterValue, 22, 17, 0, 0, // Skip to: 3734
/* 3717 */    MCD_OPC_CheckPredicate, 59, 64, 52, 0, // Skip to: 17098
/* 3722 */    MCD_OPC_CheckField, 16, 5, 0, 57, 52, 0, // Skip to: 17098
/* 3729 */    MCD_OPC_Decode, 173, 20, 226, 1, // Opcode: RSQRT_D32
/* 3734 */    MCD_OPC_FilterValue, 32, 17, 0, 0, // Skip to: 3756
/* 3739 */    MCD_OPC_CheckPredicate, 55, 42, 52, 0, // Skip to: 17098
/* 3744 */    MCD_OPC_CheckField, 16, 5, 0, 35, 52, 0, // Skip to: 17098
/* 3751 */    MCD_OPC_Decode, 202, 10, 227, 1, // Opcode: CVT_S_D32
/* 3756 */    MCD_OPC_FilterValue, 36, 17, 0, 0, // Skip to: 3778
/* 3761 */    MCD_OPC_CheckPredicate, 55, 20, 52, 0, // Skip to: 17098
/* 3766 */    MCD_OPC_CheckField, 16, 5, 0, 13, 52, 0, // Skip to: 17098
/* 3773 */    MCD_OPC_Decode, 213, 10, 227, 1, // Opcode: CVT_W_D32
/* 3778 */    MCD_OPC_FilterValue, 37, 17, 0, 0, // Skip to: 3800
/* 3783 */    MCD_OPC_CheckPredicate, 56, 254, 51, 0, // Skip to: 17098
/* 3788 */    MCD_OPC_CheckField, 16, 5, 0, 247, 51, 0, // Skip to: 17098
/* 3795 */    MCD_OPC_Decode, 193, 10, 230, 1, // Opcode: CVT_L_D64
/* 3800 */    MCD_OPC_FilterValue, 48, 17, 0, 0, // Skip to: 3822
/* 3805 */    MCD_OPC_CheckPredicate, 60, 232, 51, 0, // Skip to: 17098
/* 3810 */    MCD_OPC_CheckField, 6, 2, 0, 225, 51, 0, // Skip to: 17098
/* 3817 */    MCD_OPC_Decode, 226, 10, 231, 1, // Opcode: C_F_D32
/* 3822 */    MCD_OPC_FilterValue, 49, 17, 0, 0, // Skip to: 3844
/* 3827 */    MCD_OPC_CheckPredicate, 60, 210, 51, 0, // Skip to: 17098
/* 3832 */    MCD_OPC_CheckField, 6, 2, 0, 203, 51, 0, // Skip to: 17098
/* 3839 */    MCD_OPC_Decode, 182, 11, 231, 1, // Opcode: C_UN_D32
/* 3844 */    MCD_OPC_FilterValue, 50, 17, 0, 0, // Skip to: 3866
/* 3849 */    MCD_OPC_CheckPredicate, 60, 188, 51, 0, // Skip to: 17098
/* 3854 */    MCD_OPC_CheckField, 6, 2, 0, 181, 51, 0, // Skip to: 17098
/* 3861 */    MCD_OPC_Decode, 220, 10, 231, 1, // Opcode: C_EQ_D32
/* 3866 */    MCD_OPC_FilterValue, 51, 17, 0, 0, // Skip to: 3888
/* 3871 */    MCD_OPC_CheckPredicate, 60, 166, 51, 0, // Skip to: 17098
/* 3876 */    MCD_OPC_CheckField, 6, 2, 0, 159, 51, 0, // Skip to: 17098
/* 3883 */    MCD_OPC_Decode, 164, 11, 231, 1, // Opcode: C_UEQ_D32
/* 3888 */    MCD_OPC_FilterValue, 52, 17, 0, 0, // Skip to: 3910
/* 3893 */    MCD_OPC_CheckPredicate, 60, 144, 51, 0, // Skip to: 17098
/* 3898 */    MCD_OPC_CheckField, 6, 2, 0, 137, 51, 0, // Skip to: 17098
/* 3905 */    MCD_OPC_Decode, 146, 11, 231, 1, // Opcode: C_OLT_D32
/* 3910 */    MCD_OPC_FilterValue, 53, 17, 0, 0, // Skip to: 3932
/* 3915 */    MCD_OPC_CheckPredicate, 60, 122, 51, 0, // Skip to: 17098
/* 3920 */    MCD_OPC_CheckField, 6, 2, 0, 115, 51, 0, // Skip to: 17098
/* 3927 */    MCD_OPC_Decode, 176, 11, 231, 1, // Opcode: C_ULT_D32
/* 3932 */    MCD_OPC_FilterValue, 54, 17, 0, 0, // Skip to: 3954
/* 3937 */    MCD_OPC_CheckPredicate, 60, 100, 51, 0, // Skip to: 17098
/* 3942 */    MCD_OPC_CheckField, 6, 2, 0, 93, 51, 0, // Skip to: 17098
/* 3949 */    MCD_OPC_Decode, 140, 11, 231, 1, // Opcode: C_OLE_D32
/* 3954 */    MCD_OPC_FilterValue, 55, 17, 0, 0, // Skip to: 3976
/* 3959 */    MCD_OPC_CheckPredicate, 60, 78, 51, 0, // Skip to: 17098
/* 3964 */    MCD_OPC_CheckField, 6, 2, 0, 71, 51, 0, // Skip to: 17098
/* 3971 */    MCD_OPC_Decode, 170, 11, 231, 1, // Opcode: C_ULE_D32
/* 3976 */    MCD_OPC_FilterValue, 56, 17, 0, 0, // Skip to: 3998
/* 3981 */    MCD_OPC_CheckPredicate, 60, 56, 51, 0, // Skip to: 17098
/* 3986 */    MCD_OPC_CheckField, 6, 2, 0, 49, 51, 0, // Skip to: 17098
/* 3993 */    MCD_OPC_Decode, 158, 11, 231, 1, // Opcode: C_SF_D32
/* 3998 */    MCD_OPC_FilterValue, 57, 17, 0, 0, // Skip to: 4020
/* 4003 */    MCD_OPC_CheckPredicate, 60, 34, 51, 0, // Skip to: 17098
/* 4008 */    MCD_OPC_CheckField, 6, 2, 0, 27, 51, 0, // Skip to: 17098
/* 4015 */    MCD_OPC_Decode, 250, 10, 231, 1, // Opcode: C_NGLE_D32
/* 4020 */    MCD_OPC_FilterValue, 58, 17, 0, 0, // Skip to: 4042
/* 4025 */    MCD_OPC_CheckPredicate, 60, 12, 51, 0, // Skip to: 17098
/* 4030 */    MCD_OPC_CheckField, 6, 2, 0, 5, 51, 0, // Skip to: 17098
/* 4037 */    MCD_OPC_Decode, 152, 11, 231, 1, // Opcode: C_SEQ_D32
/* 4042 */    MCD_OPC_FilterValue, 59, 17, 0, 0, // Skip to: 4064
/* 4047 */    MCD_OPC_CheckPredicate, 60, 246, 50, 0, // Skip to: 17098
/* 4052 */    MCD_OPC_CheckField, 6, 2, 0, 239, 50, 0, // Skip to: 17098
/* 4059 */    MCD_OPC_Decode, 128, 11, 231, 1, // Opcode: C_NGL_D32
/* 4064 */    MCD_OPC_FilterValue, 60, 17, 0, 0, // Skip to: 4086
/* 4069 */    MCD_OPC_CheckPredicate, 60, 224, 50, 0, // Skip to: 17098
/* 4074 */    MCD_OPC_CheckField, 6, 2, 0, 217, 50, 0, // Skip to: 17098
/* 4081 */    MCD_OPC_Decode, 238, 10, 231, 1, // Opcode: C_LT_D32
/* 4086 */    MCD_OPC_FilterValue, 61, 17, 0, 0, // Skip to: 4108
/* 4091 */    MCD_OPC_CheckPredicate, 60, 202, 50, 0, // Skip to: 17098
/* 4096 */    MCD_OPC_CheckField, 6, 2, 0, 195, 50, 0, // Skip to: 17098
/* 4103 */    MCD_OPC_Decode, 244, 10, 231, 1, // Opcode: C_NGE_D32
/* 4108 */    MCD_OPC_FilterValue, 62, 17, 0, 0, // Skip to: 4130
/* 4113 */    MCD_OPC_CheckPredicate, 60, 180, 50, 0, // Skip to: 17098
/* 4118 */    MCD_OPC_CheckField, 6, 2, 0, 173, 50, 0, // Skip to: 17098
/* 4125 */    MCD_OPC_Decode, 232, 10, 231, 1, // Opcode: C_LE_D32
/* 4130 */    MCD_OPC_FilterValue, 63, 163, 50, 0, // Skip to: 17098
/* 4135 */    MCD_OPC_CheckPredicate, 60, 158, 50, 0, // Skip to: 17098
/* 4140 */    MCD_OPC_CheckField, 6, 2, 0, 151, 50, 0, // Skip to: 17098
/* 4147 */    MCD_OPC_Decode, 134, 11, 231, 1, // Opcode: C_NGT_D32
/* 4152 */    MCD_OPC_FilterValue, 20, 47, 0, 0, // Skip to: 4204
/* 4157 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 4160 */    MCD_OPC_FilterValue, 32, 17, 0, 0, // Skip to: 4182
/* 4165 */    MCD_OPC_CheckPredicate, 47, 128, 50, 0, // Skip to: 17098
/* 4170 */    MCD_OPC_CheckField, 16, 5, 0, 121, 50, 0, // Skip to: 17098
/* 4177 */    MCD_OPC_Decode, 210, 10, 219, 1, // Opcode: CVT_S_W
/* 4182 */    MCD_OPC_FilterValue, 33, 111, 50, 0, // Skip to: 17098
/* 4187 */    MCD_OPC_CheckPredicate, 55, 106, 50, 0, // Skip to: 17098
/* 4192 */    MCD_OPC_CheckField, 16, 5, 0, 99, 50, 0, // Skip to: 17098
/* 4199 */    MCD_OPC_Decode, 185, 10, 222, 1, // Opcode: CVT_D32_W
/* 4204 */    MCD_OPC_FilterValue, 24, 10, 0, 0, // Skip to: 4219
/* 4209 */    MCD_OPC_CheckPredicate, 30, 84, 50, 0, // Skip to: 17098
/* 4214 */    MCD_OPC_Decode, 230, 8, 217, 1, // Opcode: BZ_B
/* 4219 */    MCD_OPC_FilterValue, 25, 10, 0, 0, // Skip to: 4234
/* 4224 */    MCD_OPC_CheckPredicate, 30, 69, 50, 0, // Skip to: 17098
/* 4229 */    MCD_OPC_Decode, 232, 8, 232, 1, // Opcode: BZ_H
/* 4234 */    MCD_OPC_FilterValue, 26, 10, 0, 0, // Skip to: 4249
/* 4239 */    MCD_OPC_CheckPredicate, 30, 54, 50, 0, // Skip to: 17098
/* 4244 */    MCD_OPC_Decode, 234, 8, 233, 1, // Opcode: BZ_W
/* 4249 */    MCD_OPC_FilterValue, 27, 10, 0, 0, // Skip to: 4264
/* 4254 */    MCD_OPC_CheckPredicate, 30, 39, 50, 0, // Skip to: 17098
/* 4259 */    MCD_OPC_Decode, 231, 8, 234, 1, // Opcode: BZ_D
/* 4264 */    MCD_OPC_FilterValue, 28, 10, 0, 0, // Skip to: 4279
/* 4269 */    MCD_OPC_CheckPredicate, 30, 24, 50, 0, // Skip to: 17098
/* 4274 */    MCD_OPC_Decode, 201, 8, 217, 1, // Opcode: BNZ_B
/* 4279 */    MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 4294
/* 4284 */    MCD_OPC_CheckPredicate, 30, 9, 50, 0, // Skip to: 17098
/* 4289 */    MCD_OPC_Decode, 203, 8, 232, 1, // Opcode: BNZ_H
/* 4294 */    MCD_OPC_FilterValue, 30, 10, 0, 0, // Skip to: 4309
/* 4299 */    MCD_OPC_CheckPredicate, 30, 250, 49, 0, // Skip to: 17098
/* 4304 */    MCD_OPC_Decode, 205, 8, 233, 1, // Opcode: BNZ_W
/* 4309 */    MCD_OPC_FilterValue, 31, 240, 49, 0, // Skip to: 17098
/* 4314 */    MCD_OPC_CheckPredicate, 30, 235, 49, 0, // Skip to: 17098
/* 4319 */    MCD_OPC_Decode, 202, 8, 234, 1, // Opcode: BNZ_D
/* 4324 */    MCD_OPC_FilterValue, 18, 47, 0, 0, // Skip to: 4376
/* 4329 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 4332 */    MCD_OPC_FilterValue, 0, 17, 0, 0, // Skip to: 4354
/* 4337 */    MCD_OPC_CheckPredicate, 27, 212, 49, 0, // Skip to: 17098
/* 4342 */    MCD_OPC_CheckField, 3, 8, 0, 205, 49, 0, // Skip to: 17098
/* 4349 */    MCD_OPC_Decode, 136, 17, 235, 1, // Opcode: MFC2
/* 4354 */    MCD_OPC_FilterValue, 4, 195, 49, 0, // Skip to: 17098
/* 4359 */    MCD_OPC_CheckPredicate, 27, 190, 49, 0, // Skip to: 17098
/* 4364 */    MCD_OPC_CheckField, 3, 8, 0, 183, 49, 0, // Skip to: 17098
/* 4371 */    MCD_OPC_Decode, 165, 18, 236, 1, // Opcode: MTC2
/* 4376 */    MCD_OPC_FilterValue, 19, 255, 0, 0, // Skip to: 4636
/* 4381 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 4384 */    MCD_OPC_FilterValue, 0, 17, 0, 0, // Skip to: 4406
/* 4389 */    MCD_OPC_CheckPredicate, 61, 160, 49, 0, // Skip to: 17098
/* 4394 */    MCD_OPC_CheckField, 11, 5, 0, 153, 49, 0, // Skip to: 17098
/* 4401 */    MCD_OPC_Decode, 172, 16, 237, 1, // Opcode: LWXC1
/* 4406 */    MCD_OPC_FilterValue, 1, 17, 0, 0, // Skip to: 4428
/* 4411 */    MCD_OPC_CheckPredicate, 62, 138, 49, 0, // Skip to: 17098
/* 4416 */    MCD_OPC_CheckField, 11, 5, 0, 131, 49, 0, // Skip to: 17098
/* 4423 */    MCD_OPC_Decode, 196, 15, 238, 1, // Opcode: LDXC1
/* 4428 */    MCD_OPC_FilterValue, 5, 17, 0, 0, // Skip to: 4450
/* 4433 */    MCD_OPC_CheckPredicate, 63, 116, 49, 0, // Skip to: 17098
/* 4438 */    MCD_OPC_CheckField, 11, 5, 0, 109, 49, 0, // Skip to: 17098
/* 4445 */    MCD_OPC_Decode, 253, 15, 238, 1, // Opcode: LUXC1
/* 4450 */    MCD_OPC_FilterValue, 8, 17, 0, 0, // Skip to: 4472
/* 4455 */    MCD_OPC_CheckPredicate, 61, 94, 49, 0, // Skip to: 17098
/* 4460 */    MCD_OPC_CheckField, 6, 5, 0, 87, 49, 0, // Skip to: 17098
/* 4467 */    MCD_OPC_Decode, 165, 23, 239, 1, // Opcode: SWXC1
/* 4472 */    MCD_OPC_FilterValue, 9, 17, 0, 0, // Skip to: 4494
/* 4477 */    MCD_OPC_CheckPredicate, 62, 72, 49, 0, // Skip to: 17098
/* 4482 */    MCD_OPC_CheckField, 6, 5, 0, 65, 49, 0, // Skip to: 17098
/* 4489 */    MCD_OPC_Decode, 240, 20, 240, 1, // Opcode: SDXC1
/* 4494 */    MCD_OPC_FilterValue, 13, 17, 0, 0, // Skip to: 4516
/* 4499 */    MCD_OPC_CheckPredicate, 63, 50, 49, 0, // Skip to: 17098
/* 4504 */    MCD_OPC_CheckField, 6, 5, 0, 43, 49, 0, // Skip to: 17098
/* 4511 */    MCD_OPC_Decode, 253, 22, 240, 1, // Opcode: SUXC1
/* 4516 */    MCD_OPC_FilterValue, 32, 10, 0, 0, // Skip to: 4531
/* 4521 */    MCD_OPC_CheckPredicate, 64, 28, 49, 0, // Skip to: 17098
/* 4526 */    MCD_OPC_Decode, 218, 16, 241, 1, // Opcode: MADD_S
/* 4531 */    MCD_OPC_FilterValue, 33, 10, 0, 0, // Skip to: 4546
/* 4536 */    MCD_OPC_CheckPredicate, 65, 13, 49, 0, // Skip to: 17098
/* 4541 */    MCD_OPC_Decode, 210, 16, 242, 1, // Opcode: MADD_D32
/* 4546 */    MCD_OPC_FilterValue, 40, 10, 0, 0, // Skip to: 4561
/* 4551 */    MCD_OPC_CheckPredicate, 64, 254, 48, 0, // Skip to: 17098
/* 4556 */    MCD_OPC_Decode, 154, 18, 241, 1, // Opcode: MSUB_S
/* 4561 */    MCD_OPC_FilterValue, 41, 10, 0, 0, // Skip to: 4576
/* 4566 */    MCD_OPC_CheckPredicate, 65, 239, 48, 0, // Skip to: 17098
/* 4571 */    MCD_OPC_Decode, 146, 18, 242, 1, // Opcode: MSUB_D32
/* 4576 */    MCD_OPC_FilterValue, 48, 10, 0, 0, // Skip to: 4591
/* 4581 */    MCD_OPC_CheckPredicate, 66, 224, 48, 0, // Skip to: 17098
/* 4586 */    MCD_OPC_Decode, 142, 19, 241, 1, // Opcode: NMADD_S
/* 4591 */    MCD_OPC_FilterValue, 49, 10, 0, 0, // Skip to: 4606
/* 4596 */    MCD_OPC_CheckPredicate, 67, 209, 48, 0, // Skip to: 17098
/* 4601 */    MCD_OPC_Decode, 139, 19, 242, 1, // Opcode: NMADD_D32
/* 4606 */    MCD_OPC_FilterValue, 56, 10, 0, 0, // Skip to: 4621
/* 4611 */    MCD_OPC_CheckPredicate, 66, 194, 48, 0, // Skip to: 17098
/* 4616 */    MCD_OPC_Decode, 147, 19, 241, 1, // Opcode: NMSUB_S
/* 4621 */    MCD_OPC_FilterValue, 57, 184, 48, 0, // Skip to: 17098
/* 4626 */    MCD_OPC_CheckPredicate, 67, 179, 48, 0, // Skip to: 17098
/* 4631 */    MCD_OPC_Decode, 144, 19, 242, 1, // Opcode: NMSUB_D32
/* 4636 */    MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 4651
/* 4641 */    MCD_OPC_CheckPredicate, 39, 164, 48, 0, // Skip to: 17098
/* 4646 */    MCD_OPC_Decode, 197, 7, 201, 1, // Opcode: BEQL
/* 4651 */    MCD_OPC_FilterValue, 21, 107, 0, 0, // Skip to: 4763
/* 4656 */    MCD_OPC_ExtractField, 0, 16,  // Inst{15-0} ...
/* 4659 */    MCD_OPC_FilterValue, 123, 9, 0, 0, // Skip to: 4673
/* 4664 */    MCD_OPC_CheckPredicate, 19, 19, 0, 0, // Skip to: 4688
/* 4669 */    MCD_OPC_Decode, 233, 13, 124, // Opcode: FMOV_S_MM
/* 4673 */    MCD_OPC_FilterValue, 251, 22, 9, 0, 0, // Skip to: 4688
/* 4679 */    MCD_OPC_CheckPredicate, 19, 4, 0, 0, // Skip to: 4688
/* 4684 */    MCD_OPC_Decode, 252, 13, 124, // Opcode: FNEG_S_MM
/* 4688 */    MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 4691 */    MCD_OPC_FilterValue, 48, 10, 0, 0, // Skip to: 4706
/* 4696 */    MCD_OPC_CheckPredicate, 19, 52, 0, 0, // Skip to: 4753
/* 4701 */    MCD_OPC_Decode, 143, 13, 164, 1, // Opcode: FADD_S_MM
/* 4706 */    MCD_OPC_FilterValue, 112, 10, 0, 0, // Skip to: 4721
/* 4711 */    MCD_OPC_CheckPredicate, 19, 37, 0, 0, // Skip to: 4753
/* 4716 */    MCD_OPC_Decode, 161, 14, 164, 1, // Opcode: FSUB_S_MM
/* 4721 */    MCD_OPC_FilterValue, 176, 1, 10, 0, 0, // Skip to: 4737
/* 4727 */    MCD_OPC_CheckPredicate, 19, 21, 0, 0, // Skip to: 4753
/* 4732 */    MCD_OPC_Decode, 244, 13, 164, 1, // Opcode: FMUL_S_MM
/* 4737 */    MCD_OPC_FilterValue, 240, 1, 10, 0, 0, // Skip to: 4753
/* 4743 */    MCD_OPC_CheckPredicate, 19, 5, 0, 0, // Skip to: 4753
/* 4748 */    MCD_OPC_Decode, 181, 13, 164, 1, // Opcode: FDIV_S_MM
/* 4753 */    MCD_OPC_CheckPredicate, 39, 52, 48, 0, // Skip to: 17098
/* 4758 */    MCD_OPC_Decode, 187, 8, 201, 1, // Opcode: BNEL
/* 4763 */    MCD_OPC_FilterValue, 22, 17, 0, 0, // Skip to: 4785
/* 4768 */    MCD_OPC_CheckPredicate, 39, 37, 48, 0, // Skip to: 17098
/* 4773 */    MCD_OPC_CheckField, 16, 5, 0, 30, 48, 0, // Skip to: 17098
/* 4780 */    MCD_OPC_Decode, 141, 8, 197, 1, // Opcode: BLEZL
/* 4785 */    MCD_OPC_FilterValue, 23, 17, 0, 0, // Skip to: 4807
/* 4790 */    MCD_OPC_CheckPredicate, 39, 15, 48, 0, // Skip to: 17098
/* 4795 */    MCD_OPC_CheckField, 16, 5, 0, 8, 48, 0, // Skip to: 17098
/* 4802 */    MCD_OPC_Decode, 239, 7, 197, 1, // Opcode: BGTZL
/* 4807 */    MCD_OPC_FilterValue, 28, 15, 1, 0, // Skip to: 5083
/* 4812 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 4815 */    MCD_OPC_FilterValue, 0, 42, 0, 0, // Skip to: 4862
/* 4820 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 4823 */    MCD_OPC_FilterValue, 0, 238, 47, 0, // Skip to: 17098
/* 4828 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 4831 */    MCD_OPC_FilterValue, 0, 230, 47, 0, // Skip to: 17098
/* 4836 */    MCD_OPC_CheckPredicate, 68, 11, 0, 0, // Skip to: 4852
/* 4841 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 4852
/* 4848 */    MCD_OPC_Decode, 195, 16, 80, // Opcode: MADD
/* 4852 */    MCD_OPC_CheckPredicate, 37, 209, 47, 0, // Skip to: 17098
/* 4857 */    MCD_OPC_Decode, 213, 16, 243, 1, // Opcode: MADD_DSP
/* 4862 */    MCD_OPC_FilterValue, 1, 42, 0, 0, // Skip to: 4909
/* 4867 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 4870 */    MCD_OPC_FilterValue, 0, 191, 47, 0, // Skip to: 17098
/* 4875 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 4878 */    MCD_OPC_FilterValue, 0, 183, 47, 0, // Skip to: 17098
/* 4883 */    MCD_OPC_CheckPredicate, 68, 11, 0, 0, // Skip to: 4899
/* 4888 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 4899
/* 4895 */    MCD_OPC_Decode, 202, 16, 80, // Opcode: MADDU
/* 4899 */    MCD_OPC_CheckPredicate, 37, 162, 47, 0, // Skip to: 17098
/* 4904 */    MCD_OPC_Decode, 203, 16, 243, 1, // Opcode: MADDU_DSP
/* 4909 */    MCD_OPC_FilterValue, 2, 16, 0, 0, // Skip to: 4930
/* 4914 */    MCD_OPC_CheckPredicate, 68, 147, 47, 0, // Skip to: 17098
/* 4919 */    MCD_OPC_CheckField, 6, 5, 0, 140, 47, 0, // Skip to: 17098
/* 4926 */    MCD_OPC_Decode, 205, 18, 61, // Opcode: MUL
/* 4930 */    MCD_OPC_FilterValue, 4, 42, 0, 0, // Skip to: 4977
/* 4935 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 4938 */    MCD_OPC_FilterValue, 0, 123, 47, 0, // Skip to: 17098
/* 4943 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 4946 */    MCD_OPC_FilterValue, 0, 115, 47, 0, // Skip to: 17098
/* 4951 */    MCD_OPC_CheckPredicate, 68, 11, 0, 0, // Skip to: 4967
/* 4956 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 4967
/* 4963 */    MCD_OPC_Decode, 131, 18, 80, // Opcode: MSUB
/* 4967 */    MCD_OPC_CheckPredicate, 37, 94, 47, 0, // Skip to: 17098
/* 4972 */    MCD_OPC_Decode, 149, 18, 243, 1, // Opcode: MSUB_DSP
/* 4977 */    MCD_OPC_FilterValue, 5, 42, 0, 0, // Skip to: 5024
/* 4982 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 4985 */    MCD_OPC_FilterValue, 0, 76, 47, 0, // Skip to: 17098
/* 4990 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 4993 */    MCD_OPC_FilterValue, 0, 68, 47, 0, // Skip to: 17098
/* 4998 */    MCD_OPC_CheckPredicate, 68, 11, 0, 0, // Skip to: 5014
/* 5003 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 5014
/* 5010 */    MCD_OPC_Decode, 138, 18, 80, // Opcode: MSUBU
/* 5014 */    MCD_OPC_CheckPredicate, 37, 47, 47, 0, // Skip to: 17098
/* 5019 */    MCD_OPC_Decode, 139, 18, 243, 1, // Opcode: MSUBU_DSP
/* 5024 */    MCD_OPC_FilterValue, 32, 17, 0, 0, // Skip to: 5046
/* 5029 */    MCD_OPC_CheckPredicate, 68, 32, 47, 0, // Skip to: 17098
/* 5034 */    MCD_OPC_CheckField, 6, 5, 0, 25, 47, 0, // Skip to: 17098
/* 5041 */    MCD_OPC_Decode, 193, 9, 244, 1, // Opcode: CLZ
/* 5046 */    MCD_OPC_FilterValue, 33, 17, 0, 0, // Skip to: 5068
/* 5051 */    MCD_OPC_CheckPredicate, 68, 10, 47, 0, // Skip to: 17098
/* 5056 */    MCD_OPC_CheckField, 6, 5, 0, 3, 47, 0, // Skip to: 17098
/* 5063 */    MCD_OPC_Decode, 172, 9, 244, 1, // Opcode: CLO
/* 5068 */    MCD_OPC_FilterValue, 63, 249, 46, 0, // Skip to: 17098
/* 5073 */    MCD_OPC_CheckPredicate, 68, 244, 46, 0, // Skip to: 17098
/* 5078 */    MCD_OPC_Decode, 219, 20, 188, 1, // Opcode: SDBBP
/* 5083 */    MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 5098
/* 5088 */    MCD_OPC_CheckPredicate, 68, 229, 46, 0, // Skip to: 17098
/* 5093 */    MCD_OPC_Decode, 251, 14, 200, 1, // Opcode: JALX
/* 5098 */    MCD_OPC_FilterValue, 30, 201, 32, 0, // Skip to: 13496
/* 5103 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 5106 */    MCD_OPC_FilterValue, 0, 63, 0, 0, // Skip to: 5174
/* 5111 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 5114 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 5129
/* 5119 */    MCD_OPC_CheckPredicate, 30, 198, 46, 0, // Skip to: 17098
/* 5124 */    MCD_OPC_Decode, 224, 6, 245, 1, // Opcode: ANDI_B
/* 5129 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 5144
/* 5134 */    MCD_OPC_CheckPredicate, 30, 183, 46, 0, // Skip to: 17098
/* 5139 */    MCD_OPC_Decode, 168, 19, 245, 1, // Opcode: ORI_B
/* 5144 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 5159
/* 5149 */    MCD_OPC_CheckPredicate, 30, 168, 46, 0, // Skip to: 17098
/* 5154 */    MCD_OPC_Decode, 153, 19, 245, 1, // Opcode: NORI_B
/* 5159 */    MCD_OPC_FilterValue, 3, 158, 46, 0, // Skip to: 17098
/* 5164 */    MCD_OPC_CheckPredicate, 30, 153, 46, 0, // Skip to: 17098
/* 5169 */    MCD_OPC_Decode, 177, 24, 245, 1, // Opcode: XORI_B
/* 5174 */    MCD_OPC_FilterValue, 1, 48, 0, 0, // Skip to: 5227
/* 5179 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 5182 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 5197
/* 5187 */    MCD_OPC_CheckPredicate, 30, 130, 46, 0, // Skip to: 17098
/* 5192 */    MCD_OPC_Decode, 166, 8, 246, 1, // Opcode: BMNZI_B
/* 5197 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 5212
/* 5202 */    MCD_OPC_CheckPredicate, 30, 115, 46, 0, // Skip to: 17098
/* 5207 */    MCD_OPC_Decode, 168, 8, 246, 1, // Opcode: BMZI_B
/* 5212 */    MCD_OPC_FilterValue, 2, 105, 46, 0, // Skip to: 17098
/* 5217 */    MCD_OPC_CheckPredicate, 30, 100, 46, 0, // Skip to: 17098
/* 5222 */    MCD_OPC_Decode, 219, 8, 246, 1, // Opcode: BSELI_B
/* 5227 */    MCD_OPC_FilterValue, 2, 48, 0, 0, // Skip to: 5280
/* 5232 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 5235 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 5250
/* 5240 */    MCD_OPC_CheckPredicate, 30, 77, 46, 0, // Skip to: 17098
/* 5245 */    MCD_OPC_Decode, 150, 21, 245, 1, // Opcode: SHF_B
/* 5250 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 5265
/* 5255 */    MCD_OPC_CheckPredicate, 30, 62, 46, 0, // Skip to: 17098
/* 5260 */    MCD_OPC_Decode, 151, 21, 247, 1, // Opcode: SHF_H
/* 5265 */    MCD_OPC_FilterValue, 2, 52, 46, 0, // Skip to: 17098
/* 5270 */    MCD_OPC_CheckPredicate, 30, 47, 46, 0, // Skip to: 17098
/* 5275 */    MCD_OPC_Decode, 152, 21, 248, 1, // Opcode: SHF_W
/* 5280 */    MCD_OPC_FilterValue, 6, 107, 1, 0, // Skip to: 5648
/* 5285 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5288 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 5303
/* 5293 */    MCD_OPC_CheckPredicate, 30, 24, 46, 0, // Skip to: 17098
/* 5298 */    MCD_OPC_Decode, 185, 6, 249, 1, // Opcode: ADDVI_B
/* 5303 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 5318
/* 5308 */    MCD_OPC_CheckPredicate, 30, 9, 46, 0, // Skip to: 17098
/* 5313 */    MCD_OPC_Decode, 187, 6, 250, 1, // Opcode: ADDVI_H
/* 5318 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 5333
/* 5323 */    MCD_OPC_CheckPredicate, 30, 250, 45, 0, // Skip to: 17098
/* 5328 */    MCD_OPC_Decode, 188, 6, 251, 1, // Opcode: ADDVI_W
/* 5333 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 5348
/* 5338 */    MCD_OPC_CheckPredicate, 30, 235, 45, 0, // Skip to: 17098
/* 5343 */    MCD_OPC_Decode, 186, 6, 252, 1, // Opcode: ADDVI_D
/* 5348 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 5363
/* 5353 */    MCD_OPC_CheckPredicate, 30, 220, 45, 0, // Skip to: 17098
/* 5358 */    MCD_OPC_Decode, 238, 22, 249, 1, // Opcode: SUBVI_B
/* 5363 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 5378
/* 5368 */    MCD_OPC_CheckPredicate, 30, 205, 45, 0, // Skip to: 17098
/* 5373 */    MCD_OPC_Decode, 240, 22, 250, 1, // Opcode: SUBVI_H
/* 5378 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 5393
/* 5383 */    MCD_OPC_CheckPredicate, 30, 190, 45, 0, // Skip to: 17098
/* 5388 */    MCD_OPC_Decode, 241, 22, 251, 1, // Opcode: SUBVI_W
/* 5393 */    MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 5408
/* 5398 */    MCD_OPC_CheckPredicate, 30, 175, 45, 0, // Skip to: 17098
/* 5403 */    MCD_OPC_Decode, 239, 22, 252, 1, // Opcode: SUBVI_D
/* 5408 */    MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 5423
/* 5413 */    MCD_OPC_CheckPredicate, 30, 160, 45, 0, // Skip to: 17098
/* 5418 */    MCD_OPC_Decode, 232, 16, 249, 1, // Opcode: MAXI_S_B
/* 5423 */    MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 5438
/* 5428 */    MCD_OPC_CheckPredicate, 30, 145, 45, 0, // Skip to: 17098
/* 5433 */    MCD_OPC_Decode, 234, 16, 250, 1, // Opcode: MAXI_S_H
/* 5438 */    MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 5453
/* 5443 */    MCD_OPC_CheckPredicate, 30, 130, 45, 0, // Skip to: 17098
/* 5448 */    MCD_OPC_Decode, 235, 16, 251, 1, // Opcode: MAXI_S_W
/* 5453 */    MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 5468
/* 5458 */    MCD_OPC_CheckPredicate, 30, 115, 45, 0, // Skip to: 17098
/* 5463 */    MCD_OPC_Decode, 233, 16, 252, 1, // Opcode: MAXI_S_D
/* 5468 */    MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 5483
/* 5473 */    MCD_OPC_CheckPredicate, 30, 100, 45, 0, // Skip to: 17098
/* 5478 */    MCD_OPC_Decode, 236, 16, 249, 1, // Opcode: MAXI_U_B
/* 5483 */    MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 5498
/* 5488 */    MCD_OPC_CheckPredicate, 30, 85, 45, 0, // Skip to: 17098
/* 5493 */    MCD_OPC_Decode, 238, 16, 250, 1, // Opcode: MAXI_U_H
/* 5498 */    MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 5513
/* 5503 */    MCD_OPC_CheckPredicate, 30, 70, 45, 0, // Skip to: 17098
/* 5508 */    MCD_OPC_Decode, 239, 16, 251, 1, // Opcode: MAXI_U_W
/* 5513 */    MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 5528
/* 5518 */    MCD_OPC_CheckPredicate, 30, 55, 45, 0, // Skip to: 17098
/* 5523 */    MCD_OPC_Decode, 237, 16, 252, 1, // Opcode: MAXI_U_D
/* 5528 */    MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 5543
/* 5533 */    MCD_OPC_CheckPredicate, 30, 40, 45, 0, // Skip to: 17098
/* 5538 */    MCD_OPC_Decode, 168, 17, 249, 1, // Opcode: MINI_S_B
/* 5543 */    MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 5558
/* 5548 */    MCD_OPC_CheckPredicate, 30, 25, 45, 0, // Skip to: 17098
/* 5553 */    MCD_OPC_Decode, 170, 17, 250, 1, // Opcode: MINI_S_H
/* 5558 */    MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 5573
/* 5563 */    MCD_OPC_CheckPredicate, 30, 10, 45, 0, // Skip to: 17098
/* 5568 */    MCD_OPC_Decode, 171, 17, 251, 1, // Opcode: MINI_S_W
/* 5573 */    MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 5588
/* 5578 */    MCD_OPC_CheckPredicate, 30, 251, 44, 0, // Skip to: 17098
/* 5583 */    MCD_OPC_Decode, 169, 17, 252, 1, // Opcode: MINI_S_D
/* 5588 */    MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 5603
/* 5593 */    MCD_OPC_CheckPredicate, 30, 236, 44, 0, // Skip to: 17098
/* 5598 */    MCD_OPC_Decode, 172, 17, 249, 1, // Opcode: MINI_U_B
/* 5603 */    MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 5618
/* 5608 */    MCD_OPC_CheckPredicate, 30, 221, 44, 0, // Skip to: 17098
/* 5613 */    MCD_OPC_Decode, 174, 17, 250, 1, // Opcode: MINI_U_H
/* 5618 */    MCD_OPC_FilterValue, 22, 10, 0, 0, // Skip to: 5633
/* 5623 */    MCD_OPC_CheckPredicate, 30, 206, 44, 0, // Skip to: 17098
/* 5628 */    MCD_OPC_Decode, 175, 17, 251, 1, // Opcode: MINI_U_W
/* 5633 */    MCD_OPC_FilterValue, 23, 196, 44, 0, // Skip to: 17098
/* 5638 */    MCD_OPC_CheckPredicate, 30, 191, 44, 0, // Skip to: 17098
/* 5643 */    MCD_OPC_Decode, 173, 17, 252, 1, // Opcode: MINI_U_D
/* 5648 */    MCD_OPC_FilterValue, 7, 107, 1, 0, // Skip to: 6016
/* 5653 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5656 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 5671
/* 5661 */    MCD_OPC_CheckPredicate, 30, 168, 44, 0, // Skip to: 17098
/* 5666 */    MCD_OPC_Decode, 136, 9, 249, 1, // Opcode: CEQI_B
/* 5671 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 5686
/* 5676 */    MCD_OPC_CheckPredicate, 30, 153, 44, 0, // Skip to: 17098
/* 5681 */    MCD_OPC_Decode, 138, 9, 250, 1, // Opcode: CEQI_H
/* 5686 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 5701
/* 5691 */    MCD_OPC_CheckPredicate, 30, 138, 44, 0, // Skip to: 17098
/* 5696 */    MCD_OPC_Decode, 139, 9, 251, 1, // Opcode: CEQI_W
/* 5701 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 5716
/* 5706 */    MCD_OPC_CheckPredicate, 30, 123, 44, 0, // Skip to: 17098
/* 5711 */    MCD_OPC_Decode, 137, 9, 252, 1, // Opcode: CEQI_D
/* 5716 */    MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 5731
/* 5721 */    MCD_OPC_CheckPredicate, 30, 108, 44, 0, // Skip to: 17098
/* 5726 */    MCD_OPC_Decode, 177, 9, 249, 1, // Opcode: CLTI_S_B
/* 5731 */    MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 5746
/* 5736 */    MCD_OPC_CheckPredicate, 30, 93, 44, 0, // Skip to: 17098
/* 5741 */    MCD_OPC_Decode, 179, 9, 250, 1, // Opcode: CLTI_S_H
/* 5746 */    MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 5761
/* 5751 */    MCD_OPC_CheckPredicate, 30, 78, 44, 0, // Skip to: 17098
/* 5756 */    MCD_OPC_Decode, 180, 9, 251, 1, // Opcode: CLTI_S_W
/* 5761 */    MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 5776
/* 5766 */    MCD_OPC_CheckPredicate, 30, 63, 44, 0, // Skip to: 17098
/* 5771 */    MCD_OPC_Decode, 178, 9, 252, 1, // Opcode: CLTI_S_D
/* 5776 */    MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 5791
/* 5781 */    MCD_OPC_CheckPredicate, 30, 48, 44, 0, // Skip to: 17098
/* 5786 */    MCD_OPC_Decode, 181, 9, 249, 1, // Opcode: CLTI_U_B
/* 5791 */    MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 5806
/* 5796 */    MCD_OPC_CheckPredicate, 30, 33, 44, 0, // Skip to: 17098
/* 5801 */    MCD_OPC_Decode, 183, 9, 250, 1, // Opcode: CLTI_U_H
/* 5806 */    MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 5821
/* 5811 */    MCD_OPC_CheckPredicate, 30, 18, 44, 0, // Skip to: 17098
/* 5816 */    MCD_OPC_Decode, 184, 9, 251, 1, // Opcode: CLTI_U_W
/* 5821 */    MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 5836
/* 5826 */    MCD_OPC_CheckPredicate, 30, 3, 44, 0, // Skip to: 17098
/* 5831 */    MCD_OPC_Decode, 182, 9, 252, 1, // Opcode: CLTI_U_D
/* 5836 */    MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 5851
/* 5841 */    MCD_OPC_CheckPredicate, 30, 244, 43, 0, // Skip to: 17098
/* 5846 */    MCD_OPC_Decode, 156, 9, 249, 1, // Opcode: CLEI_S_B
/* 5851 */    MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 5866
/* 5856 */    MCD_OPC_CheckPredicate, 30, 229, 43, 0, // Skip to: 17098
/* 5861 */    MCD_OPC_Decode, 158, 9, 250, 1, // Opcode: CLEI_S_H
/* 5866 */    MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 5881
/* 5871 */    MCD_OPC_CheckPredicate, 30, 214, 43, 0, // Skip to: 17098
/* 5876 */    MCD_OPC_Decode, 159, 9, 251, 1, // Opcode: CLEI_S_W
/* 5881 */    MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 5896
/* 5886 */    MCD_OPC_CheckPredicate, 30, 199, 43, 0, // Skip to: 17098
/* 5891 */    MCD_OPC_Decode, 157, 9, 252, 1, // Opcode: CLEI_S_D
/* 5896 */    MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 5911
/* 5901 */    MCD_OPC_CheckPredicate, 30, 184, 43, 0, // Skip to: 17098
/* 5906 */    MCD_OPC_Decode, 160, 9, 249, 1, // Opcode: CLEI_U_B
/* 5911 */    MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 5926
/* 5916 */    MCD_OPC_CheckPredicate, 30, 169, 43, 0, // Skip to: 17098
/* 5921 */    MCD_OPC_Decode, 162, 9, 250, 1, // Opcode: CLEI_U_H
/* 5926 */    MCD_OPC_FilterValue, 22, 10, 0, 0, // Skip to: 5941
/* 5931 */    MCD_OPC_CheckPredicate, 30, 154, 43, 0, // Skip to: 17098
/* 5936 */    MCD_OPC_Decode, 163, 9, 251, 1, // Opcode: CLEI_U_W
/* 5941 */    MCD_OPC_FilterValue, 23, 10, 0, 0, // Skip to: 5956
/* 5946 */    MCD_OPC_CheckPredicate, 30, 139, 43, 0, // Skip to: 17098
/* 5951 */    MCD_OPC_Decode, 161, 9, 252, 1, // Opcode: CLEI_U_D
/* 5956 */    MCD_OPC_FilterValue, 24, 10, 0, 0, // Skip to: 5971
/* 5961 */    MCD_OPC_CheckPredicate, 30, 124, 43, 0, // Skip to: 17098
/* 5966 */    MCD_OPC_Decode, 189, 15, 253, 1, // Opcode: LDI_B
/* 5971 */    MCD_OPC_FilterValue, 25, 10, 0, 0, // Skip to: 5986
/* 5976 */    MCD_OPC_CheckPredicate, 30, 109, 43, 0, // Skip to: 17098
/* 5981 */    MCD_OPC_Decode, 191, 15, 254, 1, // Opcode: LDI_H
/* 5986 */    MCD_OPC_FilterValue, 26, 10, 0, 0, // Skip to: 6001
/* 5991 */    MCD_OPC_CheckPredicate, 30, 94, 43, 0, // Skip to: 17098
/* 5996 */    MCD_OPC_Decode, 192, 15, 255, 1, // Opcode: LDI_W
/* 6001 */    MCD_OPC_FilterValue, 27, 84, 43, 0, // Skip to: 17098
/* 6006 */    MCD_OPC_CheckPredicate, 30, 79, 43, 0, // Skip to: 17098
/* 6011 */    MCD_OPC_Decode, 190, 15, 128, 2, // Opcode: LDI_D
/* 6016 */    MCD_OPC_FilterValue, 9, 155, 2, 0, // Skip to: 6688
/* 6021 */    MCD_OPC_ExtractField, 22, 4,  // Inst{25-22} ...
/* 6024 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6039
/* 6029 */    MCD_OPC_CheckPredicate, 30, 56, 43, 0, // Skip to: 17098
/* 6034 */    MCD_OPC_Decode, 226, 21, 129, 2, // Opcode: SLLI_D
/* 6039 */    MCD_OPC_FilterValue, 1, 63, 0, 0, // Skip to: 6107
/* 6044 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 6047 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6062
/* 6052 */    MCD_OPC_CheckPredicate, 30, 33, 43, 0, // Skip to: 17098
/* 6057 */    MCD_OPC_Decode, 228, 21, 251, 1, // Opcode: SLLI_W
/* 6062 */    MCD_OPC_FilterValue, 1, 23, 43, 0, // Skip to: 17098
/* 6067 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 6070 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6085
/* 6075 */    MCD_OPC_CheckPredicate, 30, 10, 43, 0, // Skip to: 17098
/* 6080 */    MCD_OPC_Decode, 227, 21, 130, 2, // Opcode: SLLI_H
/* 6085 */    MCD_OPC_FilterValue, 1, 0, 43, 0, // Skip to: 17098
/* 6090 */    MCD_OPC_CheckPredicate, 30, 251, 42, 0, // Skip to: 17098
/* 6095 */    MCD_OPC_CheckField, 19, 1, 0, 244, 42, 0, // Skip to: 17098
/* 6102 */    MCD_OPC_Decode, 225, 21, 131, 2, // Opcode: SLLI_B
/* 6107 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 6122
/* 6112 */    MCD_OPC_CheckPredicate, 30, 229, 42, 0, // Skip to: 17098
/* 6117 */    MCD_OPC_Decode, 140, 22, 129, 2, // Opcode: SRAI_D
/* 6122 */    MCD_OPC_FilterValue, 3, 63, 0, 0, // Skip to: 6190
/* 6127 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 6130 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6145
/* 6135 */    MCD_OPC_CheckPredicate, 30, 206, 42, 0, // Skip to: 17098
/* 6140 */    MCD_OPC_Decode, 142, 22, 251, 1, // Opcode: SRAI_W
/* 6145 */    MCD_OPC_FilterValue, 1, 196, 42, 0, // Skip to: 17098
/* 6150 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 6153 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6168
/* 6158 */    MCD_OPC_CheckPredicate, 30, 183, 42, 0, // Skip to: 17098
/* 6163 */    MCD_OPC_Decode, 141, 22, 130, 2, // Opcode: SRAI_H
/* 6168 */    MCD_OPC_FilterValue, 1, 173, 42, 0, // Skip to: 17098
/* 6173 */    MCD_OPC_CheckPredicate, 30, 168, 42, 0, // Skip to: 17098
/* 6178 */    MCD_OPC_CheckField, 19, 1, 0, 161, 42, 0, // Skip to: 17098
/* 6185 */    MCD_OPC_Decode, 139, 22, 131, 2, // Opcode: SRAI_B
/* 6190 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 6205
/* 6195 */    MCD_OPC_CheckPredicate, 30, 146, 42, 0, // Skip to: 17098
/* 6200 */    MCD_OPC_Decode, 165, 22, 129, 2, // Opcode: SRLI_D
/* 6205 */    MCD_OPC_FilterValue, 5, 63, 0, 0, // Skip to: 6273
/* 6210 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 6213 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6228
/* 6218 */    MCD_OPC_CheckPredicate, 30, 123, 42, 0, // Skip to: 17098
/* 6223 */    MCD_OPC_Decode, 167, 22, 251, 1, // Opcode: SRLI_W
/* 6228 */    MCD_OPC_FilterValue, 1, 113, 42, 0, // Skip to: 17098
/* 6233 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 6236 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6251
/* 6241 */    MCD_OPC_CheckPredicate, 30, 100, 42, 0, // Skip to: 17098
/* 6246 */    MCD_OPC_Decode, 166, 22, 130, 2, // Opcode: SRLI_H
/* 6251 */    MCD_OPC_FilterValue, 1, 90, 42, 0, // Skip to: 17098
/* 6256 */    MCD_OPC_CheckPredicate, 30, 85, 42, 0, // Skip to: 17098
/* 6261 */    MCD_OPC_CheckField, 19, 1, 0, 78, 42, 0, // Skip to: 17098
/* 6268 */    MCD_OPC_Decode, 164, 22, 131, 2, // Opcode: SRLI_B
/* 6273 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 6288
/* 6278 */    MCD_OPC_CheckPredicate, 30, 63, 42, 0, // Skip to: 17098
/* 6283 */    MCD_OPC_Decode, 179, 7, 129, 2, // Opcode: BCLRI_D
/* 6288 */    MCD_OPC_FilterValue, 7, 63, 0, 0, // Skip to: 6356
/* 6293 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 6296 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6311
/* 6301 */    MCD_OPC_CheckPredicate, 30, 40, 42, 0, // Skip to: 17098
/* 6306 */    MCD_OPC_Decode, 181, 7, 251, 1, // Opcode: BCLRI_W
/* 6311 */    MCD_OPC_FilterValue, 1, 30, 42, 0, // Skip to: 17098
/* 6316 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 6319 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6334
/* 6324 */    MCD_OPC_CheckPredicate, 30, 17, 42, 0, // Skip to: 17098
/* 6329 */    MCD_OPC_Decode, 180, 7, 130, 2, // Opcode: BCLRI_H
/* 6334 */    MCD_OPC_FilterValue, 1, 7, 42, 0, // Skip to: 17098
/* 6339 */    MCD_OPC_CheckPredicate, 30, 2, 42, 0, // Skip to: 17098
/* 6344 */    MCD_OPC_CheckField, 19, 1, 0, 251, 41, 0, // Skip to: 17098
/* 6351 */    MCD_OPC_Decode, 178, 7, 131, 2, // Opcode: BCLRI_B
/* 6356 */    MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 6371
/* 6361 */    MCD_OPC_CheckPredicate, 30, 236, 41, 0, // Skip to: 17098
/* 6366 */    MCD_OPC_Decode, 222, 8, 129, 2, // Opcode: BSETI_D
/* 6371 */    MCD_OPC_FilterValue, 9, 63, 0, 0, // Skip to: 6439
/* 6376 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 6379 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6394
/* 6384 */    MCD_OPC_CheckPredicate, 30, 213, 41, 0, // Skip to: 17098
/* 6389 */    MCD_OPC_Decode, 224, 8, 251, 1, // Opcode: BSETI_W
/* 6394 */    MCD_OPC_FilterValue, 1, 203, 41, 0, // Skip to: 17098
/* 6399 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 6402 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6417
/* 6407 */    MCD_OPC_CheckPredicate, 30, 190, 41, 0, // Skip to: 17098
/* 6412 */    MCD_OPC_Decode, 223, 8, 130, 2, // Opcode: BSETI_H
/* 6417 */    MCD_OPC_FilterValue, 1, 180, 41, 0, // Skip to: 17098
/* 6422 */    MCD_OPC_CheckPredicate, 30, 175, 41, 0, // Skip to: 17098
/* 6427 */    MCD_OPC_CheckField, 19, 1, 0, 168, 41, 0, // Skip to: 17098
/* 6434 */    MCD_OPC_Decode, 221, 8, 131, 2, // Opcode: BSETI_B
/* 6439 */    MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 6454
/* 6444 */    MCD_OPC_CheckPredicate, 30, 153, 41, 0, // Skip to: 17098
/* 6449 */    MCD_OPC_Decode, 179, 8, 129, 2, // Opcode: BNEGI_D
/* 6454 */    MCD_OPC_FilterValue, 11, 63, 0, 0, // Skip to: 6522
/* 6459 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 6462 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6477
/* 6467 */    MCD_OPC_CheckPredicate, 30, 130, 41, 0, // Skip to: 17098
/* 6472 */    MCD_OPC_Decode, 181, 8, 251, 1, // Opcode: BNEGI_W
/* 6477 */    MCD_OPC_FilterValue, 1, 120, 41, 0, // Skip to: 17098
/* 6482 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 6485 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6500
/* 6490 */    MCD_OPC_CheckPredicate, 30, 107, 41, 0, // Skip to: 17098
/* 6495 */    MCD_OPC_Decode, 180, 8, 130, 2, // Opcode: BNEGI_H
/* 6500 */    MCD_OPC_FilterValue, 1, 97, 41, 0, // Skip to: 17098
/* 6505 */    MCD_OPC_CheckPredicate, 30, 92, 41, 0, // Skip to: 17098
/* 6510 */    MCD_OPC_CheckField, 19, 1, 0, 85, 41, 0, // Skip to: 17098
/* 6517 */    MCD_OPC_Decode, 178, 8, 131, 2, // Opcode: BNEGI_B
/* 6522 */    MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 6537
/* 6527 */    MCD_OPC_CheckPredicate, 30, 70, 41, 0, // Skip to: 17098
/* 6532 */    MCD_OPC_Decode, 242, 7, 132, 2, // Opcode: BINSLI_D
/* 6537 */    MCD_OPC_FilterValue, 13, 63, 0, 0, // Skip to: 6605
/* 6542 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 6545 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6560
/* 6550 */    MCD_OPC_CheckPredicate, 30, 47, 41, 0, // Skip to: 17098
/* 6555 */    MCD_OPC_Decode, 244, 7, 133, 2, // Opcode: BINSLI_W
/* 6560 */    MCD_OPC_FilterValue, 1, 37, 41, 0, // Skip to: 17098
/* 6565 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 6568 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6583
/* 6573 */    MCD_OPC_CheckPredicate, 30, 24, 41, 0, // Skip to: 17098
/* 6578 */    MCD_OPC_Decode, 243, 7, 134, 2, // Opcode: BINSLI_H
/* 6583 */    MCD_OPC_FilterValue, 1, 14, 41, 0, // Skip to: 17098
/* 6588 */    MCD_OPC_CheckPredicate, 30, 9, 41, 0, // Skip to: 17098
/* 6593 */    MCD_OPC_CheckField, 19, 1, 0, 2, 41, 0, // Skip to: 17098
/* 6600 */    MCD_OPC_Decode, 241, 7, 135, 2, // Opcode: BINSLI_B
/* 6605 */    MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 6620
/* 6610 */    MCD_OPC_CheckPredicate, 30, 243, 40, 0, // Skip to: 17098
/* 6615 */    MCD_OPC_Decode, 250, 7, 132, 2, // Opcode: BINSRI_D
/* 6620 */    MCD_OPC_FilterValue, 15, 233, 40, 0, // Skip to: 17098
/* 6625 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 6628 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6643
/* 6633 */    MCD_OPC_CheckPredicate, 30, 220, 40, 0, // Skip to: 17098
/* 6638 */    MCD_OPC_Decode, 252, 7, 133, 2, // Opcode: BINSRI_W
/* 6643 */    MCD_OPC_FilterValue, 1, 210, 40, 0, // Skip to: 17098
/* 6648 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 6651 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6666
/* 6656 */    MCD_OPC_CheckPredicate, 30, 197, 40, 0, // Skip to: 17098
/* 6661 */    MCD_OPC_Decode, 251, 7, 134, 2, // Opcode: BINSRI_H
/* 6666 */    MCD_OPC_FilterValue, 1, 187, 40, 0, // Skip to: 17098
/* 6671 */    MCD_OPC_CheckPredicate, 30, 182, 40, 0, // Skip to: 17098
/* 6676 */    MCD_OPC_CheckField, 19, 1, 0, 175, 40, 0, // Skip to: 17098
/* 6683 */    MCD_OPC_Decode, 249, 7, 135, 2, // Opcode: BINSRI_B
/* 6688 */    MCD_OPC_FilterValue, 10, 79, 1, 0, // Skip to: 7028
/* 6693 */    MCD_OPC_ExtractField, 22, 4,  // Inst{25-22} ...
/* 6696 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6711
/* 6701 */    MCD_OPC_CheckPredicate, 30, 152, 40, 0, // Skip to: 17098
/* 6706 */    MCD_OPC_Decode, 184, 20, 129, 2, // Opcode: SAT_S_D
/* 6711 */    MCD_OPC_FilterValue, 1, 63, 0, 0, // Skip to: 6779
/* 6716 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 6719 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6734
/* 6724 */    MCD_OPC_CheckPredicate, 30, 129, 40, 0, // Skip to: 17098
/* 6729 */    MCD_OPC_Decode, 186, 20, 251, 1, // Opcode: SAT_S_W
/* 6734 */    MCD_OPC_FilterValue, 1, 119, 40, 0, // Skip to: 17098
/* 6739 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 6742 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6757
/* 6747 */    MCD_OPC_CheckPredicate, 30, 106, 40, 0, // Skip to: 17098
/* 6752 */    MCD_OPC_Decode, 185, 20, 130, 2, // Opcode: SAT_S_H
/* 6757 */    MCD_OPC_FilterValue, 1, 96, 40, 0, // Skip to: 17098
/* 6762 */    MCD_OPC_CheckPredicate, 30, 91, 40, 0, // Skip to: 17098
/* 6767 */    MCD_OPC_CheckField, 19, 1, 0, 84, 40, 0, // Skip to: 17098
/* 6774 */    MCD_OPC_Decode, 183, 20, 131, 2, // Opcode: SAT_S_B
/* 6779 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 6794
/* 6784 */    MCD_OPC_CheckPredicate, 30, 69, 40, 0, // Skip to: 17098
/* 6789 */    MCD_OPC_Decode, 188, 20, 129, 2, // Opcode: SAT_U_D
/* 6794 */    MCD_OPC_FilterValue, 3, 63, 0, 0, // Skip to: 6862
/* 6799 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 6802 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6817
/* 6807 */    MCD_OPC_CheckPredicate, 30, 46, 40, 0, // Skip to: 17098
/* 6812 */    MCD_OPC_Decode, 190, 20, 251, 1, // Opcode: SAT_U_W
/* 6817 */    MCD_OPC_FilterValue, 1, 36, 40, 0, // Skip to: 17098
/* 6822 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 6825 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6840
/* 6830 */    MCD_OPC_CheckPredicate, 30, 23, 40, 0, // Skip to: 17098
/* 6835 */    MCD_OPC_Decode, 189, 20, 130, 2, // Opcode: SAT_U_H
/* 6840 */    MCD_OPC_FilterValue, 1, 13, 40, 0, // Skip to: 17098
/* 6845 */    MCD_OPC_CheckPredicate, 30, 8, 40, 0, // Skip to: 17098
/* 6850 */    MCD_OPC_CheckField, 19, 1, 0, 1, 40, 0, // Skip to: 17098
/* 6857 */    MCD_OPC_Decode, 187, 20, 131, 2, // Opcode: SAT_U_B
/* 6862 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 6877
/* 6867 */    MCD_OPC_CheckPredicate, 30, 242, 39, 0, // Skip to: 17098
/* 6872 */    MCD_OPC_Decode, 144, 22, 129, 2, // Opcode: SRARI_D
/* 6877 */    MCD_OPC_FilterValue, 5, 63, 0, 0, // Skip to: 6945
/* 6882 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 6885 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6900
/* 6890 */    MCD_OPC_CheckPredicate, 30, 219, 39, 0, // Skip to: 17098
/* 6895 */    MCD_OPC_Decode, 146, 22, 251, 1, // Opcode: SRARI_W
/* 6900 */    MCD_OPC_FilterValue, 1, 209, 39, 0, // Skip to: 17098
/* 6905 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 6908 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6923
/* 6913 */    MCD_OPC_CheckPredicate, 30, 196, 39, 0, // Skip to: 17098
/* 6918 */    MCD_OPC_Decode, 145, 22, 130, 2, // Opcode: SRARI_H
/* 6923 */    MCD_OPC_FilterValue, 1, 186, 39, 0, // Skip to: 17098
/* 6928 */    MCD_OPC_CheckPredicate, 30, 181, 39, 0, // Skip to: 17098
/* 6933 */    MCD_OPC_CheckField, 19, 1, 0, 174, 39, 0, // Skip to: 17098
/* 6940 */    MCD_OPC_Decode, 143, 22, 131, 2, // Opcode: SRARI_B
/* 6945 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 6960
/* 6950 */    MCD_OPC_CheckPredicate, 30, 159, 39, 0, // Skip to: 17098
/* 6955 */    MCD_OPC_Decode, 169, 22, 129, 2, // Opcode: SRLRI_D
/* 6960 */    MCD_OPC_FilterValue, 7, 149, 39, 0, // Skip to: 17098
/* 6965 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 6968 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 6983
/* 6973 */    MCD_OPC_CheckPredicate, 30, 136, 39, 0, // Skip to: 17098
/* 6978 */    MCD_OPC_Decode, 171, 22, 251, 1, // Opcode: SRLRI_W
/* 6983 */    MCD_OPC_FilterValue, 1, 126, 39, 0, // Skip to: 17098
/* 6988 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 6991 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 7006
/* 6996 */    MCD_OPC_CheckPredicate, 30, 113, 39, 0, // Skip to: 17098
/* 7001 */    MCD_OPC_Decode, 170, 22, 130, 2, // Opcode: SRLRI_H
/* 7006 */    MCD_OPC_FilterValue, 1, 103, 39, 0, // Skip to: 17098
/* 7011 */    MCD_OPC_CheckPredicate, 30, 98, 39, 0, // Skip to: 17098
/* 7016 */    MCD_OPC_CheckField, 19, 1, 0, 91, 39, 0, // Skip to: 17098
/* 7023 */    MCD_OPC_Decode, 168, 22, 131, 2, // Opcode: SRLRI_B
/* 7028 */    MCD_OPC_FilterValue, 13, 227, 1, 0, // Skip to: 7516
/* 7033 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 7036 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 7051
/* 7041 */    MCD_OPC_CheckPredicate, 30, 68, 39, 0, // Skip to: 17098
/* 7046 */    MCD_OPC_Decode, 232, 21, 136, 2, // Opcode: SLL_B
/* 7051 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 7066
/* 7056 */    MCD_OPC_CheckPredicate, 30, 53, 39, 0, // Skip to: 17098
/* 7061 */    MCD_OPC_Decode, 234, 21, 137, 2, // Opcode: SLL_H
/* 7066 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 7081
/* 7071 */    MCD_OPC_CheckPredicate, 30, 38, 39, 0, // Skip to: 17098
/* 7076 */    MCD_OPC_Decode, 238, 21, 138, 2, // Opcode: SLL_W
/* 7081 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 7096
/* 7086 */    MCD_OPC_CheckPredicate, 30, 23, 39, 0, // Skip to: 17098
/* 7091 */    MCD_OPC_Decode, 233, 21, 139, 2, // Opcode: SLL_D
/* 7096 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 7111
/* 7101 */    MCD_OPC_CheckPredicate, 30, 8, 39, 0, // Skip to: 17098
/* 7106 */    MCD_OPC_Decode, 154, 22, 136, 2, // Opcode: SRA_B
/* 7111 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 7126
/* 7116 */    MCD_OPC_CheckPredicate, 30, 249, 38, 0, // Skip to: 17098
/* 7121 */    MCD_OPC_Decode, 156, 22, 137, 2, // Opcode: SRA_H
/* 7126 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 7141
/* 7131 */    MCD_OPC_CheckPredicate, 30, 234, 38, 0, // Skip to: 17098
/* 7136 */    MCD_OPC_Decode, 159, 22, 138, 2, // Opcode: SRA_W
/* 7141 */    MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 7156
/* 7146 */    MCD_OPC_CheckPredicate, 30, 219, 38, 0, // Skip to: 17098
/* 7151 */    MCD_OPC_Decode, 155, 22, 139, 2, // Opcode: SRA_D
/* 7156 */    MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 7171
/* 7161 */    MCD_OPC_CheckPredicate, 30, 204, 38, 0, // Skip to: 17098
/* 7166 */    MCD_OPC_Decode, 179, 22, 136, 2, // Opcode: SRL_B
/* 7171 */    MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 7186
/* 7176 */    MCD_OPC_CheckPredicate, 30, 189, 38, 0, // Skip to: 17098
/* 7181 */    MCD_OPC_Decode, 181, 22, 137, 2, // Opcode: SRL_H
/* 7186 */    MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 7201
/* 7191 */    MCD_OPC_CheckPredicate, 30, 174, 38, 0, // Skip to: 17098
/* 7196 */    MCD_OPC_Decode, 184, 22, 138, 2, // Opcode: SRL_W
/* 7201 */    MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 7216
/* 7206 */    MCD_OPC_CheckPredicate, 30, 159, 38, 0, // Skip to: 17098
/* 7211 */    MCD_OPC_Decode, 180, 22, 139, 2, // Opcode: SRL_D
/* 7216 */    MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 7231
/* 7221 */    MCD_OPC_CheckPredicate, 30, 144, 38, 0, // Skip to: 17098
/* 7226 */    MCD_OPC_Decode, 182, 7, 136, 2, // Opcode: BCLR_B
/* 7231 */    MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 7246
/* 7236 */    MCD_OPC_CheckPredicate, 30, 129, 38, 0, // Skip to: 17098
/* 7241 */    MCD_OPC_Decode, 184, 7, 137, 2, // Opcode: BCLR_H
/* 7246 */    MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 7261
/* 7251 */    MCD_OPC_CheckPredicate, 30, 114, 38, 0, // Skip to: 17098
/* 7256 */    MCD_OPC_Decode, 185, 7, 138, 2, // Opcode: BCLR_W
/* 7261 */    MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 7276
/* 7266 */    MCD_OPC_CheckPredicate, 30, 99, 38, 0, // Skip to: 17098
/* 7271 */    MCD_OPC_Decode, 183, 7, 139, 2, // Opcode: BCLR_D
/* 7276 */    MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 7291
/* 7281 */    MCD_OPC_CheckPredicate, 30, 84, 38, 0, // Skip to: 17098
/* 7286 */    MCD_OPC_Decode, 225, 8, 136, 2, // Opcode: BSET_B
/* 7291 */    MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 7306
/* 7296 */    MCD_OPC_CheckPredicate, 30, 69, 38, 0, // Skip to: 17098
/* 7301 */    MCD_OPC_Decode, 227, 8, 137, 2, // Opcode: BSET_H
/* 7306 */    MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 7321
/* 7311 */    MCD_OPC_CheckPredicate, 30, 54, 38, 0, // Skip to: 17098
/* 7316 */    MCD_OPC_Decode, 228, 8, 138, 2, // Opcode: BSET_W
/* 7321 */    MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 7336
/* 7326 */    MCD_OPC_CheckPredicate, 30, 39, 38, 0, // Skip to: 17098
/* 7331 */    MCD_OPC_Decode, 226, 8, 139, 2, // Opcode: BSET_D
/* 7336 */    MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 7351
/* 7341 */    MCD_OPC_CheckPredicate, 30, 24, 38, 0, // Skip to: 17098
/* 7346 */    MCD_OPC_Decode, 182, 8, 136, 2, // Opcode: BNEG_B
/* 7351 */    MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 7366
/* 7356 */    MCD_OPC_CheckPredicate, 30, 9, 38, 0, // Skip to: 17098
/* 7361 */    MCD_OPC_Decode, 184, 8, 137, 2, // Opcode: BNEG_H
/* 7366 */    MCD_OPC_FilterValue, 22, 10, 0, 0, // Skip to: 7381
/* 7371 */    MCD_OPC_CheckPredicate, 30, 250, 37, 0, // Skip to: 17098
/* 7376 */    MCD_OPC_Decode, 185, 8, 138, 2, // Opcode: BNEG_W
/* 7381 */    MCD_OPC_FilterValue, 23, 10, 0, 0, // Skip to: 7396
/* 7386 */    MCD_OPC_CheckPredicate, 30, 235, 37, 0, // Skip to: 17098
/* 7391 */    MCD_OPC_Decode, 183, 8, 139, 2, // Opcode: BNEG_D
/* 7396 */    MCD_OPC_FilterValue, 24, 10, 0, 0, // Skip to: 7411
/* 7401 */    MCD_OPC_CheckPredicate, 30, 220, 37, 0, // Skip to: 17098
/* 7406 */    MCD_OPC_Decode, 245, 7, 140, 2, // Opcode: BINSL_B
/* 7411 */    MCD_OPC_FilterValue, 25, 10, 0, 0, // Skip to: 7426
/* 7416 */    MCD_OPC_CheckPredicate, 30, 205, 37, 0, // Skip to: 17098
/* 7421 */    MCD_OPC_Decode, 247, 7, 141, 2, // Opcode: BINSL_H
/* 7426 */    MCD_OPC_FilterValue, 26, 10, 0, 0, // Skip to: 7441
/* 7431 */    MCD_OPC_CheckPredicate, 30, 190, 37, 0, // Skip to: 17098
/* 7436 */    MCD_OPC_Decode, 248, 7, 142, 2, // Opcode: BINSL_W
/* 7441 */    MCD_OPC_FilterValue, 27, 10, 0, 0, // Skip to: 7456
/* 7446 */    MCD_OPC_CheckPredicate, 30, 175, 37, 0, // Skip to: 17098
/* 7451 */    MCD_OPC_Decode, 246, 7, 143, 2, // Opcode: BINSL_D
/* 7456 */    MCD_OPC_FilterValue, 28, 10, 0, 0, // Skip to: 7471
/* 7461 */    MCD_OPC_CheckPredicate, 30, 160, 37, 0, // Skip to: 17098
/* 7466 */    MCD_OPC_Decode, 253, 7, 140, 2, // Opcode: BINSR_B
/* 7471 */    MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 7486
/* 7476 */    MCD_OPC_CheckPredicate, 30, 145, 37, 0, // Skip to: 17098
/* 7481 */    MCD_OPC_Decode, 255, 7, 141, 2, // Opcode: BINSR_H
/* 7486 */    MCD_OPC_FilterValue, 30, 10, 0, 0, // Skip to: 7501
/* 7491 */    MCD_OPC_CheckPredicate, 30, 130, 37, 0, // Skip to: 17098
/* 7496 */    MCD_OPC_Decode, 128, 8, 142, 2, // Opcode: BINSR_W
/* 7501 */    MCD_OPC_FilterValue, 31, 120, 37, 0, // Skip to: 17098
/* 7506 */    MCD_OPC_CheckPredicate, 30, 115, 37, 0, // Skip to: 17098
/* 7511 */    MCD_OPC_Decode, 254, 7, 143, 2, // Opcode: BINSR_D
/* 7516 */    MCD_OPC_FilterValue, 14, 227, 1, 0, // Skip to: 8004
/* 7521 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 7524 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 7539
/* 7529 */    MCD_OPC_CheckPredicate, 30, 92, 37, 0, // Skip to: 17098
/* 7534 */    MCD_OPC_Decode, 189, 6, 136, 2, // Opcode: ADDV_B
/* 7539 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 7554
/* 7544 */    MCD_OPC_CheckPredicate, 30, 77, 37, 0, // Skip to: 17098
/* 7549 */    MCD_OPC_Decode, 191, 6, 137, 2, // Opcode: ADDV_H
/* 7554 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 7569
/* 7559 */    MCD_OPC_CheckPredicate, 30, 62, 37, 0, // Skip to: 17098
/* 7564 */    MCD_OPC_Decode, 192, 6, 138, 2, // Opcode: ADDV_W
/* 7569 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 7584
/* 7574 */    MCD_OPC_CheckPredicate, 30, 47, 37, 0, // Skip to: 17098
/* 7579 */    MCD_OPC_Decode, 190, 6, 139, 2, // Opcode: ADDV_D
/* 7584 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 7599
/* 7589 */    MCD_OPC_CheckPredicate, 30, 32, 37, 0, // Skip to: 17098
/* 7594 */    MCD_OPC_Decode, 242, 22, 136, 2, // Opcode: SUBV_B
/* 7599 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 7614
/* 7604 */    MCD_OPC_CheckPredicate, 30, 17, 37, 0, // Skip to: 17098
/* 7609 */    MCD_OPC_Decode, 244, 22, 137, 2, // Opcode: SUBV_H
/* 7614 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 7629
/* 7619 */    MCD_OPC_CheckPredicate, 30, 2, 37, 0, // Skip to: 17098
/* 7624 */    MCD_OPC_Decode, 245, 22, 138, 2, // Opcode: SUBV_W
/* 7629 */    MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 7644
/* 7634 */    MCD_OPC_CheckPredicate, 30, 243, 36, 0, // Skip to: 17098
/* 7639 */    MCD_OPC_Decode, 243, 22, 139, 2, // Opcode: SUBV_D
/* 7644 */    MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 7659
/* 7649 */    MCD_OPC_CheckPredicate, 30, 228, 36, 0, // Skip to: 17098
/* 7654 */    MCD_OPC_Decode, 247, 16, 136, 2, // Opcode: MAX_S_B
/* 7659 */    MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 7674
/* 7664 */    MCD_OPC_CheckPredicate, 30, 213, 36, 0, // Skip to: 17098
/* 7669 */    MCD_OPC_Decode, 249, 16, 137, 2, // Opcode: MAX_S_H
/* 7674 */    MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 7689
/* 7679 */    MCD_OPC_CheckPredicate, 30, 198, 36, 0, // Skip to: 17098
/* 7684 */    MCD_OPC_Decode, 251, 16, 138, 2, // Opcode: MAX_S_W
/* 7689 */    MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 7704
/* 7694 */    MCD_OPC_CheckPredicate, 30, 183, 36, 0, // Skip to: 17098
/* 7699 */    MCD_OPC_Decode, 248, 16, 139, 2, // Opcode: MAX_S_D
/* 7704 */    MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 7719
/* 7709 */    MCD_OPC_CheckPredicate, 30, 168, 36, 0, // Skip to: 17098
/* 7714 */    MCD_OPC_Decode, 252, 16, 136, 2, // Opcode: MAX_U_B
/* 7719 */    MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 7734
/* 7724 */    MCD_OPC_CheckPredicate, 30, 153, 36, 0, // Skip to: 17098
/* 7729 */    MCD_OPC_Decode, 254, 16, 137, 2, // Opcode: MAX_U_H
/* 7734 */    MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 7749
/* 7739 */    MCD_OPC_CheckPredicate, 30, 138, 36, 0, // Skip to: 17098
/* 7744 */    MCD_OPC_Decode, 255, 16, 138, 2, // Opcode: MAX_U_W
/* 7749 */    MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 7764
/* 7754 */    MCD_OPC_CheckPredicate, 30, 123, 36, 0, // Skip to: 17098
/* 7759 */    MCD_OPC_Decode, 253, 16, 139, 2, // Opcode: MAX_U_D
/* 7764 */    MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 7779
/* 7769 */    MCD_OPC_CheckPredicate, 30, 108, 36, 0, // Skip to: 17098
/* 7774 */    MCD_OPC_Decode, 183, 17, 136, 2, // Opcode: MIN_S_B
/* 7779 */    MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 7794
/* 7784 */    MCD_OPC_CheckPredicate, 30, 93, 36, 0, // Skip to: 17098
/* 7789 */    MCD_OPC_Decode, 185, 17, 137, 2, // Opcode: MIN_S_H
/* 7794 */    MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 7809
/* 7799 */    MCD_OPC_CheckPredicate, 30, 78, 36, 0, // Skip to: 17098
/* 7804 */    MCD_OPC_Decode, 187, 17, 138, 2, // Opcode: MIN_S_W
/* 7809 */    MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 7824
/* 7814 */    MCD_OPC_CheckPredicate, 30, 63, 36, 0, // Skip to: 17098
/* 7819 */    MCD_OPC_Decode, 184, 17, 139, 2, // Opcode: MIN_S_D
/* 7824 */    MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 7839
/* 7829 */    MCD_OPC_CheckPredicate, 30, 48, 36, 0, // Skip to: 17098
/* 7834 */    MCD_OPC_Decode, 188, 17, 136, 2, // Opcode: MIN_U_B
/* 7839 */    MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 7854
/* 7844 */    MCD_OPC_CheckPredicate, 30, 33, 36, 0, // Skip to: 17098
/* 7849 */    MCD_OPC_Decode, 190, 17, 137, 2, // Opcode: MIN_U_H
/* 7854 */    MCD_OPC_FilterValue, 22, 10, 0, 0, // Skip to: 7869
/* 7859 */    MCD_OPC_CheckPredicate, 30, 18, 36, 0, // Skip to: 17098
/* 7864 */    MCD_OPC_Decode, 191, 17, 138, 2, // Opcode: MIN_U_W
/* 7869 */    MCD_OPC_FilterValue, 23, 10, 0, 0, // Skip to: 7884
/* 7874 */    MCD_OPC_CheckPredicate, 30, 3, 36, 0, // Skip to: 17098
/* 7879 */    MCD_OPC_Decode, 189, 17, 139, 2, // Opcode: MIN_U_D
/* 7884 */    MCD_OPC_FilterValue, 24, 10, 0, 0, // Skip to: 7899
/* 7889 */    MCD_OPC_CheckPredicate, 30, 244, 35, 0, // Skip to: 17098
/* 7894 */    MCD_OPC_Decode, 240, 16, 136, 2, // Opcode: MAX_A_B
/* 7899 */    MCD_OPC_FilterValue, 25, 10, 0, 0, // Skip to: 7914
/* 7904 */    MCD_OPC_CheckPredicate, 30, 229, 35, 0, // Skip to: 17098
/* 7909 */    MCD_OPC_Decode, 242, 16, 137, 2, // Opcode: MAX_A_H
/* 7914 */    MCD_OPC_FilterValue, 26, 10, 0, 0, // Skip to: 7929
/* 7919 */    MCD_OPC_CheckPredicate, 30, 214, 35, 0, // Skip to: 17098
/* 7924 */    MCD_OPC_Decode, 243, 16, 138, 2, // Opcode: MAX_A_W
/* 7929 */    MCD_OPC_FilterValue, 27, 10, 0, 0, // Skip to: 7944
/* 7934 */    MCD_OPC_CheckPredicate, 30, 199, 35, 0, // Skip to: 17098
/* 7939 */    MCD_OPC_Decode, 241, 16, 139, 2, // Opcode: MAX_A_D
/* 7944 */    MCD_OPC_FilterValue, 28, 10, 0, 0, // Skip to: 7959
/* 7949 */    MCD_OPC_CheckPredicate, 30, 184, 35, 0, // Skip to: 17098
/* 7954 */    MCD_OPC_Decode, 176, 17, 136, 2, // Opcode: MIN_A_B
/* 7959 */    MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 7974
/* 7964 */    MCD_OPC_CheckPredicate, 30, 169, 35, 0, // Skip to: 17098
/* 7969 */    MCD_OPC_Decode, 178, 17, 137, 2, // Opcode: MIN_A_H
/* 7974 */    MCD_OPC_FilterValue, 30, 10, 0, 0, // Skip to: 7989
/* 7979 */    MCD_OPC_CheckPredicate, 30, 154, 35, 0, // Skip to: 17098
/* 7984 */    MCD_OPC_Decode, 179, 17, 138, 2, // Opcode: MIN_A_W
/* 7989 */    MCD_OPC_FilterValue, 31, 144, 35, 0, // Skip to: 17098
/* 7994 */    MCD_OPC_CheckPredicate, 30, 139, 35, 0, // Skip to: 17098
/* 7999 */    MCD_OPC_Decode, 177, 17, 139, 2, // Opcode: MIN_A_D
/* 8004 */    MCD_OPC_FilterValue, 15, 47, 1, 0, // Skip to: 8312
/* 8009 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 8012 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 8027
/* 8017 */    MCD_OPC_CheckPredicate, 30, 116, 35, 0, // Skip to: 17098
/* 8022 */    MCD_OPC_Decode, 140, 9, 136, 2, // Opcode: CEQ_B
/* 8027 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 8042
/* 8032 */    MCD_OPC_CheckPredicate, 30, 101, 35, 0, // Skip to: 17098
/* 8037 */    MCD_OPC_Decode, 142, 9, 137, 2, // Opcode: CEQ_H
/* 8042 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 8057
/* 8047 */    MCD_OPC_CheckPredicate, 30, 86, 35, 0, // Skip to: 17098
/* 8052 */    MCD_OPC_Decode, 143, 9, 138, 2, // Opcode: CEQ_W
/* 8057 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 8072
/* 8062 */    MCD_OPC_CheckPredicate, 30, 71, 35, 0, // Skip to: 17098
/* 8067 */    MCD_OPC_Decode, 141, 9, 139, 2, // Opcode: CEQ_D
/* 8072 */    MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 8087
/* 8077 */    MCD_OPC_CheckPredicate, 30, 56, 35, 0, // Skip to: 17098
/* 8082 */    MCD_OPC_Decode, 185, 9, 136, 2, // Opcode: CLT_S_B
/* 8087 */    MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 8102
/* 8092 */    MCD_OPC_CheckPredicate, 30, 41, 35, 0, // Skip to: 17098
/* 8097 */    MCD_OPC_Decode, 187, 9, 137, 2, // Opcode: CLT_S_H
/* 8102 */    MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 8117
/* 8107 */    MCD_OPC_CheckPredicate, 30, 26, 35, 0, // Skip to: 17098
/* 8112 */    MCD_OPC_Decode, 188, 9, 138, 2, // Opcode: CLT_S_W
/* 8117 */    MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 8132
/* 8122 */    MCD_OPC_CheckPredicate, 30, 11, 35, 0, // Skip to: 17098
/* 8127 */    MCD_OPC_Decode, 186, 9, 139, 2, // Opcode: CLT_S_D
/* 8132 */    MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 8147
/* 8137 */    MCD_OPC_CheckPredicate, 30, 252, 34, 0, // Skip to: 17098
/* 8142 */    MCD_OPC_Decode, 189, 9, 136, 2, // Opcode: CLT_U_B
/* 8147 */    MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 8162
/* 8152 */    MCD_OPC_CheckPredicate, 30, 237, 34, 0, // Skip to: 17098
/* 8157 */    MCD_OPC_Decode, 191, 9, 137, 2, // Opcode: CLT_U_H
/* 8162 */    MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 8177
/* 8167 */    MCD_OPC_CheckPredicate, 30, 222, 34, 0, // Skip to: 17098
/* 8172 */    MCD_OPC_Decode, 192, 9, 138, 2, // Opcode: CLT_U_W
/* 8177 */    MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 8192
/* 8182 */    MCD_OPC_CheckPredicate, 30, 207, 34, 0, // Skip to: 17098
/* 8187 */    MCD_OPC_Decode, 190, 9, 139, 2, // Opcode: CLT_U_D
/* 8192 */    MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 8207
/* 8197 */    MCD_OPC_CheckPredicate, 30, 192, 34, 0, // Skip to: 17098
/* 8202 */    MCD_OPC_Decode, 164, 9, 136, 2, // Opcode: CLE_S_B
/* 8207 */    MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 8222
/* 8212 */    MCD_OPC_CheckPredicate, 30, 177, 34, 0, // Skip to: 17098
/* 8217 */    MCD_OPC_Decode, 166, 9, 137, 2, // Opcode: CLE_S_H
/* 8222 */    MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 8237
/* 8227 */    MCD_OPC_CheckPredicate, 30, 162, 34, 0, // Skip to: 17098
/* 8232 */    MCD_OPC_Decode, 167, 9, 138, 2, // Opcode: CLE_S_W
/* 8237 */    MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 8252
/* 8242 */    MCD_OPC_CheckPredicate, 30, 147, 34, 0, // Skip to: 17098
/* 8247 */    MCD_OPC_Decode, 165, 9, 139, 2, // Opcode: CLE_S_D
/* 8252 */    MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 8267
/* 8257 */    MCD_OPC_CheckPredicate, 30, 132, 34, 0, // Skip to: 17098
/* 8262 */    MCD_OPC_Decode, 168, 9, 136, 2, // Opcode: CLE_U_B
/* 8267 */    MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 8282
/* 8272 */    MCD_OPC_CheckPredicate, 30, 117, 34, 0, // Skip to: 17098
/* 8277 */    MCD_OPC_Decode, 170, 9, 137, 2, // Opcode: CLE_U_H
/* 8282 */    MCD_OPC_FilterValue, 22, 10, 0, 0, // Skip to: 8297
/* 8287 */    MCD_OPC_CheckPredicate, 30, 102, 34, 0, // Skip to: 17098
/* 8292 */    MCD_OPC_Decode, 171, 9, 138, 2, // Opcode: CLE_U_W
/* 8297 */    MCD_OPC_FilterValue, 23, 92, 34, 0, // Skip to: 17098
/* 8302 */    MCD_OPC_CheckPredicate, 30, 87, 34, 0, // Skip to: 17098
/* 8307 */    MCD_OPC_Decode, 169, 9, 139, 2, // Opcode: CLE_U_D
/* 8312 */    MCD_OPC_FilterValue, 16, 227, 1, 0, // Skip to: 8800
/* 8317 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 8320 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 8335
/* 8325 */    MCD_OPC_CheckPredicate, 30, 64, 34, 0, // Skip to: 17098
/* 8330 */    MCD_OPC_Decode, 195, 6, 136, 2, // Opcode: ADD_A_B
/* 8335 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 8350
/* 8340 */    MCD_OPC_CheckPredicate, 30, 49, 34, 0, // Skip to: 17098
/* 8345 */    MCD_OPC_Decode, 197, 6, 137, 2, // Opcode: ADD_A_H
/* 8350 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 8365
/* 8355 */    MCD_OPC_CheckPredicate, 30, 34, 34, 0, // Skip to: 17098
/* 8360 */    MCD_OPC_Decode, 198, 6, 138, 2, // Opcode: ADD_A_W
/* 8365 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 8380
/* 8370 */    MCD_OPC_CheckPredicate, 30, 19, 34, 0, // Skip to: 17098
/* 8375 */    MCD_OPC_Decode, 196, 6, 139, 2, // Opcode: ADD_A_D
/* 8380 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 8395
/* 8385 */    MCD_OPC_CheckPredicate, 30, 4, 34, 0, // Skip to: 17098
/* 8390 */    MCD_OPC_Decode, 158, 6, 136, 2, // Opcode: ADDS_A_B
/* 8395 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 8410
/* 8400 */    MCD_OPC_CheckPredicate, 30, 245, 33, 0, // Skip to: 17098
/* 8405 */    MCD_OPC_Decode, 160, 6, 137, 2, // Opcode: ADDS_A_H
/* 8410 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 8425
/* 8415 */    MCD_OPC_CheckPredicate, 30, 230, 33, 0, // Skip to: 17098
/* 8420 */    MCD_OPC_Decode, 161, 6, 138, 2, // Opcode: ADDS_A_W
/* 8425 */    MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 8440
/* 8430 */    MCD_OPC_CheckPredicate, 30, 215, 33, 0, // Skip to: 17098
/* 8435 */    MCD_OPC_Decode, 159, 6, 139, 2, // Opcode: ADDS_A_D
/* 8440 */    MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 8455
/* 8445 */    MCD_OPC_CheckPredicate, 30, 200, 33, 0, // Skip to: 17098
/* 8450 */    MCD_OPC_Decode, 162, 6, 136, 2, // Opcode: ADDS_S_B
/* 8455 */    MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 8470
/* 8460 */    MCD_OPC_CheckPredicate, 30, 185, 33, 0, // Skip to: 17098
/* 8465 */    MCD_OPC_Decode, 164, 6, 137, 2, // Opcode: ADDS_S_H
/* 8470 */    MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 8485
/* 8475 */    MCD_OPC_CheckPredicate, 30, 170, 33, 0, // Skip to: 17098
/* 8480 */    MCD_OPC_Decode, 165, 6, 138, 2, // Opcode: ADDS_S_W
/* 8485 */    MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 8500
/* 8490 */    MCD_OPC_CheckPredicate, 30, 155, 33, 0, // Skip to: 17098
/* 8495 */    MCD_OPC_Decode, 163, 6, 139, 2, // Opcode: ADDS_S_D
/* 8500 */    MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 8515
/* 8505 */    MCD_OPC_CheckPredicate, 30, 140, 33, 0, // Skip to: 17098
/* 8510 */    MCD_OPC_Decode, 166, 6, 136, 2, // Opcode: ADDS_U_B
/* 8515 */    MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 8530
/* 8520 */    MCD_OPC_CheckPredicate, 30, 125, 33, 0, // Skip to: 17098
/* 8525 */    MCD_OPC_Decode, 168, 6, 137, 2, // Opcode: ADDS_U_H
/* 8530 */    MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 8545
/* 8535 */    MCD_OPC_CheckPredicate, 30, 110, 33, 0, // Skip to: 17098
/* 8540 */    MCD_OPC_Decode, 169, 6, 138, 2, // Opcode: ADDS_U_W
/* 8545 */    MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 8560
/* 8550 */    MCD_OPC_CheckPredicate, 30, 95, 33, 0, // Skip to: 17098
/* 8555 */    MCD_OPC_Decode, 167, 6, 139, 2, // Opcode: ADDS_U_D
/* 8560 */    MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 8575
/* 8565 */    MCD_OPC_CheckPredicate, 30, 80, 33, 0, // Skip to: 17098
/* 8570 */    MCD_OPC_Decode, 128, 7, 136, 2, // Opcode: AVE_S_B
/* 8575 */    MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 8590
/* 8580 */    MCD_OPC_CheckPredicate, 30, 65, 33, 0, // Skip to: 17098
/* 8585 */    MCD_OPC_Decode, 130, 7, 137, 2, // Opcode: AVE_S_H
/* 8590 */    MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 8605
/* 8595 */    MCD_OPC_CheckPredicate, 30, 50, 33, 0, // Skip to: 17098
/* 8600 */    MCD_OPC_Decode, 131, 7, 138, 2, // Opcode: AVE_S_W
/* 8605 */    MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 8620
/* 8610 */    MCD_OPC_CheckPredicate, 30, 35, 33, 0, // Skip to: 17098
/* 8615 */    MCD_OPC_Decode, 129, 7, 139, 2, // Opcode: AVE_S_D
/* 8620 */    MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 8635
/* 8625 */    MCD_OPC_CheckPredicate, 30, 20, 33, 0, // Skip to: 17098
/* 8630 */    MCD_OPC_Decode, 132, 7, 136, 2, // Opcode: AVE_U_B
/* 8635 */    MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 8650
/* 8640 */    MCD_OPC_CheckPredicate, 30, 5, 33, 0, // Skip to: 17098
/* 8645 */    MCD_OPC_Decode, 134, 7, 137, 2, // Opcode: AVE_U_H
/* 8650 */    MCD_OPC_FilterValue, 22, 10, 0, 0, // Skip to: 8665
/* 8655 */    MCD_OPC_CheckPredicate, 30, 246, 32, 0, // Skip to: 17098
/* 8660 */    MCD_OPC_Decode, 135, 7, 138, 2, // Opcode: AVE_U_W
/* 8665 */    MCD_OPC_FilterValue, 23, 10, 0, 0, // Skip to: 8680
/* 8670 */    MCD_OPC_CheckPredicate, 30, 231, 32, 0, // Skip to: 17098
/* 8675 */    MCD_OPC_Decode, 133, 7, 139, 2, // Opcode: AVE_U_D
/* 8680 */    MCD_OPC_FilterValue, 24, 10, 0, 0, // Skip to: 8695
/* 8685 */    MCD_OPC_CheckPredicate, 30, 216, 32, 0, // Skip to: 17098
/* 8690 */    MCD_OPC_Decode, 248, 6, 136, 2, // Opcode: AVER_S_B
/* 8695 */    MCD_OPC_FilterValue, 25, 10, 0, 0, // Skip to: 8710
/* 8700 */    MCD_OPC_CheckPredicate, 30, 201, 32, 0, // Skip to: 17098
/* 8705 */    MCD_OPC_Decode, 250, 6, 137, 2, // Opcode: AVER_S_H
/* 8710 */    MCD_OPC_FilterValue, 26, 10, 0, 0, // Skip to: 8725
/* 8715 */    MCD_OPC_CheckPredicate, 30, 186, 32, 0, // Skip to: 17098
/* 8720 */    MCD_OPC_Decode, 251, 6, 138, 2, // Opcode: AVER_S_W
/* 8725 */    MCD_OPC_FilterValue, 27, 10, 0, 0, // Skip to: 8740
/* 8730 */    MCD_OPC_CheckPredicate, 30, 171, 32, 0, // Skip to: 17098
/* 8735 */    MCD_OPC_Decode, 249, 6, 139, 2, // Opcode: AVER_S_D
/* 8740 */    MCD_OPC_FilterValue, 28, 10, 0, 0, // Skip to: 8755
/* 8745 */    MCD_OPC_CheckPredicate, 30, 156, 32, 0, // Skip to: 17098
/* 8750 */    MCD_OPC_Decode, 252, 6, 136, 2, // Opcode: AVER_U_B
/* 8755 */    MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 8770
/* 8760 */    MCD_OPC_CheckPredicate, 30, 141, 32, 0, // Skip to: 17098
/* 8765 */    MCD_OPC_Decode, 254, 6, 137, 2, // Opcode: AVER_U_H
/* 8770 */    MCD_OPC_FilterValue, 30, 10, 0, 0, // Skip to: 8785
/* 8775 */    MCD_OPC_CheckPredicate, 30, 126, 32, 0, // Skip to: 17098
/* 8780 */    MCD_OPC_Decode, 255, 6, 138, 2, // Opcode: AVER_U_W
/* 8785 */    MCD_OPC_FilterValue, 31, 116, 32, 0, // Skip to: 17098
/* 8790 */    MCD_OPC_CheckPredicate, 30, 111, 32, 0, // Skip to: 17098
/* 8795 */    MCD_OPC_Decode, 253, 6, 139, 2, // Opcode: AVER_U_D
/* 8800 */    MCD_OPC_FilterValue, 17, 107, 1, 0, // Skip to: 9168
/* 8805 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 8808 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 8823
/* 8813 */    MCD_OPC_CheckPredicate, 30, 88, 32, 0, // Skip to: 17098
/* 8818 */    MCD_OPC_Decode, 215, 22, 136, 2, // Opcode: SUBS_S_B
/* 8823 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 8838
/* 8828 */    MCD_OPC_CheckPredicate, 30, 73, 32, 0, // Skip to: 17098
/* 8833 */    MCD_OPC_Decode, 217, 22, 137, 2, // Opcode: SUBS_S_H
/* 8838 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 8853
/* 8843 */    MCD_OPC_CheckPredicate, 30, 58, 32, 0, // Skip to: 17098
/* 8848 */    MCD_OPC_Decode, 218, 22, 138, 2, // Opcode: SUBS_S_W
/* 8853 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 8868
/* 8858 */    MCD_OPC_CheckPredicate, 30, 43, 32, 0, // Skip to: 17098
/* 8863 */    MCD_OPC_Decode, 216, 22, 139, 2, // Opcode: SUBS_S_D
/* 8868 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 8883
/* 8873 */    MCD_OPC_CheckPredicate, 30, 28, 32, 0, // Skip to: 17098
/* 8878 */    MCD_OPC_Decode, 219, 22, 136, 2, // Opcode: SUBS_U_B
/* 8883 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 8898
/* 8888 */    MCD_OPC_CheckPredicate, 30, 13, 32, 0, // Skip to: 17098
/* 8893 */    MCD_OPC_Decode, 221, 22, 137, 2, // Opcode: SUBS_U_H
/* 8898 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 8913
/* 8903 */    MCD_OPC_CheckPredicate, 30, 254, 31, 0, // Skip to: 17098
/* 8908 */    MCD_OPC_Decode, 222, 22, 138, 2, // Opcode: SUBS_U_W
/* 8913 */    MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 8928
/* 8918 */    MCD_OPC_CheckPredicate, 30, 239, 31, 0, // Skip to: 17098
/* 8923 */    MCD_OPC_Decode, 220, 22, 139, 2, // Opcode: SUBS_U_D
/* 8928 */    MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 8943
/* 8933 */    MCD_OPC_CheckPredicate, 30, 224, 31, 0, // Skip to: 17098
/* 8938 */    MCD_OPC_Decode, 207, 22, 136, 2, // Opcode: SUBSUS_U_B
/* 8943 */    MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 8958
/* 8948 */    MCD_OPC_CheckPredicate, 30, 209, 31, 0, // Skip to: 17098
/* 8953 */    MCD_OPC_Decode, 209, 22, 137, 2, // Opcode: SUBSUS_U_H
/* 8958 */    MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 8973
/* 8963 */    MCD_OPC_CheckPredicate, 30, 194, 31, 0, // Skip to: 17098
/* 8968 */    MCD_OPC_Decode, 210, 22, 138, 2, // Opcode: SUBSUS_U_W
/* 8973 */    MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 8988
/* 8978 */    MCD_OPC_CheckPredicate, 30, 179, 31, 0, // Skip to: 17098
/* 8983 */    MCD_OPC_Decode, 208, 22, 139, 2, // Opcode: SUBSUS_U_D
/* 8988 */    MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 9003
/* 8993 */    MCD_OPC_CheckPredicate, 30, 164, 31, 0, // Skip to: 17098
/* 8998 */    MCD_OPC_Decode, 211, 22, 136, 2, // Opcode: SUBSUU_S_B
/* 9003 */    MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 9018
/* 9008 */    MCD_OPC_CheckPredicate, 30, 149, 31, 0, // Skip to: 17098
/* 9013 */    MCD_OPC_Decode, 213, 22, 137, 2, // Opcode: SUBSUU_S_H
/* 9018 */    MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 9033
/* 9023 */    MCD_OPC_CheckPredicate, 30, 134, 31, 0, // Skip to: 17098
/* 9028 */    MCD_OPC_Decode, 214, 22, 138, 2, // Opcode: SUBSUU_S_W
/* 9033 */    MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 9048
/* 9038 */    MCD_OPC_CheckPredicate, 30, 119, 31, 0, // Skip to: 17098
/* 9043 */    MCD_OPC_Decode, 212, 22, 139, 2, // Opcode: SUBSUU_S_D
/* 9048 */    MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 9063
/* 9053 */    MCD_OPC_CheckPredicate, 30, 104, 31, 0, // Skip to: 17098
/* 9058 */    MCD_OPC_Decode, 236, 6, 136, 2, // Opcode: ASUB_S_B
/* 9063 */    MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 9078
/* 9068 */    MCD_OPC_CheckPredicate, 30, 89, 31, 0, // Skip to: 17098
/* 9073 */    MCD_OPC_Decode, 238, 6, 137, 2, // Opcode: ASUB_S_H
/* 9078 */    MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 9093
/* 9083 */    MCD_OPC_CheckPredicate, 30, 74, 31, 0, // Skip to: 17098
/* 9088 */    MCD_OPC_Decode, 239, 6, 138, 2, // Opcode: ASUB_S_W
/* 9093 */    MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 9108
/* 9098 */    MCD_OPC_CheckPredicate, 30, 59, 31, 0, // Skip to: 17098
/* 9103 */    MCD_OPC_Decode, 237, 6, 139, 2, // Opcode: ASUB_S_D
/* 9108 */    MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 9123
/* 9113 */    MCD_OPC_CheckPredicate, 30, 44, 31, 0, // Skip to: 17098
/* 9118 */    MCD_OPC_Decode, 240, 6, 136, 2, // Opcode: ASUB_U_B
/* 9123 */    MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 9138
/* 9128 */    MCD_OPC_CheckPredicate, 30, 29, 31, 0, // Skip to: 17098
/* 9133 */    MCD_OPC_Decode, 242, 6, 137, 2, // Opcode: ASUB_U_H
/* 9138 */    MCD_OPC_FilterValue, 22, 10, 0, 0, // Skip to: 9153
/* 9143 */    MCD_OPC_CheckPredicate, 30, 14, 31, 0, // Skip to: 17098
/* 9148 */    MCD_OPC_Decode, 243, 6, 138, 2, // Opcode: ASUB_U_W
/* 9153 */    MCD_OPC_FilterValue, 23, 4, 31, 0, // Skip to: 17098
/* 9158 */    MCD_OPC_CheckPredicate, 30, 255, 30, 0, // Skip to: 17098
/* 9163 */    MCD_OPC_Decode, 241, 6, 139, 2, // Opcode: ASUB_U_D
/* 9168 */    MCD_OPC_FilterValue, 18, 167, 1, 0, // Skip to: 9596
/* 9173 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 9176 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 9191
/* 9181 */    MCD_OPC_CheckPredicate, 30, 232, 30, 0, // Skip to: 17098
/* 9186 */    MCD_OPC_Decode, 241, 18, 136, 2, // Opcode: MULV_B
/* 9191 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 9206
/* 9196 */    MCD_OPC_CheckPredicate, 30, 217, 30, 0, // Skip to: 17098
/* 9201 */    MCD_OPC_Decode, 243, 18, 137, 2, // Opcode: MULV_H
/* 9206 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 9221
/* 9211 */    MCD_OPC_CheckPredicate, 30, 202, 30, 0, // Skip to: 17098
/* 9216 */    MCD_OPC_Decode, 244, 18, 138, 2, // Opcode: MULV_W
/* 9221 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 9236
/* 9226 */    MCD_OPC_CheckPredicate, 30, 187, 30, 0, // Skip to: 17098
/* 9231 */    MCD_OPC_Decode, 242, 18, 139, 2, // Opcode: MULV_D
/* 9236 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 9251
/* 9241 */    MCD_OPC_CheckPredicate, 30, 172, 30, 0, // Skip to: 17098
/* 9246 */    MCD_OPC_Decode, 206, 16, 140, 2, // Opcode: MADDV_B
/* 9251 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 9266
/* 9256 */    MCD_OPC_CheckPredicate, 30, 157, 30, 0, // Skip to: 17098
/* 9261 */    MCD_OPC_Decode, 208, 16, 141, 2, // Opcode: MADDV_H
/* 9266 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 9281
/* 9271 */    MCD_OPC_CheckPredicate, 30, 142, 30, 0, // Skip to: 17098
/* 9276 */    MCD_OPC_Decode, 209, 16, 142, 2, // Opcode: MADDV_W
/* 9281 */    MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 9296
/* 9286 */    MCD_OPC_CheckPredicate, 30, 127, 30, 0, // Skip to: 17098
/* 9291 */    MCD_OPC_Decode, 207, 16, 143, 2, // Opcode: MADDV_D
/* 9296 */    MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 9311
/* 9301 */    MCD_OPC_CheckPredicate, 30, 112, 30, 0, // Skip to: 17098
/* 9306 */    MCD_OPC_Decode, 142, 18, 140, 2, // Opcode: MSUBV_B
/* 9311 */    MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 9326
/* 9316 */    MCD_OPC_CheckPredicate, 30, 97, 30, 0, // Skip to: 17098
/* 9321 */    MCD_OPC_Decode, 144, 18, 141, 2, // Opcode: MSUBV_H
/* 9326 */    MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 9341
/* 9331 */    MCD_OPC_CheckPredicate, 30, 82, 30, 0, // Skip to: 17098
/* 9336 */    MCD_OPC_Decode, 145, 18, 142, 2, // Opcode: MSUBV_W
/* 9341 */    MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 9356
/* 9346 */    MCD_OPC_CheckPredicate, 30, 67, 30, 0, // Skip to: 17098
/* 9351 */    MCD_OPC_Decode, 143, 18, 143, 2, // Opcode: MSUBV_D
/* 9356 */    MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 9371
/* 9361 */    MCD_OPC_CheckPredicate, 30, 52, 30, 0, // Skip to: 17098
/* 9366 */    MCD_OPC_Decode, 224, 11, 136, 2, // Opcode: DIV_S_B
/* 9371 */    MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 9386
/* 9376 */    MCD_OPC_CheckPredicate, 30, 37, 30, 0, // Skip to: 17098
/* 9381 */    MCD_OPC_Decode, 226, 11, 137, 2, // Opcode: DIV_S_H
/* 9386 */    MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 9401
/* 9391 */    MCD_OPC_CheckPredicate, 30, 22, 30, 0, // Skip to: 17098
/* 9396 */    MCD_OPC_Decode, 227, 11, 138, 2, // Opcode: DIV_S_W
/* 9401 */    MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 9416
/* 9406 */    MCD_OPC_CheckPredicate, 30, 7, 30, 0, // Skip to: 17098
/* 9411 */    MCD_OPC_Decode, 225, 11, 139, 2, // Opcode: DIV_S_D
/* 9416 */    MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 9431
/* 9421 */    MCD_OPC_CheckPredicate, 30, 248, 29, 0, // Skip to: 17098
/* 9426 */    MCD_OPC_Decode, 228, 11, 136, 2, // Opcode: DIV_U_B
/* 9431 */    MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 9446
/* 9436 */    MCD_OPC_CheckPredicate, 30, 233, 29, 0, // Skip to: 17098
/* 9441 */    MCD_OPC_Decode, 230, 11, 137, 2, // Opcode: DIV_U_H
/* 9446 */    MCD_OPC_FilterValue, 22, 10, 0, 0, // Skip to: 9461
/* 9451 */    MCD_OPC_CheckPredicate, 30, 218, 29, 0, // Skip to: 17098
/* 9456 */    MCD_OPC_Decode, 231, 11, 138, 2, // Opcode: DIV_U_W
/* 9461 */    MCD_OPC_FilterValue, 23, 10, 0, 0, // Skip to: 9476
/* 9466 */    MCD_OPC_CheckPredicate, 30, 203, 29, 0, // Skip to: 17098
/* 9471 */    MCD_OPC_Decode, 229, 11, 139, 2, // Opcode: DIV_U_D
/* 9476 */    MCD_OPC_FilterValue, 24, 10, 0, 0, // Skip to: 9491
/* 9481 */    MCD_OPC_CheckPredicate, 30, 188, 29, 0, // Skip to: 17098
/* 9486 */    MCD_OPC_Decode, 200, 17, 136, 2, // Opcode: MOD_S_B
/* 9491 */    MCD_OPC_FilterValue, 25, 10, 0, 0, // Skip to: 9506
/* 9496 */    MCD_OPC_CheckPredicate, 30, 173, 29, 0, // Skip to: 17098
/* 9501 */    MCD_OPC_Decode, 202, 17, 137, 2, // Opcode: MOD_S_H
/* 9506 */    MCD_OPC_FilterValue, 26, 10, 0, 0, // Skip to: 9521
/* 9511 */    MCD_OPC_CheckPredicate, 30, 158, 29, 0, // Skip to: 17098
/* 9516 */    MCD_OPC_Decode, 203, 17, 138, 2, // Opcode: MOD_S_W
/* 9521 */    MCD_OPC_FilterValue, 27, 10, 0, 0, // Skip to: 9536
/* 9526 */    MCD_OPC_CheckPredicate, 30, 143, 29, 0, // Skip to: 17098
/* 9531 */    MCD_OPC_Decode, 201, 17, 139, 2, // Opcode: MOD_S_D
/* 9536 */    MCD_OPC_FilterValue, 28, 10, 0, 0, // Skip to: 9551
/* 9541 */    MCD_OPC_CheckPredicate, 30, 128, 29, 0, // Skip to: 17098
/* 9546 */    MCD_OPC_Decode, 204, 17, 136, 2, // Opcode: MOD_U_B
/* 9551 */    MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 9566
/* 9556 */    MCD_OPC_CheckPredicate, 30, 113, 29, 0, // Skip to: 17098
/* 9561 */    MCD_OPC_Decode, 206, 17, 137, 2, // Opcode: MOD_U_H
/* 9566 */    MCD_OPC_FilterValue, 30, 10, 0, 0, // Skip to: 9581
/* 9571 */    MCD_OPC_CheckPredicate, 30, 98, 29, 0, // Skip to: 17098
/* 9576 */    MCD_OPC_Decode, 207, 17, 138, 2, // Opcode: MOD_U_W
/* 9581 */    MCD_OPC_FilterValue, 31, 88, 29, 0, // Skip to: 17098
/* 9586 */    MCD_OPC_CheckPredicate, 30, 83, 29, 0, // Skip to: 17098
/* 9591 */    MCD_OPC_Decode, 205, 17, 139, 2, // Opcode: MOD_U_D
/* 9596 */    MCD_OPC_FilterValue, 19, 17, 1, 0, // Skip to: 9874
/* 9601 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 9604 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 9619
/* 9609 */    MCD_OPC_CheckPredicate, 30, 60, 29, 0, // Skip to: 17098
/* 9614 */    MCD_OPC_Decode, 131, 12, 144, 2, // Opcode: DOTP_S_H
/* 9619 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 9634
/* 9624 */    MCD_OPC_CheckPredicate, 30, 45, 29, 0, // Skip to: 17098
/* 9629 */    MCD_OPC_Decode, 132, 12, 145, 2, // Opcode: DOTP_S_W
/* 9634 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 9649
/* 9639 */    MCD_OPC_CheckPredicate, 30, 30, 29, 0, // Skip to: 17098
/* 9644 */    MCD_OPC_Decode, 130, 12, 146, 2, // Opcode: DOTP_S_D
/* 9649 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 9664
/* 9654 */    MCD_OPC_CheckPredicate, 30, 15, 29, 0, // Skip to: 17098
/* 9659 */    MCD_OPC_Decode, 134, 12, 144, 2, // Opcode: DOTP_U_H
/* 9664 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 9679
/* 9669 */    MCD_OPC_CheckPredicate, 30, 0, 29, 0, // Skip to: 17098
/* 9674 */    MCD_OPC_Decode, 135, 12, 145, 2, // Opcode: DOTP_U_W
/* 9679 */    MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 9694
/* 9684 */    MCD_OPC_CheckPredicate, 30, 241, 28, 0, // Skip to: 17098
/* 9689 */    MCD_OPC_Decode, 133, 12, 146, 2, // Opcode: DOTP_U_D
/* 9694 */    MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 9709
/* 9699 */    MCD_OPC_CheckPredicate, 30, 226, 28, 0, // Skip to: 17098
/* 9704 */    MCD_OPC_Decode, 137, 12, 147, 2, // Opcode: DPADD_S_H
/* 9709 */    MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 9724
/* 9714 */    MCD_OPC_CheckPredicate, 30, 211, 28, 0, // Skip to: 17098
/* 9719 */    MCD_OPC_Decode, 138, 12, 148, 2, // Opcode: DPADD_S_W
/* 9724 */    MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 9739
/* 9729 */    MCD_OPC_CheckPredicate, 30, 196, 28, 0, // Skip to: 17098
/* 9734 */    MCD_OPC_Decode, 136, 12, 149, 2, // Opcode: DPADD_S_D
/* 9739 */    MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 9754
/* 9744 */    MCD_OPC_CheckPredicate, 30, 181, 28, 0, // Skip to: 17098
/* 9749 */    MCD_OPC_Decode, 140, 12, 147, 2, // Opcode: DPADD_U_H
/* 9754 */    MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 9769
/* 9759 */    MCD_OPC_CheckPredicate, 30, 166, 28, 0, // Skip to: 17098
/* 9764 */    MCD_OPC_Decode, 141, 12, 148, 2, // Opcode: DPADD_U_W
/* 9769 */    MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 9784
/* 9774 */    MCD_OPC_CheckPredicate, 30, 151, 28, 0, // Skip to: 17098
/* 9779 */    MCD_OPC_Decode, 139, 12, 149, 2, // Opcode: DPADD_U_D
/* 9784 */    MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 9799
/* 9789 */    MCD_OPC_CheckPredicate, 30, 136, 28, 0, // Skip to: 17098
/* 9794 */    MCD_OPC_Decode, 168, 12, 147, 2, // Opcode: DPSUB_S_H
/* 9799 */    MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 9814
/* 9804 */    MCD_OPC_CheckPredicate, 30, 121, 28, 0, // Skip to: 17098
/* 9809 */    MCD_OPC_Decode, 169, 12, 148, 2, // Opcode: DPSUB_S_W
/* 9814 */    MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 9829
/* 9819 */    MCD_OPC_CheckPredicate, 30, 106, 28, 0, // Skip to: 17098
/* 9824 */    MCD_OPC_Decode, 167, 12, 149, 2, // Opcode: DPSUB_S_D
/* 9829 */    MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 9844
/* 9834 */    MCD_OPC_CheckPredicate, 30, 91, 28, 0, // Skip to: 17098
/* 9839 */    MCD_OPC_Decode, 171, 12, 147, 2, // Opcode: DPSUB_U_H
/* 9844 */    MCD_OPC_FilterValue, 22, 10, 0, 0, // Skip to: 9859
/* 9849 */    MCD_OPC_CheckPredicate, 30, 76, 28, 0, // Skip to: 17098
/* 9854 */    MCD_OPC_Decode, 172, 12, 148, 2, // Opcode: DPSUB_U_W
/* 9859 */    MCD_OPC_FilterValue, 23, 66, 28, 0, // Skip to: 17098
/* 9864 */    MCD_OPC_CheckPredicate, 30, 61, 28, 0, // Skip to: 17098
/* 9869 */    MCD_OPC_Decode, 170, 12, 149, 2, // Opcode: DPSUB_U_D
/* 9874 */    MCD_OPC_FilterValue, 20, 227, 1, 0, // Skip to: 10362
/* 9879 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 9882 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 9897
/* 9887 */    MCD_OPC_CheckPredicate, 30, 38, 28, 0, // Skip to: 17098
/* 9892 */    MCD_OPC_Decode, 215, 21, 150, 2, // Opcode: SLD_B
/* 9897 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 9912
/* 9902 */    MCD_OPC_CheckPredicate, 30, 23, 28, 0, // Skip to: 17098
/* 9907 */    MCD_OPC_Decode, 217, 21, 151, 2, // Opcode: SLD_H
/* 9912 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 9927
/* 9917 */    MCD_OPC_CheckPredicate, 30, 8, 28, 0, // Skip to: 17098
/* 9922 */    MCD_OPC_Decode, 218, 21, 152, 2, // Opcode: SLD_W
/* 9927 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 9942
/* 9932 */    MCD_OPC_CheckPredicate, 30, 249, 27, 0, // Skip to: 17098
/* 9937 */    MCD_OPC_Decode, 216, 21, 153, 2, // Opcode: SLD_D
/* 9942 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 9957
/* 9947 */    MCD_OPC_CheckPredicate, 30, 234, 27, 0, // Skip to: 17098
/* 9952 */    MCD_OPC_Decode, 134, 22, 154, 2, // Opcode: SPLAT_B
/* 9957 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 9972
/* 9962 */    MCD_OPC_CheckPredicate, 30, 219, 27, 0, // Skip to: 17098
/* 9967 */    MCD_OPC_Decode, 136, 22, 155, 2, // Opcode: SPLAT_H
/* 9972 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 9987
/* 9977 */    MCD_OPC_CheckPredicate, 30, 204, 27, 0, // Skip to: 17098
/* 9982 */    MCD_OPC_Decode, 137, 22, 156, 2, // Opcode: SPLAT_W
/* 9987 */    MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 10002
/* 9992 */    MCD_OPC_CheckPredicate, 30, 189, 27, 0, // Skip to: 17098
/* 9997 */    MCD_OPC_Decode, 135, 22, 157, 2, // Opcode: SPLAT_D
/* 10002 */   MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 10017
/* 10007 */   MCD_OPC_CheckPredicate, 30, 174, 27, 0, // Skip to: 17098
/* 10012 */   MCD_OPC_Decode, 185, 19, 136, 2, // Opcode: PCKEV_B
/* 10017 */   MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 10032
/* 10022 */   MCD_OPC_CheckPredicate, 30, 159, 27, 0, // Skip to: 17098
/* 10027 */   MCD_OPC_Decode, 187, 19, 137, 2, // Opcode: PCKEV_H
/* 10032 */   MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 10047
/* 10037 */   MCD_OPC_CheckPredicate, 30, 144, 27, 0, // Skip to: 17098
/* 10042 */   MCD_OPC_Decode, 188, 19, 138, 2, // Opcode: PCKEV_W
/* 10047 */   MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 10062
/* 10052 */   MCD_OPC_CheckPredicate, 30, 129, 27, 0, // Skip to: 17098
/* 10057 */   MCD_OPC_Decode, 186, 19, 139, 2, // Opcode: PCKEV_D
/* 10062 */   MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 10077
/* 10067 */   MCD_OPC_CheckPredicate, 30, 114, 27, 0, // Skip to: 17098
/* 10072 */   MCD_OPC_Decode, 189, 19, 136, 2, // Opcode: PCKOD_B
/* 10077 */   MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 10092
/* 10082 */   MCD_OPC_CheckPredicate, 30, 99, 27, 0, // Skip to: 17098
/* 10087 */   MCD_OPC_Decode, 191, 19, 137, 2, // Opcode: PCKOD_H
/* 10092 */   MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 10107
/* 10097 */   MCD_OPC_CheckPredicate, 30, 84, 27, 0, // Skip to: 17098
/* 10102 */   MCD_OPC_Decode, 192, 19, 138, 2, // Opcode: PCKOD_W
/* 10107 */   MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 10122
/* 10112 */   MCD_OPC_CheckPredicate, 30, 69, 27, 0, // Skip to: 17098
/* 10117 */   MCD_OPC_Decode, 190, 19, 139, 2, // Opcode: PCKOD_D
/* 10122 */   MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 10137
/* 10127 */   MCD_OPC_CheckPredicate, 30, 54, 27, 0, // Skip to: 17098
/* 10132 */   MCD_OPC_Decode, 208, 14, 136, 2, // Opcode: ILVL_B
/* 10137 */   MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 10152
/* 10142 */   MCD_OPC_CheckPredicate, 30, 39, 27, 0, // Skip to: 17098
/* 10147 */   MCD_OPC_Decode, 210, 14, 137, 2, // Opcode: ILVL_H
/* 10152 */   MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 10167
/* 10157 */   MCD_OPC_CheckPredicate, 30, 24, 27, 0, // Skip to: 17098
/* 10162 */   MCD_OPC_Decode, 211, 14, 138, 2, // Opcode: ILVL_W
/* 10167 */   MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 10182
/* 10172 */   MCD_OPC_CheckPredicate, 30, 9, 27, 0, // Skip to: 17098
/* 10177 */   MCD_OPC_Decode, 209, 14, 139, 2, // Opcode: ILVL_D
/* 10182 */   MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 10197
/* 10187 */   MCD_OPC_CheckPredicate, 30, 250, 26, 0, // Skip to: 17098
/* 10192 */   MCD_OPC_Decode, 216, 14, 136, 2, // Opcode: ILVR_B
/* 10197 */   MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 10212
/* 10202 */   MCD_OPC_CheckPredicate, 30, 235, 26, 0, // Skip to: 17098
/* 10207 */   MCD_OPC_Decode, 218, 14, 137, 2, // Opcode: ILVR_H
/* 10212 */   MCD_OPC_FilterValue, 22, 10, 0, 0, // Skip to: 10227
/* 10217 */   MCD_OPC_CheckPredicate, 30, 220, 26, 0, // Skip to: 17098
/* 10222 */   MCD_OPC_Decode, 219, 14, 138, 2, // Opcode: ILVR_W
/* 10227 */   MCD_OPC_FilterValue, 23, 10, 0, 0, // Skip to: 10242
/* 10232 */   MCD_OPC_CheckPredicate, 30, 205, 26, 0, // Skip to: 17098
/* 10237 */   MCD_OPC_Decode, 217, 14, 139, 2, // Opcode: ILVR_D
/* 10242 */   MCD_OPC_FilterValue, 24, 10, 0, 0, // Skip to: 10257
/* 10247 */   MCD_OPC_CheckPredicate, 30, 190, 26, 0, // Skip to: 17098
/* 10252 */   MCD_OPC_Decode, 204, 14, 136, 2, // Opcode: ILVEV_B
/* 10257 */   MCD_OPC_FilterValue, 25, 10, 0, 0, // Skip to: 10272
/* 10262 */   MCD_OPC_CheckPredicate, 30, 175, 26, 0, // Skip to: 17098
/* 10267 */   MCD_OPC_Decode, 206, 14, 137, 2, // Opcode: ILVEV_H
/* 10272 */   MCD_OPC_FilterValue, 26, 10, 0, 0, // Skip to: 10287
/* 10277 */   MCD_OPC_CheckPredicate, 30, 160, 26, 0, // Skip to: 17098
/* 10282 */   MCD_OPC_Decode, 207, 14, 138, 2, // Opcode: ILVEV_W
/* 10287 */   MCD_OPC_FilterValue, 27, 10, 0, 0, // Skip to: 10302
/* 10292 */   MCD_OPC_CheckPredicate, 30, 145, 26, 0, // Skip to: 17098
/* 10297 */   MCD_OPC_Decode, 205, 14, 139, 2, // Opcode: ILVEV_D
/* 10302 */   MCD_OPC_FilterValue, 28, 10, 0, 0, // Skip to: 10317
/* 10307 */   MCD_OPC_CheckPredicate, 30, 130, 26, 0, // Skip to: 17098
/* 10312 */   MCD_OPC_Decode, 212, 14, 136, 2, // Opcode: ILVOD_B
/* 10317 */   MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 10332
/* 10322 */   MCD_OPC_CheckPredicate, 30, 115, 26, 0, // Skip to: 17098
/* 10327 */   MCD_OPC_Decode, 214, 14, 137, 2, // Opcode: ILVOD_H
/* 10332 */   MCD_OPC_FilterValue, 30, 10, 0, 0, // Skip to: 10347
/* 10337 */   MCD_OPC_CheckPredicate, 30, 100, 26, 0, // Skip to: 17098
/* 10342 */   MCD_OPC_Decode, 215, 14, 138, 2, // Opcode: ILVOD_W
/* 10347 */   MCD_OPC_FilterValue, 31, 90, 26, 0, // Skip to: 17098
/* 10352 */   MCD_OPC_CheckPredicate, 30, 85, 26, 0, // Skip to: 17098
/* 10357 */   MCD_OPC_Decode, 213, 14, 139, 2, // Opcode: ILVOD_D
/* 10362 */   MCD_OPC_FilterValue, 21, 107, 1, 0, // Skip to: 10730
/* 10367 */   MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 10370 */   MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 10385
/* 10375 */   MCD_OPC_CheckPredicate, 30, 62, 26, 0, // Skip to: 17098
/* 10380 */   MCD_OPC_Decode, 157, 24, 140, 2, // Opcode: VSHF_B
/* 10385 */   MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 10400
/* 10390 */   MCD_OPC_CheckPredicate, 30, 47, 26, 0, // Skip to: 17098
/* 10395 */   MCD_OPC_Decode, 159, 24, 141, 2, // Opcode: VSHF_H
/* 10400 */   MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 10415
/* 10405 */   MCD_OPC_CheckPredicate, 30, 32, 26, 0, // Skip to: 17098
/* 10410 */   MCD_OPC_Decode, 160, 24, 142, 2, // Opcode: VSHF_W
/* 10415 */   MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 10430
/* 10420 */   MCD_OPC_CheckPredicate, 30, 17, 26, 0, // Skip to: 17098
/* 10425 */   MCD_OPC_Decode, 158, 24, 143, 2, // Opcode: VSHF_D
/* 10430 */   MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 10445
/* 10435 */   MCD_OPC_CheckPredicate, 30, 2, 26, 0, // Skip to: 17098
/* 10440 */   MCD_OPC_Decode, 147, 22, 136, 2, // Opcode: SRAR_B
/* 10445 */   MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 10460
/* 10450 */   MCD_OPC_CheckPredicate, 30, 243, 25, 0, // Skip to: 17098
/* 10455 */   MCD_OPC_Decode, 149, 22, 137, 2, // Opcode: SRAR_H
/* 10460 */   MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 10475
/* 10465 */   MCD_OPC_CheckPredicate, 30, 228, 25, 0, // Skip to: 17098
/* 10470 */   MCD_OPC_Decode, 150, 22, 138, 2, // Opcode: SRAR_W
/* 10475 */   MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 10490
/* 10480 */   MCD_OPC_CheckPredicate, 30, 213, 25, 0, // Skip to: 17098
/* 10485 */   MCD_OPC_Decode, 148, 22, 139, 2, // Opcode: SRAR_D
/* 10490 */   MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 10505
/* 10495 */   MCD_OPC_CheckPredicate, 30, 198, 25, 0, // Skip to: 17098
/* 10500 */   MCD_OPC_Decode, 172, 22, 136, 2, // Opcode: SRLR_B
/* 10505 */   MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 10520
/* 10510 */   MCD_OPC_CheckPredicate, 30, 183, 25, 0, // Skip to: 17098
/* 10515 */   MCD_OPC_Decode, 174, 22, 137, 2, // Opcode: SRLR_H
/* 10520 */   MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 10535
/* 10525 */   MCD_OPC_CheckPredicate, 30, 168, 25, 0, // Skip to: 17098
/* 10530 */   MCD_OPC_Decode, 175, 22, 138, 2, // Opcode: SRLR_W
/* 10535 */   MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 10550
/* 10540 */   MCD_OPC_CheckPredicate, 30, 153, 25, 0, // Skip to: 17098
/* 10545 */   MCD_OPC_Decode, 173, 22, 139, 2, // Opcode: SRLR_D
/* 10550 */   MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 10565
/* 10555 */   MCD_OPC_CheckPredicate, 30, 138, 25, 0, // Skip to: 17098
/* 10560 */   MCD_OPC_Decode, 191, 14, 144, 2, // Opcode: HADD_S_H
/* 10565 */   MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 10580
/* 10570 */   MCD_OPC_CheckPredicate, 30, 123, 25, 0, // Skip to: 17098
/* 10575 */   MCD_OPC_Decode, 192, 14, 145, 2, // Opcode: HADD_S_W
/* 10580 */   MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 10595
/* 10585 */   MCD_OPC_CheckPredicate, 30, 108, 25, 0, // Skip to: 17098
/* 10590 */   MCD_OPC_Decode, 190, 14, 146, 2, // Opcode: HADD_S_D
/* 10595 */   MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 10610
/* 10600 */   MCD_OPC_CheckPredicate, 30, 93, 25, 0, // Skip to: 17098
/* 10605 */   MCD_OPC_Decode, 194, 14, 144, 2, // Opcode: HADD_U_H
/* 10610 */   MCD_OPC_FilterValue, 22, 10, 0, 0, // Skip to: 10625
/* 10615 */   MCD_OPC_CheckPredicate, 30, 78, 25, 0, // Skip to: 17098
/* 10620 */   MCD_OPC_Decode, 195, 14, 145, 2, // Opcode: HADD_U_W
/* 10625 */   MCD_OPC_FilterValue, 23, 10, 0, 0, // Skip to: 10640
/* 10630 */   MCD_OPC_CheckPredicate, 30, 63, 25, 0, // Skip to: 17098
/* 10635 */   MCD_OPC_Decode, 193, 14, 146, 2, // Opcode: HADD_U_D
/* 10640 */   MCD_OPC_FilterValue, 25, 10, 0, 0, // Skip to: 10655
/* 10645 */   MCD_OPC_CheckPredicate, 30, 48, 25, 0, // Skip to: 17098
/* 10650 */   MCD_OPC_Decode, 197, 14, 144, 2, // Opcode: HSUB_S_H
/* 10655 */   MCD_OPC_FilterValue, 26, 10, 0, 0, // Skip to: 10670
/* 10660 */   MCD_OPC_CheckPredicate, 30, 33, 25, 0, // Skip to: 17098
/* 10665 */   MCD_OPC_Decode, 198, 14, 145, 2, // Opcode: HSUB_S_W
/* 10670 */   MCD_OPC_FilterValue, 27, 10, 0, 0, // Skip to: 10685
/* 10675 */   MCD_OPC_CheckPredicate, 30, 18, 25, 0, // Skip to: 17098
/* 10680 */   MCD_OPC_Decode, 196, 14, 146, 2, // Opcode: HSUB_S_D
/* 10685 */   MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 10700
/* 10690 */   MCD_OPC_CheckPredicate, 30, 3, 25, 0, // Skip to: 17098
/* 10695 */   MCD_OPC_Decode, 200, 14, 144, 2, // Opcode: HSUB_U_H
/* 10700 */   MCD_OPC_FilterValue, 30, 10, 0, 0, // Skip to: 10715
/* 10705 */   MCD_OPC_CheckPredicate, 30, 244, 24, 0, // Skip to: 17098
/* 10710 */   MCD_OPC_Decode, 201, 14, 145, 2, // Opcode: HSUB_U_W
/* 10715 */   MCD_OPC_FilterValue, 31, 234, 24, 0, // Skip to: 17098
/* 10720 */   MCD_OPC_CheckPredicate, 30, 229, 24, 0, // Skip to: 17098
/* 10725 */   MCD_OPC_Decode, 199, 14, 146, 2, // Opcode: HSUB_U_D
/* 10730 */   MCD_OPC_FilterValue, 25, 26, 2, 0, // Skip to: 11273
/* 10735 */   MCD_OPC_ExtractField, 20, 6,  // Inst{25-20} ...
/* 10738 */   MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 10753
/* 10743 */   MCD_OPC_CheckPredicate, 30, 206, 24, 0, // Skip to: 17098
/* 10748 */   MCD_OPC_Decode, 211, 21, 158, 2, // Opcode: SLDI_B
/* 10753 */   MCD_OPC_FilterValue, 2, 17, 0, 0, // Skip to: 10775
/* 10758 */   MCD_OPC_CheckPredicate, 30, 191, 24, 0, // Skip to: 17098
/* 10763 */   MCD_OPC_CheckField, 19, 1, 0, 184, 24, 0, // Skip to: 17098
/* 10770 */   MCD_OPC_Decode, 213, 21, 159, 2, // Opcode: SLDI_H
/* 10775 */   MCD_OPC_FilterValue, 3, 62, 0, 0, // Skip to: 10842
/* 10780 */   MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 10783 */   MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 10798
/* 10788 */   MCD_OPC_CheckPredicate, 30, 161, 24, 0, // Skip to: 17098
/* 10793 */   MCD_OPC_Decode, 214, 21, 160, 2, // Opcode: SLDI_W
/* 10798 */   MCD_OPC_FilterValue, 2, 17, 0, 0, // Skip to: 10820
/* 10803 */   MCD_OPC_CheckPredicate, 30, 146, 24, 0, // Skip to: 17098
/* 10808 */   MCD_OPC_CheckField, 17, 1, 0, 139, 24, 0, // Skip to: 17098
/* 10815 */   MCD_OPC_Decode, 212, 21, 161, 2, // Opcode: SLDI_D
/* 10820 */   MCD_OPC_FilterValue, 3, 129, 24, 0, // Skip to: 17098
/* 10825 */   MCD_OPC_CheckPredicate, 30, 124, 24, 0, // Skip to: 17098
/* 10830 */   MCD_OPC_CheckField, 16, 2, 2, 117, 24, 0, // Skip to: 17098
/* 10837 */   MCD_OPC_Decode, 182, 10, 162, 2, // Opcode: CTCMSA
/* 10842 */   MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 10857
/* 10847 */   MCD_OPC_CheckPredicate, 30, 102, 24, 0, // Skip to: 17098
/* 10852 */   MCD_OPC_Decode, 130, 22, 163, 2, // Opcode: SPLATI_B
/* 10857 */   MCD_OPC_FilterValue, 6, 17, 0, 0, // Skip to: 10879
/* 10862 */   MCD_OPC_CheckPredicate, 30, 87, 24, 0, // Skip to: 17098
/* 10867 */   MCD_OPC_CheckField, 19, 1, 0, 80, 24, 0, // Skip to: 17098
/* 10874 */   MCD_OPC_Decode, 132, 22, 164, 2, // Opcode: SPLATI_H
/* 10879 */   MCD_OPC_FilterValue, 7, 62, 0, 0, // Skip to: 10946
/* 10884 */   MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 10887 */   MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 10902
/* 10892 */   MCD_OPC_CheckPredicate, 30, 57, 24, 0, // Skip to: 17098
/* 10897 */   MCD_OPC_Decode, 133, 22, 165, 2, // Opcode: SPLATI_W
/* 10902 */   MCD_OPC_FilterValue, 2, 17, 0, 0, // Skip to: 10924
/* 10907 */   MCD_OPC_CheckPredicate, 30, 42, 24, 0, // Skip to: 17098
/* 10912 */   MCD_OPC_CheckField, 17, 1, 0, 35, 24, 0, // Skip to: 17098
/* 10919 */   MCD_OPC_Decode, 131, 22, 166, 2, // Opcode: SPLATI_D
/* 10924 */   MCD_OPC_FilterValue, 3, 25, 24, 0, // Skip to: 17098
/* 10929 */   MCD_OPC_CheckPredicate, 30, 20, 24, 0, // Skip to: 17098
/* 10934 */   MCD_OPC_CheckField, 16, 2, 2, 13, 24, 0, // Skip to: 17098
/* 10941 */   MCD_OPC_Decode, 147, 9, 167, 2, // Opcode: CFCMSA
/* 10946 */   MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 10961
/* 10951 */   MCD_OPC_CheckPredicate, 30, 254, 23, 0, // Skip to: 17098
/* 10956 */   MCD_OPC_Decode, 158, 10, 168, 2, // Opcode: COPY_S_B
/* 10961 */   MCD_OPC_FilterValue, 10, 17, 0, 0, // Skip to: 10983
/* 10966 */   MCD_OPC_CheckPredicate, 30, 239, 23, 0, // Skip to: 17098
/* 10971 */   MCD_OPC_CheckField, 19, 1, 0, 232, 23, 0, // Skip to: 17098
/* 10978 */   MCD_OPC_Decode, 160, 10, 169, 2, // Opcode: COPY_S_H
/* 10983 */   MCD_OPC_FilterValue, 11, 62, 0, 0, // Skip to: 11050
/* 10988 */   MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 10991 */   MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 11006
/* 10996 */   MCD_OPC_CheckPredicate, 30, 209, 23, 0, // Skip to: 17098
/* 11001 */   MCD_OPC_Decode, 161, 10, 170, 2, // Opcode: COPY_S_W
/* 11006 */   MCD_OPC_FilterValue, 2, 17, 0, 0, // Skip to: 11028
/* 11011 */   MCD_OPC_CheckPredicate, 38, 194, 23, 0, // Skip to: 17098
/* 11016 */   MCD_OPC_CheckField, 17, 1, 0, 187, 23, 0, // Skip to: 17098
/* 11023 */   MCD_OPC_Decode, 159, 10, 171, 2, // Opcode: COPY_S_D
/* 11028 */   MCD_OPC_FilterValue, 3, 177, 23, 0, // Skip to: 17098
/* 11033 */   MCD_OPC_CheckPredicate, 30, 172, 23, 0, // Skip to: 17098
/* 11038 */   MCD_OPC_CheckField, 16, 2, 2, 165, 23, 0, // Skip to: 17098
/* 11045 */   MCD_OPC_Decode, 216, 17, 172, 2, // Opcode: MOVE_V
/* 11050 */   MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 11065
/* 11055 */   MCD_OPC_CheckPredicate, 30, 150, 23, 0, // Skip to: 17098
/* 11060 */   MCD_OPC_Decode, 162, 10, 168, 2, // Opcode: COPY_U_B
/* 11065 */   MCD_OPC_FilterValue, 14, 17, 0, 0, // Skip to: 11087
/* 11070 */   MCD_OPC_CheckPredicate, 30, 135, 23, 0, // Skip to: 17098
/* 11075 */   MCD_OPC_CheckField, 19, 1, 0, 128, 23, 0, // Skip to: 17098
/* 11082 */   MCD_OPC_Decode, 163, 10, 169, 2, // Opcode: COPY_U_H
/* 11087 */   MCD_OPC_FilterValue, 15, 17, 0, 0, // Skip to: 11109
/* 11092 */   MCD_OPC_CheckPredicate, 38, 113, 23, 0, // Skip to: 17098
/* 11097 */   MCD_OPC_CheckField, 18, 2, 0, 106, 23, 0, // Skip to: 17098
/* 11104 */   MCD_OPC_Decode, 164, 10, 170, 2, // Opcode: COPY_U_W
/* 11109 */   MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 11124
/* 11114 */   MCD_OPC_CheckPredicate, 30, 91, 23, 0, // Skip to: 17098
/* 11119 */   MCD_OPC_Decode, 221, 14, 173, 2, // Opcode: INSERT_B
/* 11124 */   MCD_OPC_FilterValue, 18, 17, 0, 0, // Skip to: 11146
/* 11129 */   MCD_OPC_CheckPredicate, 30, 76, 23, 0, // Skip to: 17098
/* 11134 */   MCD_OPC_CheckField, 19, 1, 0, 69, 23, 0, // Skip to: 17098
/* 11141 */   MCD_OPC_Decode, 223, 14, 174, 2, // Opcode: INSERT_H
/* 11146 */   MCD_OPC_FilterValue, 19, 40, 0, 0, // Skip to: 11191
/* 11151 */   MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 11154 */   MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 11169
/* 11159 */   MCD_OPC_CheckPredicate, 30, 46, 23, 0, // Skip to: 17098
/* 11164 */   MCD_OPC_Decode, 224, 14, 175, 2, // Opcode: INSERT_W
/* 11169 */   MCD_OPC_FilterValue, 2, 36, 23, 0, // Skip to: 17098
/* 11174 */   MCD_OPC_CheckPredicate, 38, 31, 23, 0, // Skip to: 17098
/* 11179 */   MCD_OPC_CheckField, 17, 1, 0, 24, 23, 0, // Skip to: 17098
/* 11186 */   MCD_OPC_Decode, 222, 14, 176, 2, // Opcode: INSERT_D
/* 11191 */   MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 11206
/* 11196 */   MCD_OPC_CheckPredicate, 30, 9, 23, 0, // Skip to: 17098
/* 11201 */   MCD_OPC_Decode, 226, 14, 177, 2, // Opcode: INSVE_B
/* 11206 */   MCD_OPC_FilterValue, 22, 17, 0, 0, // Skip to: 11228
/* 11211 */   MCD_OPC_CheckPredicate, 30, 250, 22, 0, // Skip to: 17098
/* 11216 */   MCD_OPC_CheckField, 19, 1, 0, 243, 22, 0, // Skip to: 17098
/* 11223 */   MCD_OPC_Decode, 228, 14, 177, 2, // Opcode: INSVE_H
/* 11228 */   MCD_OPC_FilterValue, 23, 233, 22, 0, // Skip to: 17098
/* 11233 */   MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 11236 */   MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 11251
/* 11241 */   MCD_OPC_CheckPredicate, 30, 220, 22, 0, // Skip to: 17098
/* 11246 */   MCD_OPC_Decode, 229, 14, 177, 2, // Opcode: INSVE_W
/* 11251 */   MCD_OPC_FilterValue, 2, 210, 22, 0, // Skip to: 17098
/* 11256 */   MCD_OPC_CheckPredicate, 30, 205, 22, 0, // Skip to: 17098
/* 11261 */   MCD_OPC_CheckField, 17, 1, 0, 198, 22, 0, // Skip to: 17098
/* 11268 */   MCD_OPC_Decode, 227, 14, 177, 2, // Opcode: INSVE_D
/* 11273 */   MCD_OPC_FilterValue, 26, 227, 1, 0, // Skip to: 11761
/* 11278 */   MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 11281 */   MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 11296
/* 11286 */   MCD_OPC_CheckPredicate, 30, 175, 22, 0, // Skip to: 17098
/* 11291 */   MCD_OPC_Decode, 147, 13, 138, 2, // Opcode: FCAF_W
/* 11296 */   MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 11311
/* 11301 */   MCD_OPC_CheckPredicate, 30, 160, 22, 0, // Skip to: 17098
/* 11306 */   MCD_OPC_Decode, 146, 13, 139, 2, // Opcode: FCAF_D
/* 11311 */   MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 11326
/* 11316 */   MCD_OPC_CheckPredicate, 30, 145, 22, 0, // Skip to: 17098
/* 11321 */   MCD_OPC_Decode, 174, 13, 138, 2, // Opcode: FCUN_W
/* 11326 */   MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 11341
/* 11331 */   MCD_OPC_CheckPredicate, 30, 130, 22, 0, // Skip to: 17098
/* 11336 */   MCD_OPC_Decode, 173, 13, 139, 2, // Opcode: FCUN_D
/* 11341 */   MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 11356
/* 11346 */   MCD_OPC_CheckPredicate, 30, 115, 22, 0, // Skip to: 17098
/* 11351 */   MCD_OPC_Decode, 149, 13, 138, 2, // Opcode: FCEQ_W
/* 11356 */   MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 11371
/* 11361 */   MCD_OPC_CheckPredicate, 30, 100, 22, 0, // Skip to: 17098
/* 11366 */   MCD_OPC_Decode, 148, 13, 139, 2, // Opcode: FCEQ_D
/* 11371 */   MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 11386
/* 11376 */   MCD_OPC_CheckPredicate, 30, 85, 22, 0, // Skip to: 17098
/* 11381 */   MCD_OPC_Decode, 166, 13, 138, 2, // Opcode: FCUEQ_W
/* 11386 */   MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 11401
/* 11391 */   MCD_OPC_CheckPredicate, 30, 70, 22, 0, // Skip to: 17098
/* 11396 */   MCD_OPC_Decode, 165, 13, 139, 2, // Opcode: FCUEQ_D
/* 11401 */   MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 11416
/* 11406 */   MCD_OPC_CheckPredicate, 30, 55, 22, 0, // Skip to: 17098
/* 11411 */   MCD_OPC_Decode, 155, 13, 138, 2, // Opcode: FCLT_W
/* 11416 */   MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 11431
/* 11421 */   MCD_OPC_CheckPredicate, 30, 40, 22, 0, // Skip to: 17098
/* 11426 */   MCD_OPC_Decode, 154, 13, 139, 2, // Opcode: FCLT_D
/* 11431 */   MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 11446
/* 11436 */   MCD_OPC_CheckPredicate, 30, 25, 22, 0, // Skip to: 17098
/* 11441 */   MCD_OPC_Decode, 170, 13, 138, 2, // Opcode: FCULT_W
/* 11446 */   MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 11461
/* 11451 */   MCD_OPC_CheckPredicate, 30, 10, 22, 0, // Skip to: 17098
/* 11456 */   MCD_OPC_Decode, 169, 13, 139, 2, // Opcode: FCULT_D
/* 11461 */   MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 11476
/* 11466 */   MCD_OPC_CheckPredicate, 30, 251, 21, 0, // Skip to: 17098
/* 11471 */   MCD_OPC_Decode, 153, 13, 138, 2, // Opcode: FCLE_W
/* 11476 */   MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 11491
/* 11481 */   MCD_OPC_CheckPredicate, 30, 236, 21, 0, // Skip to: 17098
/* 11486 */   MCD_OPC_Decode, 152, 13, 139, 2, // Opcode: FCLE_D
/* 11491 */   MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 11506
/* 11496 */   MCD_OPC_CheckPredicate, 30, 221, 21, 0, // Skip to: 17098
/* 11501 */   MCD_OPC_Decode, 168, 13, 138, 2, // Opcode: FCULE_W
/* 11506 */   MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 11521
/* 11511 */   MCD_OPC_CheckPredicate, 30, 206, 21, 0, // Skip to: 17098
/* 11516 */   MCD_OPC_Decode, 167, 13, 139, 2, // Opcode: FCULE_D
/* 11521 */   MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 11536
/* 11526 */   MCD_OPC_CheckPredicate, 30, 191, 21, 0, // Skip to: 17098
/* 11531 */   MCD_OPC_Decode, 135, 14, 138, 2, // Opcode: FSAF_W
/* 11536 */   MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 11551
/* 11541 */   MCD_OPC_CheckPredicate, 30, 176, 21, 0, // Skip to: 17098
/* 11546 */   MCD_OPC_Decode, 134, 14, 139, 2, // Opcode: FSAF_D
/* 11551 */   MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 11566
/* 11556 */   MCD_OPC_CheckPredicate, 30, 161, 21, 0, // Skip to: 17098
/* 11561 */   MCD_OPC_Decode, 173, 14, 138, 2, // Opcode: FSUN_W
/* 11566 */   MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 11581
/* 11571 */   MCD_OPC_CheckPredicate, 30, 146, 21, 0, // Skip to: 17098
/* 11576 */   MCD_OPC_Decode, 172, 14, 139, 2, // Opcode: FSUN_D
/* 11581 */   MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 11596
/* 11586 */   MCD_OPC_CheckPredicate, 30, 131, 21, 0, // Skip to: 17098
/* 11591 */   MCD_OPC_Decode, 137, 14, 138, 2, // Opcode: FSEQ_W
/* 11596 */   MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 11611
/* 11601 */   MCD_OPC_CheckPredicate, 30, 116, 21, 0, // Skip to: 17098
/* 11606 */   MCD_OPC_Decode, 136, 14, 139, 2, // Opcode: FSEQ_D
/* 11611 */   MCD_OPC_FilterValue, 22, 10, 0, 0, // Skip to: 11626
/* 11616 */   MCD_OPC_CheckPredicate, 30, 101, 21, 0, // Skip to: 17098
/* 11621 */   MCD_OPC_Decode, 165, 14, 138, 2, // Opcode: FSUEQ_W
/* 11626 */   MCD_OPC_FilterValue, 23, 10, 0, 0, // Skip to: 11641
/* 11631 */   MCD_OPC_CheckPredicate, 30, 86, 21, 0, // Skip to: 17098
/* 11636 */   MCD_OPC_Decode, 164, 14, 139, 2, // Opcode: FSUEQ_D
/* 11641 */   MCD_OPC_FilterValue, 24, 10, 0, 0, // Skip to: 11656
/* 11646 */   MCD_OPC_CheckPredicate, 30, 71, 21, 0, // Skip to: 17098
/* 11651 */   MCD_OPC_Decode, 141, 14, 138, 2, // Opcode: FSLT_W
/* 11656 */   MCD_OPC_FilterValue, 25, 10, 0, 0, // Skip to: 11671
/* 11661 */   MCD_OPC_CheckPredicate, 30, 56, 21, 0, // Skip to: 17098
/* 11666 */   MCD_OPC_Decode, 140, 14, 139, 2, // Opcode: FSLT_D
/* 11671 */   MCD_OPC_FilterValue, 26, 10, 0, 0, // Skip to: 11686
/* 11676 */   MCD_OPC_CheckPredicate, 30, 41, 21, 0, // Skip to: 17098
/* 11681 */   MCD_OPC_Decode, 169, 14, 138, 2, // Opcode: FSULT_W
/* 11686 */   MCD_OPC_FilterValue, 27, 10, 0, 0, // Skip to: 11701
/* 11691 */   MCD_OPC_CheckPredicate, 30, 26, 21, 0, // Skip to: 17098
/* 11696 */   MCD_OPC_Decode, 168, 14, 139, 2, // Opcode: FSULT_D
/* 11701 */   MCD_OPC_FilterValue, 28, 10, 0, 0, // Skip to: 11716
/* 11706 */   MCD_OPC_CheckPredicate, 30, 11, 21, 0, // Skip to: 17098
/* 11711 */   MCD_OPC_Decode, 139, 14, 138, 2, // Opcode: FSLE_W
/* 11716 */   MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 11731
/* 11721 */   MCD_OPC_CheckPredicate, 30, 252, 20, 0, // Skip to: 17098
/* 11726 */   MCD_OPC_Decode, 138, 14, 139, 2, // Opcode: FSLE_D
/* 11731 */   MCD_OPC_FilterValue, 30, 10, 0, 0, // Skip to: 11746
/* 11736 */   MCD_OPC_CheckPredicate, 30, 237, 20, 0, // Skip to: 17098
/* 11741 */   MCD_OPC_Decode, 167, 14, 138, 2, // Opcode: FSULE_W
/* 11746 */   MCD_OPC_FilterValue, 31, 227, 20, 0, // Skip to: 17098
/* 11751 */   MCD_OPC_CheckPredicate, 30, 222, 20, 0, // Skip to: 17098
/* 11756 */   MCD_OPC_Decode, 166, 14, 139, 2, // Opcode: FSULE_D
/* 11761 */   MCD_OPC_FilterValue, 27, 137, 1, 0, // Skip to: 12159
/* 11766 */   MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 11769 */   MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 11784
/* 11774 */   MCD_OPC_CheckPredicate, 30, 199, 20, 0, // Skip to: 17098
/* 11779 */   MCD_OPC_Decode, 145, 13, 138, 2, // Opcode: FADD_W
/* 11784 */   MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 11799
/* 11789 */   MCD_OPC_CheckPredicate, 30, 184, 20, 0, // Skip to: 17098
/* 11794 */   MCD_OPC_Decode, 136, 13, 139, 2, // Opcode: FADD_D
/* 11799 */   MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 11814
/* 11804 */   MCD_OPC_CheckPredicate, 30, 169, 20, 0, // Skip to: 17098
/* 11809 */   MCD_OPC_Decode, 163, 14, 138, 2, // Opcode: FSUB_W
/* 11814 */   MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 11829
/* 11819 */   MCD_OPC_CheckPredicate, 30, 154, 20, 0, // Skip to: 17098
/* 11824 */   MCD_OPC_Decode, 154, 14, 139, 2, // Opcode: FSUB_D
/* 11829 */   MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 11844
/* 11834 */   MCD_OPC_CheckPredicate, 30, 139, 20, 0, // Skip to: 17098
/* 11839 */   MCD_OPC_Decode, 246, 13, 138, 2, // Opcode: FMUL_W
/* 11844 */   MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 11859
/* 11849 */   MCD_OPC_CheckPredicate, 30, 124, 20, 0, // Skip to: 17098
/* 11854 */   MCD_OPC_Decode, 237, 13, 139, 2, // Opcode: FMUL_D
/* 11859 */   MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 11874
/* 11864 */   MCD_OPC_CheckPredicate, 30, 109, 20, 0, // Skip to: 17098
/* 11869 */   MCD_OPC_Decode, 183, 13, 138, 2, // Opcode: FDIV_W
/* 11874 */   MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 11889
/* 11879 */   MCD_OPC_CheckPredicate, 30, 94, 20, 0, // Skip to: 17098
/* 11884 */   MCD_OPC_Decode, 175, 13, 139, 2, // Opcode: FDIV_D
/* 11889 */   MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 11904
/* 11894 */   MCD_OPC_CheckPredicate, 30, 79, 20, 0, // Skip to: 17098
/* 11899 */   MCD_OPC_Decode, 218, 13, 142, 2, // Opcode: FMADD_W
/* 11904 */   MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 11919
/* 11909 */   MCD_OPC_CheckPredicate, 30, 64, 20, 0, // Skip to: 17098
/* 11914 */   MCD_OPC_Decode, 217, 13, 143, 2, // Opcode: FMADD_D
/* 11919 */   MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 11934
/* 11924 */   MCD_OPC_CheckPredicate, 30, 49, 20, 0, // Skip to: 17098
/* 11929 */   MCD_OPC_Decode, 236, 13, 142, 2, // Opcode: FMSUB_W
/* 11934 */   MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 11949
/* 11939 */   MCD_OPC_CheckPredicate, 30, 34, 20, 0, // Skip to: 17098
/* 11944 */   MCD_OPC_Decode, 235, 13, 143, 2, // Opcode: FMSUB_D
/* 11949 */   MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 11964
/* 11954 */   MCD_OPC_CheckPredicate, 30, 19, 20, 0, // Skip to: 17098
/* 11959 */   MCD_OPC_Decode, 187, 13, 138, 2, // Opcode: FEXP2_W
/* 11964 */   MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 11979
/* 11969 */   MCD_OPC_CheckPredicate, 30, 4, 20, 0, // Skip to: 17098
/* 11974 */   MCD_OPC_Decode, 186, 13, 139, 2, // Opcode: FEXP2_D
/* 11979 */   MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 11994
/* 11984 */   MCD_OPC_CheckPredicate, 30, 245, 19, 0, // Skip to: 17098
/* 11989 */   MCD_OPC_Decode, 184, 13, 178, 2, // Opcode: FEXDO_H
/* 11994 */   MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 12009
/* 11999 */   MCD_OPC_CheckPredicate, 30, 230, 19, 0, // Skip to: 17098
/* 12004 */   MCD_OPC_Decode, 185, 13, 179, 2, // Opcode: FEXDO_W
/* 12009 */   MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 12024
/* 12014 */   MCD_OPC_CheckPredicate, 30, 215, 19, 0, // Skip to: 17098
/* 12019 */   MCD_OPC_Decode, 178, 14, 178, 2, // Opcode: FTQ_H
/* 12024 */   MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 12039
/* 12029 */   MCD_OPC_CheckPredicate, 30, 200, 19, 0, // Skip to: 17098
/* 12034 */   MCD_OPC_Decode, 179, 14, 179, 2, // Opcode: FTQ_W
/* 12039 */   MCD_OPC_FilterValue, 24, 10, 0, 0, // Skip to: 12054
/* 12044 */   MCD_OPC_CheckPredicate, 30, 185, 19, 0, // Skip to: 17098
/* 12049 */   MCD_OPC_Decode, 226, 13, 138, 2, // Opcode: FMIN_W
/* 12054 */   MCD_OPC_FilterValue, 25, 10, 0, 0, // Skip to: 12069
/* 12059 */   MCD_OPC_CheckPredicate, 30, 170, 19, 0, // Skip to: 17098
/* 12064 */   MCD_OPC_Decode, 225, 13, 139, 2, // Opcode: FMIN_D
/* 12069 */   MCD_OPC_FilterValue, 26, 10, 0, 0, // Skip to: 12084
/* 12074 */   MCD_OPC_CheckPredicate, 30, 155, 19, 0, // Skip to: 17098
/* 12079 */   MCD_OPC_Decode, 224, 13, 138, 2, // Opcode: FMIN_A_W
/* 12084 */   MCD_OPC_FilterValue, 27, 10, 0, 0, // Skip to: 12099
/* 12089 */   MCD_OPC_CheckPredicate, 30, 140, 19, 0, // Skip to: 17098
/* 12094 */   MCD_OPC_Decode, 223, 13, 139, 2, // Opcode: FMIN_A_D
/* 12099 */   MCD_OPC_FilterValue, 28, 10, 0, 0, // Skip to: 12114
/* 12104 */   MCD_OPC_CheckPredicate, 30, 125, 19, 0, // Skip to: 17098
/* 12109 */   MCD_OPC_Decode, 222, 13, 138, 2, // Opcode: FMAX_W
/* 12114 */   MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 12129
/* 12119 */   MCD_OPC_CheckPredicate, 30, 110, 19, 0, // Skip to: 17098
/* 12124 */   MCD_OPC_Decode, 221, 13, 139, 2, // Opcode: FMAX_D
/* 12129 */   MCD_OPC_FilterValue, 30, 10, 0, 0, // Skip to: 12144
/* 12134 */   MCD_OPC_CheckPredicate, 30, 95, 19, 0, // Skip to: 17098
/* 12139 */   MCD_OPC_Decode, 220, 13, 138, 2, // Opcode: FMAX_A_W
/* 12144 */   MCD_OPC_FilterValue, 31, 85, 19, 0, // Skip to: 17098
/* 12149 */   MCD_OPC_CheckPredicate, 30, 80, 19, 0, // Skip to: 17098
/* 12154 */   MCD_OPC_Decode, 219, 13, 139, 2, // Opcode: FMAX_A_D
/* 12159 */   MCD_OPC_FilterValue, 28, 107, 1, 0, // Skip to: 12527
/* 12164 */   MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 12167 */   MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 12182
/* 12172 */   MCD_OPC_CheckPredicate, 30, 57, 19, 0, // Skip to: 17098
/* 12177 */   MCD_OPC_Decode, 164, 13, 138, 2, // Opcode: FCOR_W
/* 12182 */   MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 12197
/* 12187 */   MCD_OPC_CheckPredicate, 30, 42, 19, 0, // Skip to: 17098
/* 12192 */   MCD_OPC_Decode, 163, 13, 139, 2, // Opcode: FCOR_D
/* 12197 */   MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 12212
/* 12202 */   MCD_OPC_CheckPredicate, 30, 27, 19, 0, // Skip to: 17098
/* 12207 */   MCD_OPC_Decode, 172, 13, 138, 2, // Opcode: FCUNE_W
/* 12212 */   MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 12227
/* 12217 */   MCD_OPC_CheckPredicate, 30, 12, 19, 0, // Skip to: 17098
/* 12222 */   MCD_OPC_Decode, 171, 13, 139, 2, // Opcode: FCUNE_D
/* 12227 */   MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 12242
/* 12232 */   MCD_OPC_CheckPredicate, 30, 253, 18, 0, // Skip to: 17098
/* 12237 */   MCD_OPC_Decode, 162, 13, 138, 2, // Opcode: FCNE_W
/* 12242 */   MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 12257
/* 12247 */   MCD_OPC_CheckPredicate, 30, 238, 18, 0, // Skip to: 17098
/* 12252 */   MCD_OPC_Decode, 161, 13, 139, 2, // Opcode: FCNE_D
/* 12257 */   MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 12272
/* 12262 */   MCD_OPC_CheckPredicate, 30, 223, 18, 0, // Skip to: 17098
/* 12267 */   MCD_OPC_Decode, 250, 18, 137, 2, // Opcode: MUL_Q_H
/* 12272 */   MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 12287
/* 12277 */   MCD_OPC_CheckPredicate, 30, 208, 18, 0, // Skip to: 17098
/* 12282 */   MCD_OPC_Decode, 251, 18, 138, 2, // Opcode: MUL_Q_W
/* 12287 */   MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 12302
/* 12292 */   MCD_OPC_CheckPredicate, 30, 193, 18, 0, // Skip to: 17098
/* 12297 */   MCD_OPC_Decode, 216, 16, 141, 2, // Opcode: MADD_Q_H
/* 12302 */   MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 12317
/* 12307 */   MCD_OPC_CheckPredicate, 30, 178, 18, 0, // Skip to: 17098
/* 12312 */   MCD_OPC_Decode, 217, 16, 142, 2, // Opcode: MADD_Q_W
/* 12317 */   MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 12332
/* 12322 */   MCD_OPC_CheckPredicate, 30, 163, 18, 0, // Skip to: 17098
/* 12327 */   MCD_OPC_Decode, 152, 18, 141, 2, // Opcode: MSUB_Q_H
/* 12332 */   MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 12347
/* 12337 */   MCD_OPC_CheckPredicate, 30, 148, 18, 0, // Skip to: 17098
/* 12342 */   MCD_OPC_Decode, 153, 18, 142, 2, // Opcode: MSUB_Q_W
/* 12347 */   MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 12362
/* 12352 */   MCD_OPC_CheckPredicate, 30, 133, 18, 0, // Skip to: 17098
/* 12357 */   MCD_OPC_Decode, 145, 14, 138, 2, // Opcode: FSOR_W
/* 12362 */   MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 12377
/* 12367 */   MCD_OPC_CheckPredicate, 30, 118, 18, 0, // Skip to: 17098
/* 12372 */   MCD_OPC_Decode, 144, 14, 139, 2, // Opcode: FSOR_D
/* 12377 */   MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 12392
/* 12382 */   MCD_OPC_CheckPredicate, 30, 103, 18, 0, // Skip to: 17098
/* 12387 */   MCD_OPC_Decode, 171, 14, 138, 2, // Opcode: FSUNE_W
/* 12392 */   MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 12407
/* 12397 */   MCD_OPC_CheckPredicate, 30, 88, 18, 0, // Skip to: 17098
/* 12402 */   MCD_OPC_Decode, 170, 14, 139, 2, // Opcode: FSUNE_D
/* 12407 */   MCD_OPC_FilterValue, 22, 10, 0, 0, // Skip to: 12422
/* 12412 */   MCD_OPC_CheckPredicate, 30, 73, 18, 0, // Skip to: 17098
/* 12417 */   MCD_OPC_Decode, 143, 14, 138, 2, // Opcode: FSNE_W
/* 12422 */   MCD_OPC_FilterValue, 23, 10, 0, 0, // Skip to: 12437
/* 12427 */   MCD_OPC_CheckPredicate, 30, 58, 18, 0, // Skip to: 17098
/* 12432 */   MCD_OPC_Decode, 142, 14, 139, 2, // Opcode: FSNE_D
/* 12437 */   MCD_OPC_FilterValue, 24, 10, 0, 0, // Skip to: 12452
/* 12442 */   MCD_OPC_CheckPredicate, 30, 43, 18, 0, // Skip to: 17098
/* 12447 */   MCD_OPC_Decode, 224, 18, 137, 2, // Opcode: MULR_Q_H
/* 12452 */   MCD_OPC_FilterValue, 25, 10, 0, 0, // Skip to: 12467
/* 12457 */   MCD_OPC_CheckPredicate, 30, 28, 18, 0, // Skip to: 17098
/* 12462 */   MCD_OPC_Decode, 225, 18, 138, 2, // Opcode: MULR_Q_W
/* 12467 */   MCD_OPC_FilterValue, 26, 10, 0, 0, // Skip to: 12482
/* 12472 */   MCD_OPC_CheckPredicate, 30, 13, 18, 0, // Skip to: 17098
/* 12477 */   MCD_OPC_Decode, 200, 16, 141, 2, // Opcode: MADDR_Q_H
/* 12482 */   MCD_OPC_FilterValue, 27, 10, 0, 0, // Skip to: 12497
/* 12487 */   MCD_OPC_CheckPredicate, 30, 254, 17, 0, // Skip to: 17098
/* 12492 */   MCD_OPC_Decode, 201, 16, 142, 2, // Opcode: MADDR_Q_W
/* 12497 */   MCD_OPC_FilterValue, 28, 10, 0, 0, // Skip to: 12512
/* 12502 */   MCD_OPC_CheckPredicate, 30, 239, 17, 0, // Skip to: 17098
/* 12507 */   MCD_OPC_Decode, 136, 18, 141, 2, // Opcode: MSUBR_Q_H
/* 12512 */   MCD_OPC_FilterValue, 29, 229, 17, 0, // Skip to: 17098
/* 12517 */   MCD_OPC_CheckPredicate, 30, 224, 17, 0, // Skip to: 17098
/* 12522 */   MCD_OPC_Decode, 137, 18, 142, 2, // Opcode: MSUBR_Q_W
/* 12527 */   MCD_OPC_FilterValue, 30, 76, 3, 0, // Skip to: 13376
/* 12532 */   MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 12535 */   MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 12550
/* 12540 */   MCD_OPC_CheckPredicate, 30, 201, 17, 0, // Skip to: 17098
/* 12545 */   MCD_OPC_Decode, 230, 6, 136, 2, // Opcode: AND_V
/* 12550 */   MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 12565
/* 12555 */   MCD_OPC_CheckPredicate, 30, 186, 17, 0, // Skip to: 17098
/* 12560 */   MCD_OPC_Decode, 174, 19, 136, 2, // Opcode: OR_V
/* 12565 */   MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 12580
/* 12570 */   MCD_OPC_CheckPredicate, 30, 171, 17, 0, // Skip to: 17098
/* 12575 */   MCD_OPC_Decode, 157, 19, 136, 2, // Opcode: NOR_V
/* 12580 */   MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 12595
/* 12585 */   MCD_OPC_CheckPredicate, 30, 156, 17, 0, // Skip to: 17098
/* 12590 */   MCD_OPC_Decode, 183, 24, 136, 2, // Opcode: XOR_V
/* 12595 */   MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 12610
/* 12600 */   MCD_OPC_CheckPredicate, 30, 141, 17, 0, // Skip to: 17098
/* 12605 */   MCD_OPC_Decode, 167, 8, 140, 2, // Opcode: BMNZ_V
/* 12610 */   MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 12625
/* 12615 */   MCD_OPC_CheckPredicate, 30, 126, 17, 0, // Skip to: 17098
/* 12620 */   MCD_OPC_Decode, 169, 8, 140, 2, // Opcode: BMZ_V
/* 12625 */   MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 12640
/* 12630 */   MCD_OPC_CheckPredicate, 30, 111, 17, 0, // Skip to: 17098
/* 12635 */   MCD_OPC_Decode, 220, 8, 140, 2, // Opcode: BSEL_V
/* 12640 */   MCD_OPC_FilterValue, 24, 243, 0, 0, // Skip to: 12888
/* 12645 */   MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 12648 */   MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 12663
/* 12653 */   MCD_OPC_CheckPredicate, 30, 88, 17, 0, // Skip to: 17098
/* 12658 */   MCD_OPC_Decode, 200, 13, 180, 2, // Opcode: FILL_B
/* 12663 */   MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 12678
/* 12668 */   MCD_OPC_CheckPredicate, 30, 73, 17, 0, // Skip to: 17098
/* 12673 */   MCD_OPC_Decode, 202, 13, 181, 2, // Opcode: FILL_H
/* 12678 */   MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 12693
/* 12683 */   MCD_OPC_CheckPredicate, 30, 58, 17, 0, // Skip to: 17098
/* 12688 */   MCD_OPC_Decode, 203, 13, 182, 2, // Opcode: FILL_W
/* 12693 */   MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 12708
/* 12698 */   MCD_OPC_CheckPredicate, 38, 43, 17, 0, // Skip to: 17098
/* 12703 */   MCD_OPC_Decode, 201, 13, 183, 2, // Opcode: FILL_D
/* 12708 */   MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 12723
/* 12713 */   MCD_OPC_CheckPredicate, 30, 28, 17, 0, // Skip to: 17098
/* 12718 */   MCD_OPC_Decode, 193, 19, 172, 2, // Opcode: PCNT_B
/* 12723 */   MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 12738
/* 12728 */   MCD_OPC_CheckPredicate, 30, 13, 17, 0, // Skip to: 17098
/* 12733 */   MCD_OPC_Decode, 195, 19, 184, 2, // Opcode: PCNT_H
/* 12738 */   MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 12753
/* 12743 */   MCD_OPC_CheckPredicate, 30, 254, 16, 0, // Skip to: 17098
/* 12748 */   MCD_OPC_Decode, 196, 19, 185, 2, // Opcode: PCNT_W
/* 12753 */   MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 12768
/* 12758 */   MCD_OPC_CheckPredicate, 30, 239, 16, 0, // Skip to: 17098
/* 12763 */   MCD_OPC_Decode, 194, 19, 186, 2, // Opcode: PCNT_D
/* 12768 */   MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 12783
/* 12773 */   MCD_OPC_CheckPredicate, 30, 224, 16, 0, // Skip to: 17098
/* 12778 */   MCD_OPC_Decode, 131, 19, 172, 2, // Opcode: NLOC_B
/* 12783 */   MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 12798
/* 12788 */   MCD_OPC_CheckPredicate, 30, 209, 16, 0, // Skip to: 17098
/* 12793 */   MCD_OPC_Decode, 133, 19, 184, 2, // Opcode: NLOC_H
/* 12798 */   MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 12813
/* 12803 */   MCD_OPC_CheckPredicate, 30, 194, 16, 0, // Skip to: 17098
/* 12808 */   MCD_OPC_Decode, 134, 19, 185, 2, // Opcode: NLOC_W
/* 12813 */   MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 12828
/* 12818 */   MCD_OPC_CheckPredicate, 30, 179, 16, 0, // Skip to: 17098
/* 12823 */   MCD_OPC_Decode, 132, 19, 186, 2, // Opcode: NLOC_D
/* 12828 */   MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 12843
/* 12833 */   MCD_OPC_CheckPredicate, 30, 164, 16, 0, // Skip to: 17098
/* 12838 */   MCD_OPC_Decode, 135, 19, 172, 2, // Opcode: NLZC_B
/* 12843 */   MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 12858
/* 12848 */   MCD_OPC_CheckPredicate, 30, 149, 16, 0, // Skip to: 17098
/* 12853 */   MCD_OPC_Decode, 137, 19, 184, 2, // Opcode: NLZC_H
/* 12858 */   MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 12873
/* 12863 */   MCD_OPC_CheckPredicate, 30, 134, 16, 0, // Skip to: 17098
/* 12868 */   MCD_OPC_Decode, 138, 19, 185, 2, // Opcode: NLZC_W
/* 12873 */   MCD_OPC_FilterValue, 15, 124, 16, 0, // Skip to: 17098
/* 12878 */   MCD_OPC_CheckPredicate, 30, 119, 16, 0, // Skip to: 17098
/* 12883 */   MCD_OPC_Decode, 136, 19, 186, 2, // Opcode: NLZC_D
/* 12888 */   MCD_OPC_FilterValue, 25, 109, 16, 0, // Skip to: 17098
/* 12893 */   MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 12896 */   MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 12911
/* 12901 */   MCD_OPC_CheckPredicate, 30, 96, 16, 0, // Skip to: 17098
/* 12906 */   MCD_OPC_Decode, 151, 13, 185, 2, // Opcode: FCLASS_W
/* 12911 */   MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 12926
/* 12916 */   MCD_OPC_CheckPredicate, 30, 81, 16, 0, // Skip to: 17098
/* 12921 */   MCD_OPC_Decode, 150, 13, 186, 2, // Opcode: FCLASS_D
/* 12926 */   MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 12941
/* 12931 */   MCD_OPC_CheckPredicate, 30, 66, 16, 0, // Skip to: 17098
/* 12936 */   MCD_OPC_Decode, 181, 14, 185, 2, // Opcode: FTRUNC_S_W
/* 12941 */   MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 12956
/* 12946 */   MCD_OPC_CheckPredicate, 30, 51, 16, 0, // Skip to: 17098
/* 12951 */   MCD_OPC_Decode, 180, 14, 186, 2, // Opcode: FTRUNC_S_D
/* 12956 */   MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 12971
/* 12961 */   MCD_OPC_CheckPredicate, 30, 36, 16, 0, // Skip to: 17098
/* 12966 */   MCD_OPC_Decode, 183, 14, 185, 2, // Opcode: FTRUNC_U_W
/* 12971 */   MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 12986
/* 12976 */   MCD_OPC_CheckPredicate, 30, 21, 16, 0, // Skip to: 17098
/* 12981 */   MCD_OPC_Decode, 182, 14, 186, 2, // Opcode: FTRUNC_U_D
/* 12986 */   MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 13001
/* 12991 */   MCD_OPC_CheckPredicate, 30, 6, 16, 0, // Skip to: 17098
/* 12996 */   MCD_OPC_Decode, 153, 14, 185, 2, // Opcode: FSQRT_W
/* 13001 */   MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 13016
/* 13006 */   MCD_OPC_CheckPredicate, 30, 247, 15, 0, // Skip to: 17098
/* 13011 */   MCD_OPC_Decode, 146, 14, 186, 2, // Opcode: FSQRT_D
/* 13016 */   MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 13031
/* 13021 */   MCD_OPC_CheckPredicate, 30, 232, 15, 0, // Skip to: 17098
/* 13026 */   MCD_OPC_Decode, 133, 14, 185, 2, // Opcode: FRSQRT_W
/* 13031 */   MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 13046
/* 13036 */   MCD_OPC_CheckPredicate, 30, 217, 15, 0, // Skip to: 17098
/* 13041 */   MCD_OPC_Decode, 132, 14, 186, 2, // Opcode: FRSQRT_D
/* 13046 */   MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 13061
/* 13051 */   MCD_OPC_CheckPredicate, 30, 202, 15, 0, // Skip to: 17098
/* 13056 */   MCD_OPC_Decode, 129, 14, 185, 2, // Opcode: FRCP_W
/* 13061 */   MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 13076
/* 13066 */   MCD_OPC_CheckPredicate, 30, 187, 15, 0, // Skip to: 17098
/* 13071 */   MCD_OPC_Decode, 128, 14, 186, 2, // Opcode: FRCP_D
/* 13076 */   MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 13091
/* 13081 */   MCD_OPC_CheckPredicate, 30, 172, 15, 0, // Skip to: 17098
/* 13086 */   MCD_OPC_Decode, 131, 14, 185, 2, // Opcode: FRINT_W
/* 13091 */   MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 13106
/* 13096 */   MCD_OPC_CheckPredicate, 30, 157, 15, 0, // Skip to: 17098
/* 13101 */   MCD_OPC_Decode, 130, 14, 186, 2, // Opcode: FRINT_D
/* 13106 */   MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 13121
/* 13111 */   MCD_OPC_CheckPredicate, 30, 142, 15, 0, // Skip to: 17098
/* 13116 */   MCD_OPC_Decode, 205, 13, 185, 2, // Opcode: FLOG2_W
/* 13121 */   MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 13136
/* 13126 */   MCD_OPC_CheckPredicate, 30, 127, 15, 0, // Skip to: 17098
/* 13131 */   MCD_OPC_Decode, 204, 13, 186, 2, // Opcode: FLOG2_D
/* 13136 */   MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 13151
/* 13141 */   MCD_OPC_CheckPredicate, 30, 112, 15, 0, // Skip to: 17098
/* 13146 */   MCD_OPC_Decode, 189, 13, 187, 2, // Opcode: FEXUPL_W
/* 13151 */   MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 13166
/* 13156 */   MCD_OPC_CheckPredicate, 30, 97, 15, 0, // Skip to: 17098
/* 13161 */   MCD_OPC_Decode, 188, 13, 188, 2, // Opcode: FEXUPL_D
/* 13166 */   MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 13181
/* 13171 */   MCD_OPC_CheckPredicate, 30, 82, 15, 0, // Skip to: 17098
/* 13176 */   MCD_OPC_Decode, 191, 13, 187, 2, // Opcode: FEXUPR_W
/* 13181 */   MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 13196
/* 13186 */   MCD_OPC_CheckPredicate, 30, 67, 15, 0, // Skip to: 17098
/* 13191 */   MCD_OPC_Decode, 190, 13, 188, 2, // Opcode: FEXUPR_D
/* 13196 */   MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 13211
/* 13201 */   MCD_OPC_CheckPredicate, 30, 52, 15, 0, // Skip to: 17098
/* 13206 */   MCD_OPC_Decode, 197, 13, 187, 2, // Opcode: FFQL_W
/* 13211 */   MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 13226
/* 13216 */   MCD_OPC_CheckPredicate, 30, 37, 15, 0, // Skip to: 17098
/* 13221 */   MCD_OPC_Decode, 196, 13, 188, 2, // Opcode: FFQL_D
/* 13226 */   MCD_OPC_FilterValue, 22, 10, 0, 0, // Skip to: 13241
/* 13231 */   MCD_OPC_CheckPredicate, 30, 22, 15, 0, // Skip to: 17098
/* 13236 */   MCD_OPC_Decode, 199, 13, 187, 2, // Opcode: FFQR_W
/* 13241 */   MCD_OPC_FilterValue, 23, 10, 0, 0, // Skip to: 13256
/* 13246 */   MCD_OPC_CheckPredicate, 30, 7, 15, 0, // Skip to: 17098
/* 13251 */   MCD_OPC_Decode, 198, 13, 188, 2, // Opcode: FFQR_D
/* 13256 */   MCD_OPC_FilterValue, 24, 10, 0, 0, // Skip to: 13271
/* 13261 */   MCD_OPC_CheckPredicate, 30, 248, 14, 0, // Skip to: 17098
/* 13266 */   MCD_OPC_Decode, 175, 14, 185, 2, // Opcode: FTINT_S_W
/* 13271 */   MCD_OPC_FilterValue, 25, 10, 0, 0, // Skip to: 13286
/* 13276 */   MCD_OPC_CheckPredicate, 30, 233, 14, 0, // Skip to: 17098
/* 13281 */   MCD_OPC_Decode, 174, 14, 186, 2, // Opcode: FTINT_S_D
/* 13286 */   MCD_OPC_FilterValue, 26, 10, 0, 0, // Skip to: 13301
/* 13291 */   MCD_OPC_CheckPredicate, 30, 218, 14, 0, // Skip to: 17098
/* 13296 */   MCD_OPC_Decode, 177, 14, 185, 2, // Opcode: FTINT_U_W
/* 13301 */   MCD_OPC_FilterValue, 27, 10, 0, 0, // Skip to: 13316
/* 13306 */   MCD_OPC_CheckPredicate, 30, 203, 14, 0, // Skip to: 17098
/* 13311 */   MCD_OPC_Decode, 176, 14, 186, 2, // Opcode: FTINT_U_D
/* 13316 */   MCD_OPC_FilterValue, 28, 10, 0, 0, // Skip to: 13331
/* 13321 */   MCD_OPC_CheckPredicate, 30, 188, 14, 0, // Skip to: 17098
/* 13326 */   MCD_OPC_Decode, 193, 13, 185, 2, // Opcode: FFINT_S_W
/* 13331 */   MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 13346
/* 13336 */   MCD_OPC_CheckPredicate, 30, 173, 14, 0, // Skip to: 17098
/* 13341 */   MCD_OPC_Decode, 192, 13, 186, 2, // Opcode: FFINT_S_D
/* 13346 */   MCD_OPC_FilterValue, 30, 10, 0, 0, // Skip to: 13361
/* 13351 */   MCD_OPC_CheckPredicate, 30, 158, 14, 0, // Skip to: 17098
/* 13356 */   MCD_OPC_Decode, 195, 13, 185, 2, // Opcode: FFINT_U_W
/* 13361 */   MCD_OPC_FilterValue, 31, 148, 14, 0, // Skip to: 17098
/* 13366 */   MCD_OPC_CheckPredicate, 30, 143, 14, 0, // Skip to: 17098
/* 13371 */   MCD_OPC_Decode, 194, 13, 186, 2, // Opcode: FFINT_U_D
/* 13376 */   MCD_OPC_FilterValue, 32, 10, 0, 0, // Skip to: 13391
/* 13381 */   MCD_OPC_CheckPredicate, 30, 128, 14, 0, // Skip to: 17098
/* 13386 */   MCD_OPC_Decode, 198, 15, 189, 2, // Opcode: LD_B
/* 13391 */   MCD_OPC_FilterValue, 33, 10, 0, 0, // Skip to: 13406
/* 13396 */   MCD_OPC_CheckPredicate, 30, 113, 14, 0, // Skip to: 17098
/* 13401 */   MCD_OPC_Decode, 200, 15, 189, 2, // Opcode: LD_H
/* 13406 */   MCD_OPC_FilterValue, 34, 10, 0, 0, // Skip to: 13421
/* 13411 */   MCD_OPC_CheckPredicate, 30, 98, 14, 0, // Skip to: 17098
/* 13416 */   MCD_OPC_Decode, 201, 15, 189, 2, // Opcode: LD_W
/* 13421 */   MCD_OPC_FilterValue, 35, 10, 0, 0, // Skip to: 13436
/* 13426 */   MCD_OPC_CheckPredicate, 30, 83, 14, 0, // Skip to: 17098
/* 13431 */   MCD_OPC_Decode, 199, 15, 189, 2, // Opcode: LD_D
/* 13436 */   MCD_OPC_FilterValue, 36, 10, 0, 0, // Skip to: 13451
/* 13441 */   MCD_OPC_CheckPredicate, 30, 68, 14, 0, // Skip to: 17098
/* 13446 */   MCD_OPC_Decode, 188, 22, 189, 2, // Opcode: ST_B
/* 13451 */   MCD_OPC_FilterValue, 37, 10, 0, 0, // Skip to: 13466
/* 13456 */   MCD_OPC_CheckPredicate, 30, 53, 14, 0, // Skip to: 17098
/* 13461 */   MCD_OPC_Decode, 190, 22, 189, 2, // Opcode: ST_H
/* 13466 */   MCD_OPC_FilterValue, 38, 10, 0, 0, // Skip to: 13481
/* 13471 */   MCD_OPC_CheckPredicate, 30, 38, 14, 0, // Skip to: 17098
/* 13476 */   MCD_OPC_Decode, 191, 22, 189, 2, // Opcode: ST_W
/* 13481 */   MCD_OPC_FilterValue, 39, 28, 14, 0, // Skip to: 17098
/* 13486 */   MCD_OPC_CheckPredicate, 30, 23, 14, 0, // Skip to: 17098
/* 13491 */   MCD_OPC_Decode, 189, 22, 189, 2, // Opcode: ST_D
/* 13496 */   MCD_OPC_FilterValue, 31, 165, 12, 0, // Skip to: 16738
/* 13501 */   MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 13504 */   MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 13519
/* 13509 */   MCD_OPC_CheckPredicate, 28, 0, 14, 0, // Skip to: 17098
/* 13514 */   MCD_OPC_Decode, 227, 12, 190, 2, // Opcode: EXT
/* 13519 */   MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 13534
/* 13524 */   MCD_OPC_CheckPredicate, 28, 241, 13, 0, // Skip to: 17098
/* 13529 */   MCD_OPC_Decode, 220, 14, 191, 2, // Opcode: INS
/* 13534 */   MCD_OPC_FilterValue, 8, 17, 0, 0, // Skip to: 13556
/* 13539 */   MCD_OPC_CheckPredicate, 42, 226, 13, 0, // Skip to: 17098
/* 13544 */   MCD_OPC_CheckField, 6, 5, 0, 219, 13, 0, // Skip to: 17098
/* 13551 */   MCD_OPC_Decode, 254, 13, 192, 2, // Opcode: FORK
/* 13556 */   MCD_OPC_FilterValue, 9, 23, 0, 0, // Skip to: 13584
/* 13561 */   MCD_OPC_CheckPredicate, 42, 204, 13, 0, // Skip to: 17098
/* 13566 */   MCD_OPC_CheckField, 16, 5, 0, 197, 13, 0, // Skip to: 17098
/* 13573 */   MCD_OPC_CheckField, 6, 5, 0, 190, 13, 0, // Skip to: 17098
/* 13580 */   MCD_OPC_Decode, 188, 24, 25, // Opcode: YIELD
/* 13584 */   MCD_OPC_FilterValue, 10, 48, 0, 0, // Skip to: 13637
/* 13589 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 13592 */   MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 13607
/* 13597 */   MCD_OPC_CheckPredicate, 37, 168, 13, 0, // Skip to: 17098
/* 13602 */   MCD_OPC_Decode, 171, 16, 193, 2, // Opcode: LWX
/* 13607 */   MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 13622
/* 13612 */   MCD_OPC_CheckPredicate, 37, 153, 13, 0, // Skip to: 17098
/* 13617 */   MCD_OPC_Decode, 219, 15, 193, 2, // Opcode: LHX
/* 13622 */   MCD_OPC_FilterValue, 6, 143, 13, 0, // Skip to: 17098
/* 13627 */   MCD_OPC_CheckPredicate, 37, 138, 13, 0, // Skip to: 17098
/* 13632 */   MCD_OPC_Decode, 163, 15, 193, 2, // Opcode: LBUX
/* 13637 */   MCD_OPC_FilterValue, 12, 17, 0, 0, // Skip to: 13659
/* 13642 */   MCD_OPC_CheckPredicate, 37, 123, 13, 0, // Skip to: 17098
/* 13647 */   MCD_OPC_CheckField, 6, 10, 0, 116, 13, 0, // Skip to: 17098
/* 13654 */   MCD_OPC_Decode, 225, 14, 194, 2, // Opcode: INSV
/* 13659 */   MCD_OPC_FilterValue, 16, 109, 1, 0, // Skip to: 14029
/* 13664 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 13667 */   MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 13682
/* 13672 */   MCD_OPC_CheckPredicate, 37, 93, 13, 0, // Skip to: 17098
/* 13677 */   MCD_OPC_Decode, 179, 6, 195, 2, // Opcode: ADDU_QB
/* 13682 */   MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 13697
/* 13687 */   MCD_OPC_CheckPredicate, 37, 78, 13, 0, // Skip to: 17098
/* 13692 */   MCD_OPC_Decode, 232, 22, 195, 2, // Opcode: SUBU_QB
/* 13697 */   MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 13712
/* 13702 */   MCD_OPC_CheckPredicate, 37, 63, 13, 0, // Skip to: 17098
/* 13707 */   MCD_OPC_Decode, 183, 6, 195, 2, // Opcode: ADDU_S_QB
/* 13712 */   MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 13727
/* 13717 */   MCD_OPC_CheckPredicate, 37, 48, 13, 0, // Skip to: 17098
/* 13722 */   MCD_OPC_Decode, 236, 22, 195, 2, // Opcode: SUBU_S_QB
/* 13727 */   MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 13742
/* 13732 */   MCD_OPC_CheckPredicate, 37, 33, 13, 0, // Skip to: 17098
/* 13737 */   MCD_OPC_Decode, 211, 18, 195, 2, // Opcode: MULEU_S_PH_QBL
/* 13742 */   MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 13757
/* 13747 */   MCD_OPC_CheckPredicate, 37, 18, 13, 0, // Skip to: 17098
/* 13752 */   MCD_OPC_Decode, 213, 18, 195, 2, // Opcode: MULEU_S_PH_QBR
/* 13757 */   MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 13772
/* 13762 */   MCD_OPC_CheckPredicate, 69, 3, 13, 0, // Skip to: 17098
/* 13767 */   MCD_OPC_Decode, 177, 6, 195, 2, // Opcode: ADDU_PH
/* 13772 */   MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 13787
/* 13777 */   MCD_OPC_CheckPredicate, 69, 244, 12, 0, // Skip to: 17098
/* 13782 */   MCD_OPC_Decode, 230, 22, 195, 2, // Opcode: SUBU_PH
/* 13787 */   MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 13802
/* 13792 */   MCD_OPC_CheckPredicate, 37, 229, 12, 0, // Skip to: 17098
/* 13797 */   MCD_OPC_Decode, 149, 6, 195, 2, // Opcode: ADDQ_PH
/* 13802 */   MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 13817
/* 13807 */   MCD_OPC_CheckPredicate, 37, 214, 12, 0, // Skip to: 17098
/* 13812 */   MCD_OPC_Decode, 201, 22, 195, 2, // Opcode: SUBQ_PH
/* 13817 */   MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 13832
/* 13822 */   MCD_OPC_CheckPredicate, 69, 199, 12, 0, // Skip to: 17098
/* 13827 */   MCD_OPC_Decode, 181, 6, 195, 2, // Opcode: ADDU_S_PH
/* 13832 */   MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 13847
/* 13837 */   MCD_OPC_CheckPredicate, 69, 184, 12, 0, // Skip to: 17098
/* 13842 */   MCD_OPC_Decode, 234, 22, 195, 2, // Opcode: SUBU_S_PH
/* 13847 */   MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 13862
/* 13852 */   MCD_OPC_CheckPredicate, 37, 169, 12, 0, // Skip to: 17098
/* 13857 */   MCD_OPC_Decode, 151, 6, 195, 2, // Opcode: ADDQ_S_PH
/* 13862 */   MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 13877
/* 13867 */   MCD_OPC_CheckPredicate, 37, 154, 12, 0, // Skip to: 17098
/* 13872 */   MCD_OPC_Decode, 203, 22, 195, 2, // Opcode: SUBQ_S_PH
/* 13877 */   MCD_OPC_FilterValue, 16, 9, 0, 0, // Skip to: 13891
/* 13882 */   MCD_OPC_CheckPredicate, 37, 139, 12, 0, // Skip to: 17098
/* 13887 */   MCD_OPC_Decode, 156, 6, 61, // Opcode: ADDSC
/* 13891 */   MCD_OPC_FilterValue, 17, 9, 0, 0, // Skip to: 13905
/* 13896 */   MCD_OPC_CheckPredicate, 37, 125, 12, 0, // Skip to: 17098
/* 13901 */   MCD_OPC_Decode, 193, 6, 61, // Opcode: ADDWC
/* 13905 */   MCD_OPC_FilterValue, 18, 9, 0, 0, // Skip to: 13919
/* 13910 */   MCD_OPC_CheckPredicate, 37, 111, 12, 0, // Skip to: 17098
/* 13915 */   MCD_OPC_Decode, 193, 17, 61, // Opcode: MODSUB
/* 13919 */   MCD_OPC_FilterValue, 20, 17, 0, 0, // Skip to: 13941
/* 13924 */   MCD_OPC_CheckPredicate, 37, 97, 12, 0, // Skip to: 17098
/* 13929 */   MCD_OPC_CheckField, 16, 5, 0, 90, 12, 0, // Skip to: 17098
/* 13936 */   MCD_OPC_Decode, 251, 19, 196, 2, // Opcode: RADDU_W_QB
/* 13941 */   MCD_OPC_FilterValue, 22, 9, 0, 0, // Skip to: 13955
/* 13946 */   MCD_OPC_CheckPredicate, 37, 75, 12, 0, // Skip to: 17098
/* 13951 */   MCD_OPC_Decode, 153, 6, 61, // Opcode: ADDQ_S_W
/* 13955 */   MCD_OPC_FilterValue, 23, 9, 0, 0, // Skip to: 13969
/* 13960 */   MCD_OPC_CheckPredicate, 37, 61, 12, 0, // Skip to: 17098
/* 13965 */   MCD_OPC_Decode, 205, 22, 61, // Opcode: SUBQ_S_W
/* 13969 */   MCD_OPC_FilterValue, 28, 10, 0, 0, // Skip to: 13984
/* 13974 */   MCD_OPC_CheckPredicate, 37, 47, 12, 0, // Skip to: 17098
/* 13979 */   MCD_OPC_Decode, 207, 18, 197, 2, // Opcode: MULEQ_S_W_PHL
/* 13984 */   MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 13999
/* 13989 */   MCD_OPC_CheckPredicate, 37, 32, 12, 0, // Skip to: 17098
/* 13994 */   MCD_OPC_Decode, 209, 18, 197, 2, // Opcode: MULEQ_S_W_PHR
/* 13999 */   MCD_OPC_FilterValue, 30, 10, 0, 0, // Skip to: 14014
/* 14004 */   MCD_OPC_CheckPredicate, 69, 17, 12, 0, // Skip to: 17098
/* 14009 */   MCD_OPC_Decode, 219, 18, 195, 2, // Opcode: MULQ_S_PH
/* 14014 */   MCD_OPC_FilterValue, 31, 7, 12, 0, // Skip to: 17098
/* 14019 */   MCD_OPC_CheckPredicate, 37, 2, 12, 0, // Skip to: 17098
/* 14024 */   MCD_OPC_Decode, 215, 18, 195, 2, // Opcode: MULQ_RS_PH
/* 14029 */   MCD_OPC_FilterValue, 17, 113, 1, 0, // Skip to: 14403
/* 14034 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 14037 */   MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 14058
/* 14042 */   MCD_OPC_CheckPredicate, 37, 235, 11, 0, // Skip to: 17098
/* 14047 */   MCD_OPC_CheckField, 11, 5, 0, 228, 11, 0, // Skip to: 17098
/* 14054 */   MCD_OPC_Decode, 210, 9, 79, // Opcode: CMPU_EQ_QB
/* 14058 */   MCD_OPC_FilterValue, 1, 16, 0, 0, // Skip to: 14079
/* 14063 */   MCD_OPC_CheckPredicate, 37, 214, 11, 0, // Skip to: 17098
/* 14068 */   MCD_OPC_CheckField, 11, 5, 0, 207, 11, 0, // Skip to: 17098
/* 14075 */   MCD_OPC_Decode, 214, 9, 79, // Opcode: CMPU_LT_QB
/* 14079 */   MCD_OPC_FilterValue, 2, 16, 0, 0, // Skip to: 14100
/* 14084 */   MCD_OPC_CheckPredicate, 37, 193, 11, 0, // Skip to: 17098
/* 14089 */   MCD_OPC_CheckField, 11, 5, 0, 186, 11, 0, // Skip to: 17098
/* 14096 */   MCD_OPC_Decode, 212, 9, 79, // Opcode: CMPU_LE_QB
/* 14100 */   MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 14115
/* 14105 */   MCD_OPC_CheckPredicate, 37, 172, 11, 0, // Skip to: 17098
/* 14110 */   MCD_OPC_Decode, 199, 19, 195, 2, // Opcode: PICK_QB
/* 14115 */   MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 14130
/* 14120 */   MCD_OPC_CheckPredicate, 37, 157, 11, 0, // Skip to: 17098
/* 14125 */   MCD_OPC_Decode, 204, 9, 197, 2, // Opcode: CMPGU_EQ_QB
/* 14130 */   MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 14145
/* 14135 */   MCD_OPC_CheckPredicate, 37, 142, 11, 0, // Skip to: 17098
/* 14140 */   MCD_OPC_Decode, 208, 9, 197, 2, // Opcode: CMPGU_LT_QB
/* 14145 */   MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 14160
/* 14150 */   MCD_OPC_CheckPredicate, 37, 127, 11, 0, // Skip to: 17098
/* 14155 */   MCD_OPC_Decode, 206, 9, 197, 2, // Opcode: CMPGU_LE_QB
/* 14160 */   MCD_OPC_FilterValue, 8, 16, 0, 0, // Skip to: 14181
/* 14165 */   MCD_OPC_CheckPredicate, 37, 112, 11, 0, // Skip to: 17098
/* 14170 */   MCD_OPC_CheckField, 11, 5, 0, 105, 11, 0, // Skip to: 17098
/* 14177 */   MCD_OPC_Decode, 220, 9, 79, // Opcode: CMP_EQ_PH
/* 14181 */   MCD_OPC_FilterValue, 9, 16, 0, 0, // Skip to: 14202
/* 14186 */   MCD_OPC_CheckPredicate, 37, 91, 11, 0, // Skip to: 17098
/* 14191 */   MCD_OPC_CheckField, 11, 5, 0, 84, 11, 0, // Skip to: 17098
/* 14198 */   MCD_OPC_Decode, 234, 9, 79, // Opcode: CMP_LT_PH
/* 14202 */   MCD_OPC_FilterValue, 10, 16, 0, 0, // Skip to: 14223
/* 14207 */   MCD_OPC_CheckPredicate, 37, 70, 11, 0, // Skip to: 17098
/* 14212 */   MCD_OPC_CheckField, 11, 5, 0, 63, 11, 0, // Skip to: 17098
/* 14219 */   MCD_OPC_Decode, 228, 9, 79, // Opcode: CMP_LE_PH
/* 14223 */   MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 14238
/* 14228 */   MCD_OPC_CheckPredicate, 37, 49, 11, 0, // Skip to: 17098
/* 14233 */   MCD_OPC_Decode, 197, 19, 195, 2, // Opcode: PICK_PH
/* 14238 */   MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 14253
/* 14243 */   MCD_OPC_CheckPredicate, 37, 34, 11, 0, // Skip to: 17098
/* 14248 */   MCD_OPC_Decode, 228, 19, 195, 2, // Opcode: PRECRQ_QB_PH
/* 14253 */   MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 14268
/* 14258 */   MCD_OPC_CheckPredicate, 69, 19, 11, 0, // Skip to: 17098
/* 14263 */   MCD_OPC_Decode, 232, 19, 195, 2, // Opcode: PRECR_QB_PH
/* 14268 */   MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 14283
/* 14273 */   MCD_OPC_CheckPredicate, 37, 4, 11, 0, // Skip to: 17098
/* 14278 */   MCD_OPC_Decode, 179, 19, 195, 2, // Opcode: PACKRL_PH
/* 14283 */   MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 14298
/* 14288 */   MCD_OPC_CheckPredicate, 37, 245, 10, 0, // Skip to: 17098
/* 14293 */   MCD_OPC_Decode, 224, 19, 195, 2, // Opcode: PRECRQU_S_QB_PH
/* 14298 */   MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 14313
/* 14303 */   MCD_OPC_CheckPredicate, 37, 230, 10, 0, // Skip to: 17098
/* 14308 */   MCD_OPC_Decode, 226, 19, 198, 2, // Opcode: PRECRQ_PH_W
/* 14313 */   MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 14328
/* 14318 */   MCD_OPC_CheckPredicate, 37, 215, 10, 0, // Skip to: 17098
/* 14323 */   MCD_OPC_Decode, 230, 19, 198, 2, // Opcode: PRECRQ_RS_PH_W
/* 14328 */   MCD_OPC_FilterValue, 24, 10, 0, 0, // Skip to: 14343
/* 14333 */   MCD_OPC_CheckPredicate, 69, 200, 10, 0, // Skip to: 17098
/* 14338 */   MCD_OPC_Decode, 198, 9, 197, 2, // Opcode: CMPGDU_EQ_QB
/* 14343 */   MCD_OPC_FilterValue, 25, 10, 0, 0, // Skip to: 14358
/* 14348 */   MCD_OPC_CheckPredicate, 69, 185, 10, 0, // Skip to: 17098
/* 14353 */   MCD_OPC_Decode, 202, 9, 197, 2, // Opcode: CMPGDU_LT_QB
/* 14358 */   MCD_OPC_FilterValue, 26, 10, 0, 0, // Skip to: 14373
/* 14363 */   MCD_OPC_CheckPredicate, 69, 170, 10, 0, // Skip to: 17098
/* 14368 */   MCD_OPC_Decode, 200, 9, 197, 2, // Opcode: CMPGDU_LE_QB
/* 14373 */   MCD_OPC_FilterValue, 30, 10, 0, 0, // Skip to: 14388
/* 14378 */   MCD_OPC_CheckPredicate, 69, 155, 10, 0, // Skip to: 17098
/* 14383 */   MCD_OPC_Decode, 234, 19, 199, 2, // Opcode: PRECR_SRA_PH_W
/* 14388 */   MCD_OPC_FilterValue, 31, 145, 10, 0, // Skip to: 17098
/* 14393 */   MCD_OPC_CheckPredicate, 69, 140, 10, 0, // Skip to: 17098
/* 14398 */   MCD_OPC_Decode, 236, 19, 199, 2, // Opcode: PRECR_SRA_R_PH_W
/* 14403 */   MCD_OPC_FilterValue, 18, 128, 1, 0, // Skip to: 14792
/* 14408 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 14411 */   MCD_OPC_FilterValue, 1, 17, 0, 0, // Skip to: 14433
/* 14416 */   MCD_OPC_CheckPredicate, 69, 117, 10, 0, // Skip to: 17098
/* 14421 */   MCD_OPC_CheckField, 21, 5, 0, 110, 10, 0, // Skip to: 17098
/* 14428 */   MCD_OPC_Decode, 247, 5, 200, 2, // Opcode: ABSQ_S_QB
/* 14433 */   MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 14448
/* 14438 */   MCD_OPC_CheckPredicate, 37, 95, 10, 0, // Skip to: 17098
/* 14443 */   MCD_OPC_Decode, 146, 20, 201, 2, // Opcode: REPL_QB
/* 14448 */   MCD_OPC_FilterValue, 3, 17, 0, 0, // Skip to: 14470
/* 14453 */   MCD_OPC_CheckPredicate, 37, 80, 10, 0, // Skip to: 17098
/* 14458 */   MCD_OPC_CheckField, 21, 5, 0, 73, 10, 0, // Skip to: 17098
/* 14465 */   MCD_OPC_Decode, 142, 20, 202, 2, // Opcode: REPLV_QB
/* 14470 */   MCD_OPC_FilterValue, 4, 17, 0, 0, // Skip to: 14492
/* 14475 */   MCD_OPC_CheckPredicate, 37, 58, 10, 0, // Skip to: 17098
/* 14480 */   MCD_OPC_CheckField, 21, 5, 0, 51, 10, 0, // Skip to: 17098
/* 14487 */   MCD_OPC_Decode, 204, 19, 200, 2, // Opcode: PRECEQU_PH_QBL
/* 14492 */   MCD_OPC_FilterValue, 5, 17, 0, 0, // Skip to: 14514
/* 14497 */   MCD_OPC_CheckPredicate, 37, 36, 10, 0, // Skip to: 17098
/* 14502 */   MCD_OPC_CheckField, 21, 5, 0, 29, 10, 0, // Skip to: 17098
/* 14509 */   MCD_OPC_Decode, 208, 19, 200, 2, // Opcode: PRECEQU_PH_QBR
/* 14514 */   MCD_OPC_FilterValue, 6, 17, 0, 0, // Skip to: 14536
/* 14519 */   MCD_OPC_CheckPredicate, 37, 14, 10, 0, // Skip to: 17098
/* 14524 */   MCD_OPC_CheckField, 21, 5, 0, 7, 10, 0, // Skip to: 17098
/* 14531 */   MCD_OPC_Decode, 205, 19, 200, 2, // Opcode: PRECEQU_PH_QBLA
/* 14536 */   MCD_OPC_FilterValue, 7, 17, 0, 0, // Skip to: 14558
/* 14541 */   MCD_OPC_CheckPredicate, 37, 248, 9, 0, // Skip to: 17098
/* 14546 */   MCD_OPC_CheckField, 21, 5, 0, 241, 9, 0, // Skip to: 17098
/* 14553 */   MCD_OPC_Decode, 209, 19, 200, 2, // Opcode: PRECEQU_PH_QBRA
/* 14558 */   MCD_OPC_FilterValue, 9, 17, 0, 0, // Skip to: 14580
/* 14563 */   MCD_OPC_CheckPredicate, 37, 226, 9, 0, // Skip to: 17098
/* 14568 */   MCD_OPC_CheckField, 21, 5, 0, 219, 9, 0, // Skip to: 17098
/* 14575 */   MCD_OPC_Decode, 245, 5, 200, 2, // Opcode: ABSQ_S_PH
/* 14580 */   MCD_OPC_FilterValue, 10, 9, 0, 0, // Skip to: 14594
/* 14585 */   MCD_OPC_CheckPredicate, 37, 204, 9, 0, // Skip to: 17098
/* 14590 */   MCD_OPC_Decode, 144, 20, 96, // Opcode: REPL_PH
/* 14594 */   MCD_OPC_FilterValue, 11, 17, 0, 0, // Skip to: 14616
/* 14599 */   MCD_OPC_CheckPredicate, 37, 190, 9, 0, // Skip to: 17098
/* 14604 */   MCD_OPC_CheckField, 21, 5, 0, 183, 9, 0, // Skip to: 17098
/* 14611 */   MCD_OPC_Decode, 140, 20, 202, 2, // Opcode: REPLV_PH
/* 14616 */   MCD_OPC_FilterValue, 12, 17, 0, 0, // Skip to: 14638
/* 14621 */   MCD_OPC_CheckPredicate, 37, 168, 9, 0, // Skip to: 17098
/* 14626 */   MCD_OPC_CheckField, 21, 5, 0, 161, 9, 0, // Skip to: 17098
/* 14633 */   MCD_OPC_Decode, 212, 19, 203, 2, // Opcode: PRECEQ_W_PHL
/* 14638 */   MCD_OPC_FilterValue, 13, 17, 0, 0, // Skip to: 14660
/* 14643 */   MCD_OPC_CheckPredicate, 37, 146, 9, 0, // Skip to: 17098
/* 14648 */   MCD_OPC_CheckField, 21, 5, 0, 139, 9, 0, // Skip to: 17098
/* 14655 */   MCD_OPC_Decode, 214, 19, 203, 2, // Opcode: PRECEQ_W_PHR
/* 14660 */   MCD_OPC_FilterValue, 17, 17, 0, 0, // Skip to: 14682
/* 14665 */   MCD_OPC_CheckPredicate, 37, 124, 9, 0, // Skip to: 17098
/* 14670 */   MCD_OPC_CheckField, 21, 5, 0, 117, 9, 0, // Skip to: 17098
/* 14677 */   MCD_OPC_Decode, 249, 5, 204, 2, // Opcode: ABSQ_S_W
/* 14682 */   MCD_OPC_FilterValue, 27, 17, 0, 0, // Skip to: 14704
/* 14687 */   MCD_OPC_CheckPredicate, 37, 102, 9, 0, // Skip to: 17098
/* 14692 */   MCD_OPC_CheckField, 21, 5, 0, 95, 9, 0, // Skip to: 17098
/* 14699 */   MCD_OPC_Decode, 129, 8, 204, 2, // Opcode: BITREV
/* 14704 */   MCD_OPC_FilterValue, 28, 17, 0, 0, // Skip to: 14726
/* 14709 */   MCD_OPC_CheckPredicate, 37, 80, 9, 0, // Skip to: 17098
/* 14714 */   MCD_OPC_CheckField, 21, 5, 0, 73, 9, 0, // Skip to: 17098
/* 14721 */   MCD_OPC_Decode, 216, 19, 200, 2, // Opcode: PRECEU_PH_QBL
/* 14726 */   MCD_OPC_FilterValue, 29, 17, 0, 0, // Skip to: 14748
/* 14731 */   MCD_OPC_CheckPredicate, 37, 58, 9, 0, // Skip to: 17098
/* 14736 */   MCD_OPC_CheckField, 21, 5, 0, 51, 9, 0, // Skip to: 17098
/* 14743 */   MCD_OPC_Decode, 220, 19, 200, 2, // Opcode: PRECEU_PH_QBR
/* 14748 */   MCD_OPC_FilterValue, 30, 17, 0, 0, // Skip to: 14770
/* 14753 */   MCD_OPC_CheckPredicate, 37, 36, 9, 0, // Skip to: 17098
/* 14758 */   MCD_OPC_CheckField, 21, 5, 0, 29, 9, 0, // Skip to: 17098
/* 14765 */   MCD_OPC_Decode, 217, 19, 200, 2, // Opcode: PRECEU_PH_QBLA
/* 14770 */   MCD_OPC_FilterValue, 31, 19, 9, 0, // Skip to: 17098
/* 14775 */   MCD_OPC_CheckPredicate, 37, 14, 9, 0, // Skip to: 17098
/* 14780 */   MCD_OPC_CheckField, 21, 5, 0, 7, 9, 0, // Skip to: 17098
/* 14787 */   MCD_OPC_Decode, 221, 19, 200, 2, // Opcode: PRECEU_PH_QBRA
/* 14792 */   MCD_OPC_FilterValue, 19, 75, 1, 0, // Skip to: 15128
/* 14797 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 14800 */   MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 14815
/* 14805 */   MCD_OPC_CheckPredicate, 37, 240, 8, 0, // Skip to: 17098
/* 14810 */   MCD_OPC_Decode, 168, 21, 205, 2, // Opcode: SHLL_QB
/* 14815 */   MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 14830
/* 14820 */   MCD_OPC_CheckPredicate, 37, 225, 8, 0, // Skip to: 17098
/* 14825 */   MCD_OPC_Decode, 200, 21, 205, 2, // Opcode: SHRL_QB
/* 14830 */   MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 14845
/* 14835 */   MCD_OPC_CheckPredicate, 37, 210, 8, 0, // Skip to: 17098
/* 14840 */   MCD_OPC_Decode, 160, 21, 206, 2, // Opcode: SHLLV_QB
/* 14845 */   MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 14860
/* 14850 */   MCD_OPC_CheckPredicate, 37, 195, 8, 0, // Skip to: 17098
/* 14855 */   MCD_OPC_Decode, 196, 21, 206, 2, // Opcode: SHRLV_QB
/* 14860 */   MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 14875
/* 14865 */   MCD_OPC_CheckPredicate, 69, 180, 8, 0, // Skip to: 17098
/* 14870 */   MCD_OPC_Decode, 186, 21, 205, 2, // Opcode: SHRA_QB
/* 14875 */   MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 14890
/* 14880 */   MCD_OPC_CheckPredicate, 69, 165, 8, 0, // Skip to: 17098
/* 14885 */   MCD_OPC_Decode, 190, 21, 205, 2, // Opcode: SHRA_R_QB
/* 14890 */   MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 14905
/* 14895 */   MCD_OPC_CheckPredicate, 69, 150, 8, 0, // Skip to: 17098
/* 14900 */   MCD_OPC_Decode, 176, 21, 206, 2, // Opcode: SHRAV_QB
/* 14905 */   MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 14920
/* 14910 */   MCD_OPC_CheckPredicate, 69, 135, 8, 0, // Skip to: 17098
/* 14915 */   MCD_OPC_Decode, 180, 21, 206, 2, // Opcode: SHRAV_R_QB
/* 14920 */   MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 14935
/* 14925 */   MCD_OPC_CheckPredicate, 37, 120, 8, 0, // Skip to: 17098
/* 14930 */   MCD_OPC_Decode, 166, 21, 205, 2, // Opcode: SHLL_PH
/* 14935 */   MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 14950
/* 14940 */   MCD_OPC_CheckPredicate, 37, 105, 8, 0, // Skip to: 17098
/* 14945 */   MCD_OPC_Decode, 184, 21, 205, 2, // Opcode: SHRA_PH
/* 14950 */   MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 14965
/* 14955 */   MCD_OPC_CheckPredicate, 37, 90, 8, 0, // Skip to: 17098
/* 14960 */   MCD_OPC_Decode, 158, 21, 206, 2, // Opcode: SHLLV_PH
/* 14965 */   MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 14980
/* 14970 */   MCD_OPC_CheckPredicate, 37, 75, 8, 0, // Skip to: 17098
/* 14975 */   MCD_OPC_Decode, 174, 21, 206, 2, // Opcode: SHRAV_PH
/* 14980 */   MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 14995
/* 14985 */   MCD_OPC_CheckPredicate, 37, 60, 8, 0, // Skip to: 17098
/* 14990 */   MCD_OPC_Decode, 170, 21, 205, 2, // Opcode: SHLL_S_PH
/* 14995 */   MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 15010
/* 15000 */   MCD_OPC_CheckPredicate, 37, 45, 8, 0, // Skip to: 17098
/* 15005 */   MCD_OPC_Decode, 188, 21, 205, 2, // Opcode: SHRA_R_PH
/* 15010 */   MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 15025
/* 15015 */   MCD_OPC_CheckPredicate, 37, 30, 8, 0, // Skip to: 17098
/* 15020 */   MCD_OPC_Decode, 162, 21, 206, 2, // Opcode: SHLLV_S_PH
/* 15025 */   MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 15040
/* 15030 */   MCD_OPC_CheckPredicate, 37, 15, 8, 0, // Skip to: 17098
/* 15035 */   MCD_OPC_Decode, 178, 21, 206, 2, // Opcode: SHRAV_R_PH
/* 15040 */   MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 15055
/* 15045 */   MCD_OPC_CheckPredicate, 37, 0, 8, 0, // Skip to: 17098
/* 15050 */   MCD_OPC_Decode, 172, 21, 207, 2, // Opcode: SHLL_S_W
/* 15055 */   MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 15070
/* 15060 */   MCD_OPC_CheckPredicate, 37, 241, 7, 0, // Skip to: 17098
/* 15065 */   MCD_OPC_Decode, 192, 21, 207, 2, // Opcode: SHRA_R_W
/* 15070 */   MCD_OPC_FilterValue, 22, 9, 0, 0, // Skip to: 15084
/* 15075 */   MCD_OPC_CheckPredicate, 37, 226, 7, 0, // Skip to: 17098
/* 15080 */   MCD_OPC_Decode, 164, 21, 55, // Opcode: SHLLV_S_W
/* 15084 */   MCD_OPC_FilterValue, 23, 9, 0, 0, // Skip to: 15098
/* 15089 */   MCD_OPC_CheckPredicate, 37, 212, 7, 0, // Skip to: 17098
/* 15094 */   MCD_OPC_Decode, 182, 21, 55, // Opcode: SHRAV_R_W
/* 15098 */   MCD_OPC_FilterValue, 25, 10, 0, 0, // Skip to: 15113
/* 15103 */   MCD_OPC_CheckPredicate, 69, 198, 7, 0, // Skip to: 17098
/* 15108 */   MCD_OPC_Decode, 198, 21, 205, 2, // Opcode: SHRL_PH
/* 15113 */   MCD_OPC_FilterValue, 27, 188, 7, 0, // Skip to: 17098
/* 15118 */   MCD_OPC_CheckPredicate, 69, 183, 7, 0, // Skip to: 17098
/* 15123 */   MCD_OPC_Decode, 194, 21, 206, 2, // Opcode: SHRLV_PH
/* 15128 */   MCD_OPC_FilterValue, 24, 237, 0, 0, // Skip to: 15370
/* 15133 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 15136 */   MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 15151
/* 15141 */   MCD_OPC_CheckPredicate, 69, 160, 7, 0, // Skip to: 17098
/* 15146 */   MCD_OPC_Decode, 172, 6, 195, 2, // Opcode: ADDUH_QB
/* 15151 */   MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 15166
/* 15156 */   MCD_OPC_CheckPredicate, 69, 145, 7, 0, // Skip to: 17098
/* 15161 */   MCD_OPC_Decode, 225, 22, 195, 2, // Opcode: SUBUH_QB
/* 15166 */   MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 15181
/* 15171 */   MCD_OPC_CheckPredicate, 69, 130, 7, 0, // Skip to: 17098
/* 15176 */   MCD_OPC_Decode, 174, 6, 195, 2, // Opcode: ADDUH_R_QB
/* 15181 */   MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 15196
/* 15186 */   MCD_OPC_CheckPredicate, 69, 115, 7, 0, // Skip to: 17098
/* 15191 */   MCD_OPC_Decode, 227, 22, 195, 2, // Opcode: SUBUH_R_QB
/* 15196 */   MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 15211
/* 15201 */   MCD_OPC_CheckPredicate, 69, 100, 7, 0, // Skip to: 17098
/* 15206 */   MCD_OPC_Decode, 141, 6, 195, 2, // Opcode: ADDQH_PH
/* 15211 */   MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 15226
/* 15216 */   MCD_OPC_CheckPredicate, 69, 85, 7, 0, // Skip to: 17098
/* 15221 */   MCD_OPC_Decode, 193, 22, 195, 2, // Opcode: SUBQH_PH
/* 15226 */   MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 15241
/* 15231 */   MCD_OPC_CheckPredicate, 69, 70, 7, 0, // Skip to: 17098
/* 15236 */   MCD_OPC_Decode, 143, 6, 195, 2, // Opcode: ADDQH_R_PH
/* 15241 */   MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 15256
/* 15246 */   MCD_OPC_CheckPredicate, 69, 55, 7, 0, // Skip to: 17098
/* 15251 */   MCD_OPC_Decode, 195, 22, 195, 2, // Opcode: SUBQH_R_PH
/* 15256 */   MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 15271
/* 15261 */   MCD_OPC_CheckPredicate, 69, 40, 7, 0, // Skip to: 17098
/* 15266 */   MCD_OPC_Decode, 248, 18, 195, 2, // Opcode: MUL_PH
/* 15271 */   MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 15286
/* 15276 */   MCD_OPC_CheckPredicate, 69, 25, 7, 0, // Skip to: 17098
/* 15281 */   MCD_OPC_Decode, 253, 18, 195, 2, // Opcode: MUL_S_PH
/* 15286 */   MCD_OPC_FilterValue, 16, 9, 0, 0, // Skip to: 15300
/* 15291 */   MCD_OPC_CheckPredicate, 69, 10, 7, 0, // Skip to: 17098
/* 15296 */   MCD_OPC_Decode, 147, 6, 61, // Opcode: ADDQH_W
/* 15300 */   MCD_OPC_FilterValue, 17, 9, 0, 0, // Skip to: 15314
/* 15305 */   MCD_OPC_CheckPredicate, 69, 252, 6, 0, // Skip to: 17098
/* 15310 */   MCD_OPC_Decode, 199, 22, 61, // Opcode: SUBQH_W
/* 15314 */   MCD_OPC_FilterValue, 18, 9, 0, 0, // Skip to: 15328
/* 15319 */   MCD_OPC_CheckPredicate, 69, 238, 6, 0, // Skip to: 17098
/* 15324 */   MCD_OPC_Decode, 145, 6, 61, // Opcode: ADDQH_R_W
/* 15328 */   MCD_OPC_FilterValue, 19, 9, 0, 0, // Skip to: 15342
/* 15333 */   MCD_OPC_CheckPredicate, 69, 224, 6, 0, // Skip to: 17098
/* 15338 */   MCD_OPC_Decode, 197, 22, 61, // Opcode: SUBQH_R_W
/* 15342 */   MCD_OPC_FilterValue, 22, 9, 0, 0, // Skip to: 15356
/* 15347 */   MCD_OPC_CheckPredicate, 69, 210, 6, 0, // Skip to: 17098
/* 15352 */   MCD_OPC_Decode, 221, 18, 61, // Opcode: MULQ_S_W
/* 15356 */   MCD_OPC_FilterValue, 23, 201, 6, 0, // Skip to: 17098
/* 15361 */   MCD_OPC_CheckPredicate, 69, 196, 6, 0, // Skip to: 17098
/* 15366 */   MCD_OPC_Decode, 217, 18, 61, // Opcode: MULQ_RS_W
/* 15370 */   MCD_OPC_FilterValue, 25, 17, 0, 0, // Skip to: 15392
/* 15375 */   MCD_OPC_CheckPredicate, 70, 182, 6, 0, // Skip to: 17098
/* 15380 */   MCD_OPC_CheckField, 6, 1, 0, 175, 6, 0, // Skip to: 17098
/* 15387 */   MCD_OPC_Decode, 151, 16, 208, 2, // Opcode: LWLE
/* 15392 */   MCD_OPC_FilterValue, 26, 17, 0, 0, // Skip to: 15414
/* 15397 */   MCD_OPC_CheckPredicate, 70, 160, 6, 0, // Skip to: 17098
/* 15402 */   MCD_OPC_CheckField, 6, 1, 0, 153, 6, 0, // Skip to: 17098
/* 15409 */   MCD_OPC_Decode, 164, 16, 208, 2, // Opcode: LWRE
/* 15414 */   MCD_OPC_FilterValue, 27, 17, 0, 0, // Skip to: 15436
/* 15419 */   MCD_OPC_CheckPredicate, 44, 138, 6, 0, // Skip to: 17098
/* 15424 */   MCD_OPC_CheckField, 6, 1, 0, 131, 6, 0, // Skip to: 17098
/* 15431 */   MCD_OPC_Decode, 247, 8, 209, 2, // Opcode: CACHEE
/* 15436 */   MCD_OPC_FilterValue, 28, 17, 0, 0, // Skip to: 15458
/* 15441 */   MCD_OPC_CheckPredicate, 44, 116, 6, 0, // Skip to: 17098
/* 15446 */   MCD_OPC_CheckField, 6, 1, 0, 109, 6, 0, // Skip to: 17098
/* 15453 */   MCD_OPC_Decode, 198, 20, 208, 2, // Opcode: SBE
/* 15458 */   MCD_OPC_FilterValue, 29, 17, 0, 0, // Skip to: 15480
/* 15463 */   MCD_OPC_CheckPredicate, 44, 94, 6, 0, // Skip to: 17098
/* 15468 */   MCD_OPC_CheckField, 6, 1, 0, 87, 6, 0, // Skip to: 17098
/* 15475 */   MCD_OPC_Decode, 148, 21, 208, 2, // Opcode: SHE
/* 15480 */   MCD_OPC_FilterValue, 30, 17, 0, 0, // Skip to: 15502
/* 15485 */   MCD_OPC_CheckPredicate, 44, 72, 6, 0, // Skip to: 17098
/* 15490 */   MCD_OPC_CheckField, 6, 1, 0, 65, 6, 0, // Skip to: 17098
/* 15497 */   MCD_OPC_Decode, 211, 20, 208, 2, // Opcode: SCE
/* 15502 */   MCD_OPC_FilterValue, 31, 17, 0, 0, // Skip to: 15524
/* 15507 */   MCD_OPC_CheckPredicate, 44, 50, 6, 0, // Skip to: 17098
/* 15512 */   MCD_OPC_CheckField, 6, 1, 0, 43, 6, 0, // Skip to: 17098
/* 15519 */   MCD_OPC_Decode, 142, 23, 208, 2, // Opcode: SWE
/* 15524 */   MCD_OPC_FilterValue, 32, 69, 0, 0, // Skip to: 15598
/* 15529 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 15532 */   MCD_OPC_FilterValue, 2, 17, 0, 0, // Skip to: 15554
/* 15537 */   MCD_OPC_CheckPredicate, 28, 20, 6, 0, // Skip to: 17098
/* 15542 */   MCD_OPC_CheckField, 21, 5, 0, 13, 6, 0, // Skip to: 17098
/* 15549 */   MCD_OPC_Decode, 169, 24, 204, 2, // Opcode: WSBH
/* 15554 */   MCD_OPC_FilterValue, 16, 17, 0, 0, // Skip to: 15576
/* 15559 */   MCD_OPC_CheckPredicate, 28, 254, 5, 0, // Skip to: 17098
/* 15564 */   MCD_OPC_CheckField, 21, 5, 0, 247, 5, 0, // Skip to: 17098
/* 15571 */   MCD_OPC_Decode, 242, 20, 204, 2, // Opcode: SEB
/* 15576 */   MCD_OPC_FilterValue, 24, 237, 5, 0, // Skip to: 17098
/* 15581 */   MCD_OPC_CheckPredicate, 28, 232, 5, 0, // Skip to: 17098
/* 15586 */   MCD_OPC_CheckField, 21, 5, 0, 225, 5, 0, // Skip to: 17098
/* 15593 */   MCD_OPC_Decode, 246, 20, 204, 2, // Opcode: SEH
/* 15598 */   MCD_OPC_FilterValue, 33, 17, 0, 0, // Skip to: 15620
/* 15603 */   MCD_OPC_CheckPredicate, 70, 210, 5, 0, // Skip to: 17098
/* 15608 */   MCD_OPC_CheckField, 6, 1, 0, 203, 5, 0, // Skip to: 17098
/* 15615 */   MCD_OPC_Decode, 148, 23, 208, 2, // Opcode: SWLE
/* 15620 */   MCD_OPC_FilterValue, 34, 17, 0, 0, // Skip to: 15642
/* 15625 */   MCD_OPC_CheckPredicate, 70, 188, 5, 0, // Skip to: 17098
/* 15630 */   MCD_OPC_CheckField, 6, 1, 0, 181, 5, 0, // Skip to: 17098
/* 15637 */   MCD_OPC_Decode, 159, 23, 208, 2, // Opcode: SWRE
/* 15642 */   MCD_OPC_FilterValue, 35, 17, 0, 0, // Skip to: 15664
/* 15647 */   MCD_OPC_CheckPredicate, 44, 166, 5, 0, // Skip to: 17098
/* 15652 */   MCD_OPC_CheckField, 6, 1, 0, 159, 5, 0, // Skip to: 17098
/* 15659 */   MCD_OPC_Decode, 239, 19, 209, 2, // Opcode: PREFE
/* 15664 */   MCD_OPC_FilterValue, 40, 17, 0, 0, // Skip to: 15686
/* 15669 */   MCD_OPC_CheckPredicate, 44, 144, 5, 0, // Skip to: 17098
/* 15674 */   MCD_OPC_CheckField, 6, 1, 0, 137, 5, 0, // Skip to: 17098
/* 15681 */   MCD_OPC_Decode, 176, 15, 208, 2, // Opcode: LBuE
/* 15686 */   MCD_OPC_FilterValue, 41, 17, 0, 0, // Skip to: 15708
/* 15691 */   MCD_OPC_CheckPredicate, 44, 122, 5, 0, // Skip to: 17098
/* 15696 */   MCD_OPC_CheckField, 6, 1, 0, 115, 5, 0, // Skip to: 17098
/* 15703 */   MCD_OPC_Decode, 228, 15, 208, 2, // Opcode: LHuE
/* 15708 */   MCD_OPC_FilterValue, 44, 17, 0, 0, // Skip to: 15730
/* 15713 */   MCD_OPC_CheckPredicate, 44, 100, 5, 0, // Skip to: 17098
/* 15718 */   MCD_OPC_CheckField, 6, 1, 0, 93, 5, 0, // Skip to: 17098
/* 15725 */   MCD_OPC_Decode, 157, 15, 208, 2, // Opcode: LBE
/* 15730 */   MCD_OPC_FilterValue, 45, 17, 0, 0, // Skip to: 15752
/* 15735 */   MCD_OPC_CheckPredicate, 44, 78, 5, 0, // Skip to: 17098
/* 15740 */   MCD_OPC_CheckField, 6, 1, 0, 71, 5, 0, // Skip to: 17098
/* 15747 */   MCD_OPC_Decode, 209, 15, 208, 2, // Opcode: LHE
/* 15752 */   MCD_OPC_FilterValue, 46, 17, 0, 0, // Skip to: 15774
/* 15757 */   MCD_OPC_CheckPredicate, 44, 56, 5, 0, // Skip to: 17098
/* 15762 */   MCD_OPC_CheckField, 6, 1, 0, 49, 5, 0, // Skip to: 17098
/* 15769 */   MCD_OPC_Decode, 240, 15, 208, 2, // Opcode: LLE
/* 15774 */   MCD_OPC_FilterValue, 47, 17, 0, 0, // Skip to: 15796
/* 15779 */   MCD_OPC_CheckPredicate, 44, 34, 5, 0, // Skip to: 17098
/* 15784 */   MCD_OPC_CheckField, 6, 1, 0, 27, 5, 0, // Skip to: 17098
/* 15791 */   MCD_OPC_Decode, 144, 16, 208, 2, // Opcode: LWE
/* 15796 */   MCD_OPC_FilterValue, 48, 231, 1, 0, // Skip to: 16288
/* 15801 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 15804 */   MCD_OPC_FilterValue, 0, 17, 0, 0, // Skip to: 15826
/* 15809 */   MCD_OPC_CheckPredicate, 69, 4, 5, 0, // Skip to: 17098
/* 15814 */   MCD_OPC_CheckField, 13, 3, 0, 253, 4, 0, // Skip to: 17098
/* 15821 */   MCD_OPC_Decode, 156, 12, 243, 1, // Opcode: DPA_W_PH
/* 15826 */   MCD_OPC_FilterValue, 1, 17, 0, 0, // Skip to: 15848
/* 15831 */   MCD_OPC_CheckPredicate, 69, 238, 4, 0, // Skip to: 17098
/* 15836 */   MCD_OPC_CheckField, 13, 3, 0, 231, 4, 0, // Skip to: 17098
/* 15843 */   MCD_OPC_Decode, 179, 12, 243, 1, // Opcode: DPS_W_PH
/* 15848 */   MCD_OPC_FilterValue, 2, 17, 0, 0, // Skip to: 15870
/* 15853 */   MCD_OPC_CheckPredicate, 69, 216, 4, 0, // Skip to: 17098
/* 15858 */   MCD_OPC_CheckField, 13, 3, 0, 209, 4, 0, // Skip to: 17098
/* 15865 */   MCD_OPC_Decode, 228, 18, 243, 1, // Opcode: MULSA_W_PH
/* 15870 */   MCD_OPC_FilterValue, 3, 17, 0, 0, // Skip to: 15892
/* 15875 */   MCD_OPC_CheckPredicate, 37, 194, 4, 0, // Skip to: 17098
/* 15880 */   MCD_OPC_CheckField, 13, 3, 0, 187, 4, 0, // Skip to: 17098
/* 15887 */   MCD_OPC_Decode, 150, 12, 243, 1, // Opcode: DPAU_H_QBL
/* 15892 */   MCD_OPC_FilterValue, 4, 17, 0, 0, // Skip to: 15914
/* 15897 */   MCD_OPC_CheckPredicate, 37, 172, 4, 0, // Skip to: 17098
/* 15902 */   MCD_OPC_CheckField, 13, 3, 0, 165, 4, 0, // Skip to: 17098
/* 15909 */   MCD_OPC_Decode, 148, 12, 243, 1, // Opcode: DPAQ_S_W_PH
/* 15914 */   MCD_OPC_FilterValue, 5, 17, 0, 0, // Skip to: 15936
/* 15919 */   MCD_OPC_CheckPredicate, 37, 150, 4, 0, // Skip to: 17098
/* 15924 */   MCD_OPC_CheckField, 13, 3, 0, 143, 4, 0, // Skip to: 17098
/* 15931 */   MCD_OPC_Decode, 165, 12, 243, 1, // Opcode: DPSQ_S_W_PH
/* 15936 */   MCD_OPC_FilterValue, 6, 17, 0, 0, // Skip to: 15958
/* 15941 */   MCD_OPC_CheckPredicate, 37, 128, 4, 0, // Skip to: 17098
/* 15946 */   MCD_OPC_CheckField, 13, 3, 0, 121, 4, 0, // Skip to: 17098
/* 15953 */   MCD_OPC_Decode, 226, 18, 243, 1, // Opcode: MULSAQ_S_W_PH
/* 15958 */   MCD_OPC_FilterValue, 7, 17, 0, 0, // Skip to: 15980
/* 15963 */   MCD_OPC_CheckPredicate, 37, 106, 4, 0, // Skip to: 17098
/* 15968 */   MCD_OPC_CheckField, 13, 3, 0, 99, 4, 0, // Skip to: 17098
/* 15975 */   MCD_OPC_Decode, 152, 12, 243, 1, // Opcode: DPAU_H_QBR
/* 15980 */   MCD_OPC_FilterValue, 8, 17, 0, 0, // Skip to: 16002
/* 15985 */   MCD_OPC_CheckPredicate, 69, 84, 4, 0, // Skip to: 17098
/* 15990 */   MCD_OPC_CheckField, 13, 3, 0, 77, 4, 0, // Skip to: 17098
/* 15997 */   MCD_OPC_Decode, 154, 12, 243, 1, // Opcode: DPAX_W_PH
/* 16002 */   MCD_OPC_FilterValue, 9, 17, 0, 0, // Skip to: 16024
/* 16007 */   MCD_OPC_CheckPredicate, 69, 62, 4, 0, // Skip to: 17098
/* 16012 */   MCD_OPC_CheckField, 13, 3, 0, 55, 4, 0, // Skip to: 17098
/* 16019 */   MCD_OPC_Decode, 177, 12, 243, 1, // Opcode: DPSX_W_PH
/* 16024 */   MCD_OPC_FilterValue, 11, 17, 0, 0, // Skip to: 16046
/* 16029 */   MCD_OPC_CheckPredicate, 37, 40, 4, 0, // Skip to: 17098
/* 16034 */   MCD_OPC_CheckField, 13, 3, 0, 33, 4, 0, // Skip to: 17098
/* 16041 */   MCD_OPC_Decode, 173, 12, 243, 1, // Opcode: DPSU_H_QBL
/* 16046 */   MCD_OPC_FilterValue, 12, 17, 0, 0, // Skip to: 16068
/* 16051 */   MCD_OPC_CheckPredicate, 37, 18, 4, 0, // Skip to: 17098
/* 16056 */   MCD_OPC_CheckField, 13, 3, 0, 11, 4, 0, // Skip to: 17098
/* 16063 */   MCD_OPC_Decode, 146, 12, 243, 1, // Opcode: DPAQ_SA_L_W
/* 16068 */   MCD_OPC_FilterValue, 13, 17, 0, 0, // Skip to: 16090
/* 16073 */   MCD_OPC_CheckPredicate, 37, 252, 3, 0, // Skip to: 17098
/* 16078 */   MCD_OPC_CheckField, 13, 3, 0, 245, 3, 0, // Skip to: 17098
/* 16085 */   MCD_OPC_Decode, 163, 12, 243, 1, // Opcode: DPSQ_SA_L_W
/* 16090 */   MCD_OPC_FilterValue, 15, 17, 0, 0, // Skip to: 16112
/* 16095 */   MCD_OPC_CheckPredicate, 37, 230, 3, 0, // Skip to: 17098
/* 16100 */   MCD_OPC_CheckField, 13, 3, 0, 223, 3, 0, // Skip to: 17098
/* 16107 */   MCD_OPC_Decode, 175, 12, 243, 1, // Opcode: DPSU_H_QBR
/* 16112 */   MCD_OPC_FilterValue, 16, 17, 0, 0, // Skip to: 16134
/* 16117 */   MCD_OPC_CheckPredicate, 37, 208, 3, 0, // Skip to: 17098
/* 16122 */   MCD_OPC_CheckField, 13, 3, 0, 201, 3, 0, // Skip to: 17098
/* 16129 */   MCD_OPC_Decode, 220, 16, 243, 1, // Opcode: MAQ_SA_W_PHL
/* 16134 */   MCD_OPC_FilterValue, 18, 17, 0, 0, // Skip to: 16156
/* 16139 */   MCD_OPC_CheckPredicate, 37, 186, 3, 0, // Skip to: 17098
/* 16144 */   MCD_OPC_CheckField, 13, 3, 0, 179, 3, 0, // Skip to: 17098
/* 16151 */   MCD_OPC_Decode, 222, 16, 243, 1, // Opcode: MAQ_SA_W_PHR
/* 16156 */   MCD_OPC_FilterValue, 20, 17, 0, 0, // Skip to: 16178
/* 16161 */   MCD_OPC_CheckPredicate, 37, 164, 3, 0, // Skip to: 17098
/* 16166 */   MCD_OPC_CheckField, 13, 3, 0, 157, 3, 0, // Skip to: 17098
/* 16173 */   MCD_OPC_Decode, 224, 16, 243, 1, // Opcode: MAQ_S_W_PHL
/* 16178 */   MCD_OPC_FilterValue, 22, 17, 0, 0, // Skip to: 16200
/* 16183 */   MCD_OPC_CheckPredicate, 37, 142, 3, 0, // Skip to: 17098
/* 16188 */   MCD_OPC_CheckField, 13, 3, 0, 135, 3, 0, // Skip to: 17098
/* 16195 */   MCD_OPC_Decode, 226, 16, 243, 1, // Opcode: MAQ_S_W_PHR
/* 16200 */   MCD_OPC_FilterValue, 24, 17, 0, 0, // Skip to: 16222
/* 16205 */   MCD_OPC_CheckPredicate, 69, 120, 3, 0, // Skip to: 17098
/* 16210 */   MCD_OPC_CheckField, 13, 3, 0, 113, 3, 0, // Skip to: 17098
/* 16217 */   MCD_OPC_Decode, 144, 12, 243, 1, // Opcode: DPAQX_S_W_PH
/* 16222 */   MCD_OPC_FilterValue, 25, 17, 0, 0, // Skip to: 16244
/* 16227 */   MCD_OPC_CheckPredicate, 69, 98, 3, 0, // Skip to: 17098
/* 16232 */   MCD_OPC_CheckField, 13, 3, 0, 91, 3, 0, // Skip to: 17098
/* 16239 */   MCD_OPC_Decode, 161, 12, 243, 1, // Opcode: DPSQX_S_W_PH
/* 16244 */   MCD_OPC_FilterValue, 26, 17, 0, 0, // Skip to: 16266
/* 16249 */   MCD_OPC_CheckPredicate, 69, 76, 3, 0, // Skip to: 17098
/* 16254 */   MCD_OPC_CheckField, 13, 3, 0, 69, 3, 0, // Skip to: 17098
/* 16261 */   MCD_OPC_Decode, 142, 12, 243, 1, // Opcode: DPAQX_SA_W_PH
/* 16266 */   MCD_OPC_FilterValue, 27, 59, 3, 0, // Skip to: 17098
/* 16271 */   MCD_OPC_CheckPredicate, 69, 54, 3, 0, // Skip to: 17098
/* 16276 */   MCD_OPC_CheckField, 13, 3, 0, 47, 3, 0, // Skip to: 17098
/* 16283 */   MCD_OPC_Decode, 159, 12, 243, 1, // Opcode: DPSQX_SA_W_PH
/* 16288 */   MCD_OPC_FilterValue, 49, 48, 0, 0, // Skip to: 16341
/* 16293 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 16296 */   MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 16311
/* 16301 */   MCD_OPC_CheckPredicate, 69, 24, 3, 0, // Skip to: 17098
/* 16306 */   MCD_OPC_Decode, 234, 6, 210, 2, // Opcode: APPEND
/* 16311 */   MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 16326
/* 16316 */   MCD_OPC_CheckPredicate, 69, 9, 3, 0, // Skip to: 17098
/* 16321 */   MCD_OPC_Decode, 247, 19, 210, 2, // Opcode: PREPEND
/* 16326 */   MCD_OPC_FilterValue, 16, 255, 2, 0, // Skip to: 17098
/* 16331 */   MCD_OPC_CheckPredicate, 69, 250, 2, 0, // Skip to: 17098
/* 16336 */   MCD_OPC_Decode, 152, 7, 210, 2, // Opcode: BALIGN
/* 16341 */   MCD_OPC_FilterValue, 56, 107, 1, 0, // Skip to: 16709
/* 16346 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 16349 */   MCD_OPC_FilterValue, 0, 17, 0, 0, // Skip to: 16371
/* 16354 */   MCD_OPC_CheckPredicate, 37, 227, 2, 0, // Skip to: 17098
/* 16359 */   MCD_OPC_CheckField, 13, 3, 0, 220, 2, 0, // Skip to: 17098
/* 16366 */   MCD_OPC_Decode, 250, 12, 211, 2, // Opcode: EXTR_W
/* 16371 */   MCD_OPC_FilterValue, 1, 17, 0, 0, // Skip to: 16393
/* 16376 */   MCD_OPC_CheckPredicate, 37, 205, 2, 0, // Skip to: 17098
/* 16381 */   MCD_OPC_CheckField, 13, 3, 0, 198, 2, 0, // Skip to: 17098
/* 16388 */   MCD_OPC_Decode, 242, 12, 212, 2, // Opcode: EXTRV_W
/* 16393 */   MCD_OPC_FilterValue, 2, 17, 0, 0, // Skip to: 16415
/* 16398 */   MCD_OPC_CheckPredicate, 37, 183, 2, 0, // Skip to: 17098
/* 16403 */   MCD_OPC_CheckField, 13, 3, 0, 176, 2, 0, // Skip to: 17098
/* 16410 */   MCD_OPC_Decode, 228, 12, 211, 2, // Opcode: EXTP
/* 16415 */   MCD_OPC_FilterValue, 3, 17, 0, 0, // Skip to: 16437
/* 16420 */   MCD_OPC_CheckPredicate, 37, 161, 2, 0, // Skip to: 17098
/* 16425 */   MCD_OPC_CheckField, 13, 3, 0, 154, 2, 0, // Skip to: 17098
/* 16432 */   MCD_OPC_Decode, 233, 12, 212, 2, // Opcode: EXTPV
/* 16437 */   MCD_OPC_FilterValue, 4, 17, 0, 0, // Skip to: 16459
/* 16442 */   MCD_OPC_CheckPredicate, 37, 139, 2, 0, // Skip to: 17098
/* 16447 */   MCD_OPC_CheckField, 13, 3, 0, 132, 2, 0, // Skip to: 17098
/* 16454 */   MCD_OPC_Decode, 246, 12, 211, 2, // Opcode: EXTR_R_W
/* 16459 */   MCD_OPC_FilterValue, 5, 17, 0, 0, // Skip to: 16481
/* 16464 */   MCD_OPC_CheckPredicate, 37, 117, 2, 0, // Skip to: 17098
/* 16469 */   MCD_OPC_CheckField, 13, 3, 0, 110, 2, 0, // Skip to: 17098
/* 16476 */   MCD_OPC_Decode, 238, 12, 212, 2, // Opcode: EXTRV_R_W
/* 16481 */   MCD_OPC_FilterValue, 6, 17, 0, 0, // Skip to: 16503
/* 16486 */   MCD_OPC_CheckPredicate, 37, 95, 2, 0, // Skip to: 17098
/* 16491 */   MCD_OPC_CheckField, 13, 3, 0, 88, 2, 0, // Skip to: 17098
/* 16498 */   MCD_OPC_Decode, 244, 12, 211, 2, // Opcode: EXTR_RS_W
/* 16503 */   MCD_OPC_FilterValue, 7, 17, 0, 0, // Skip to: 16525
/* 16508 */   MCD_OPC_CheckPredicate, 37, 73, 2, 0, // Skip to: 17098
/* 16513 */   MCD_OPC_CheckField, 13, 3, 0, 66, 2, 0, // Skip to: 17098
/* 16520 */   MCD_OPC_Decode, 236, 12, 212, 2, // Opcode: EXTRV_RS_W
/* 16525 */   MCD_OPC_FilterValue, 10, 17, 0, 0, // Skip to: 16547
/* 16530 */   MCD_OPC_CheckPredicate, 37, 51, 2, 0, // Skip to: 17098
/* 16535 */   MCD_OPC_CheckField, 13, 3, 0, 44, 2, 0, // Skip to: 17098
/* 16542 */   MCD_OPC_Decode, 229, 12, 211, 2, // Opcode: EXTPDP
/* 16547 */   MCD_OPC_FilterValue, 11, 17, 0, 0, // Skip to: 16569
/* 16552 */   MCD_OPC_CheckPredicate, 37, 29, 2, 0, // Skip to: 17098
/* 16557 */   MCD_OPC_CheckField, 13, 3, 0, 22, 2, 0, // Skip to: 17098
/* 16564 */   MCD_OPC_Decode, 230, 12, 212, 2, // Opcode: EXTPDPV
/* 16569 */   MCD_OPC_FilterValue, 14, 17, 0, 0, // Skip to: 16591
/* 16574 */   MCD_OPC_CheckPredicate, 37, 7, 2, 0, // Skip to: 17098
/* 16579 */   MCD_OPC_CheckField, 13, 3, 0, 0, 2, 0, // Skip to: 17098
/* 16586 */   MCD_OPC_Decode, 248, 12, 211, 2, // Opcode: EXTR_S_H
/* 16591 */   MCD_OPC_FilterValue, 15, 17, 0, 0, // Skip to: 16613
/* 16596 */   MCD_OPC_CheckPredicate, 37, 241, 1, 0, // Skip to: 17098
/* 16601 */   MCD_OPC_CheckField, 13, 3, 0, 234, 1, 0, // Skip to: 17098
/* 16608 */   MCD_OPC_Decode, 240, 12, 212, 2, // Opcode: EXTRV_S_H
/* 16613 */   MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 16628
/* 16618 */   MCD_OPC_CheckPredicate, 37, 219, 1, 0, // Skip to: 17098
/* 16623 */   MCD_OPC_Decode, 253, 19, 213, 2, // Opcode: RDDSP
/* 16628 */   MCD_OPC_FilterValue, 19, 10, 0, 0, // Skip to: 16643
/* 16633 */   MCD_OPC_CheckPredicate, 40, 204, 1, 0, // Skip to: 17098
/* 16638 */   MCD_OPC_Decode, 165, 24, 214, 2, // Opcode: WRDSP
/* 16643 */   MCD_OPC_FilterValue, 26, 17, 0, 0, // Skip to: 16665
/* 16648 */   MCD_OPC_CheckPredicate, 37, 189, 1, 0, // Skip to: 17098
/* 16653 */   MCD_OPC_CheckField, 13, 7, 0, 182, 1, 0, // Skip to: 17098
/* 16660 */   MCD_OPC_Decode, 154, 21, 215, 2, // Opcode: SHILO
/* 16665 */   MCD_OPC_FilterValue, 27, 17, 0, 0, // Skip to: 16687
/* 16670 */   MCD_OPC_CheckPredicate, 37, 167, 1, 0, // Skip to: 17098
/* 16675 */   MCD_OPC_CheckField, 13, 8, 0, 160, 1, 0, // Skip to: 17098
/* 16682 */   MCD_OPC_Decode, 155, 21, 216, 2, // Opcode: SHILOV
/* 16687 */   MCD_OPC_FilterValue, 31, 150, 1, 0, // Skip to: 17098
/* 16692 */   MCD_OPC_CheckPredicate, 37, 145, 1, 0, // Skip to: 17098
/* 16697 */   MCD_OPC_CheckField, 13, 8, 0, 138, 1, 0, // Skip to: 17098
/* 16704 */   MCD_OPC_Decode, 184, 18, 216, 2, // Opcode: MTHLIP
/* 16709 */   MCD_OPC_FilterValue, 59, 128, 1, 0, // Skip to: 17098
/* 16714 */   MCD_OPC_CheckPredicate, 27, 123, 1, 0, // Skip to: 17098
/* 16719 */   MCD_OPC_CheckField, 21, 5, 0, 116, 1, 0, // Skip to: 17098
/* 16726 */   MCD_OPC_CheckField, 9, 2, 0, 109, 1, 0, // Skip to: 17098
/* 16733 */   MCD_OPC_Decode, 255, 19, 217, 2, // Opcode: RDHWR
/* 16738 */   MCD_OPC_FilterValue, 32, 10, 0, 0, // Skip to: 16753
/* 16743 */   MCD_OPC_CheckPredicate, 27, 94, 1, 0, // Skip to: 17098
/* 16748 */   MCD_OPC_Decode, 154, 15, 141, 1, // Opcode: LB
/* 16753 */   MCD_OPC_FilterValue, 33, 10, 0, 0, // Skip to: 16768
/* 16758 */   MCD_OPC_CheckPredicate, 27, 79, 1, 0, // Skip to: 17098
/* 16763 */   MCD_OPC_Decode, 206, 15, 141, 1, // Opcode: LH
/* 16768 */   MCD_OPC_FilterValue, 34, 10, 0, 0, // Skip to: 16783
/* 16773 */   MCD_OPC_CheckPredicate, 31, 64, 1, 0, // Skip to: 17098
/* 16778 */   MCD_OPC_Decode, 149, 16, 141, 1, // Opcode: LWL
/* 16783 */   MCD_OPC_FilterValue, 35, 10, 0, 0, // Skip to: 16798
/* 16788 */   MCD_OPC_CheckPredicate, 27, 49, 1, 0, // Skip to: 17098
/* 16793 */   MCD_OPC_Decode, 131, 16, 141, 1, // Opcode: LW
/* 16798 */   MCD_OPC_FilterValue, 36, 10, 0, 0, // Skip to: 16813
/* 16803 */   MCD_OPC_CheckPredicate, 27, 34, 1, 0, // Skip to: 17098
/* 16808 */   MCD_OPC_Decode, 174, 15, 141, 1, // Opcode: LBu
/* 16813 */   MCD_OPC_FilterValue, 37, 10, 0, 0, // Skip to: 16828
/* 16818 */   MCD_OPC_CheckPredicate, 27, 19, 1, 0, // Skip to: 17098
/* 16823 */   MCD_OPC_Decode, 226, 15, 141, 1, // Opcode: LHu
/* 16828 */   MCD_OPC_FilterValue, 38, 10, 0, 0, // Skip to: 16843
/* 16833 */   MCD_OPC_CheckPredicate, 31, 4, 1, 0, // Skip to: 17098
/* 16838 */   MCD_OPC_Decode, 162, 16, 141, 1, // Opcode: LWR
/* 16843 */   MCD_OPC_FilterValue, 40, 10, 0, 0, // Skip to: 16858
/* 16848 */   MCD_OPC_CheckPredicate, 27, 245, 0, 0, // Skip to: 17098
/* 16853 */   MCD_OPC_Decode, 193, 20, 141, 1, // Opcode: SB
/* 16858 */   MCD_OPC_FilterValue, 41, 10, 0, 0, // Skip to: 16873
/* 16863 */   MCD_OPC_CheckPredicate, 27, 230, 0, 0, // Skip to: 17098
/* 16868 */   MCD_OPC_Decode, 143, 21, 141, 1, // Opcode: SH
/* 16873 */   MCD_OPC_FilterValue, 42, 10, 0, 0, // Skip to: 16888
/* 16878 */   MCD_OPC_CheckPredicate, 31, 215, 0, 0, // Skip to: 17098
/* 16883 */   MCD_OPC_Decode, 146, 23, 141, 1, // Opcode: SWL
/* 16888 */   MCD_OPC_FilterValue, 43, 10, 0, 0, // Skip to: 16903
/* 16893 */   MCD_OPC_CheckPredicate, 27, 200, 0, 0, // Skip to: 17098
/* 16898 */   MCD_OPC_Decode, 128, 23, 141, 1, // Opcode: SW
/* 16903 */   MCD_OPC_FilterValue, 46, 10, 0, 0, // Skip to: 16918
/* 16908 */   MCD_OPC_CheckPredicate, 31, 185, 0, 0, // Skip to: 17098
/* 16913 */   MCD_OPC_Decode, 157, 23, 141, 1, // Opcode: SWR
/* 16918 */   MCD_OPC_FilterValue, 47, 10, 0, 0, // Skip to: 16933
/* 16923 */   MCD_OPC_CheckPredicate, 71, 170, 0, 0, // Skip to: 17098
/* 16928 */   MCD_OPC_Decode, 246, 8, 218, 2, // Opcode: CACHE
/* 16933 */   MCD_OPC_FilterValue, 48, 10, 0, 0, // Skip to: 16948
/* 16938 */   MCD_OPC_CheckPredicate, 72, 155, 0, 0, // Skip to: 17098
/* 16943 */   MCD_OPC_Decode, 235, 15, 141, 1, // Opcode: LL
/* 16948 */   MCD_OPC_FilterValue, 49, 10, 0, 0, // Skip to: 16963
/* 16953 */   MCD_OPC_CheckPredicate, 47, 140, 0, 0, // Skip to: 17098
/* 16958 */   MCD_OPC_Decode, 136, 16, 219, 2, // Opcode: LWC1
/* 16963 */   MCD_OPC_FilterValue, 50, 10, 0, 0, // Skip to: 16978
/* 16968 */   MCD_OPC_CheckPredicate, 31, 125, 0, 0, // Skip to: 17098
/* 16973 */   MCD_OPC_Decode, 138, 16, 220, 2, // Opcode: LWC2
/* 16978 */   MCD_OPC_FilterValue, 51, 10, 0, 0, // Skip to: 16993
/* 16983 */   MCD_OPC_CheckPredicate, 71, 110, 0, 0, // Skip to: 17098
/* 16988 */   MCD_OPC_Decode, 238, 19, 218, 2, // Opcode: PREF
/* 16993 */   MCD_OPC_FilterValue, 53, 10, 0, 0, // Skip to: 17008
/* 16998 */   MCD_OPC_CheckPredicate, 57, 95, 0, 0, // Skip to: 17098
/* 17003 */   MCD_OPC_Decode, 180, 15, 219, 2, // Opcode: LDC1
/* 17008 */   MCD_OPC_FilterValue, 54, 10, 0, 0, // Skip to: 17023
/* 17013 */   MCD_OPC_CheckPredicate, 39, 80, 0, 0, // Skip to: 17098
/* 17018 */   MCD_OPC_Decode, 185, 15, 220, 2, // Opcode: LDC2
/* 17023 */   MCD_OPC_FilterValue, 56, 10, 0, 0, // Skip to: 17038
/* 17028 */   MCD_OPC_CheckPredicate, 72, 65, 0, 0, // Skip to: 17098
/* 17033 */   MCD_OPC_Decode, 206, 20, 141, 1, // Opcode: SC
/* 17038 */   MCD_OPC_FilterValue, 57, 10, 0, 0, // Skip to: 17053
/* 17043 */   MCD_OPC_CheckPredicate, 47, 50, 0, 0, // Skip to: 17098
/* 17048 */   MCD_OPC_Decode, 134, 23, 219, 2, // Opcode: SWC1
/* 17053 */   MCD_OPC_FilterValue, 58, 10, 0, 0, // Skip to: 17068
/* 17058 */   MCD_OPC_CheckPredicate, 31, 35, 0, 0, // Skip to: 17098
/* 17063 */   MCD_OPC_Decode, 136, 23, 220, 2, // Opcode: SWC2
/* 17068 */   MCD_OPC_FilterValue, 61, 10, 0, 0, // Skip to: 17083
/* 17073 */   MCD_OPC_CheckPredicate, 57, 20, 0, 0, // Skip to: 17098
/* 17078 */   MCD_OPC_Decode, 227, 20, 219, 2, // Opcode: SDC1
/* 17083 */   MCD_OPC_FilterValue, 62, 10, 0, 0, // Skip to: 17098
/* 17088 */   MCD_OPC_CheckPredicate, 39, 5, 0, 0, // Skip to: 17098
/* 17093 */   MCD_OPC_Decode, 232, 20, 220, 2, // Opcode: SDC2
/* 17098 */   MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMips32_64_PTR6432[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 24
/* 8 */       MCD_OPC_CheckPredicate, 73, 41, 0, 0, // Skip to: 54
/* 13 */      MCD_OPC_CheckField, 0, 21, 8, 34, 0, 0, // Skip to: 54
/* 20 */      MCD_OPC_Decode, 134, 15, 24, // Opcode: JR64
/* 24 */      MCD_OPC_FilterValue, 48, 10, 0, 0, // Skip to: 39
/* 29 */      MCD_OPC_CheckPredicate, 74, 20, 0, 0, // Skip to: 54
/* 34 */      MCD_OPC_Decode, 236, 15, 141, 1, // Opcode: LL64
/* 39 */      MCD_OPC_FilterValue, 56, 10, 0, 0, // Skip to: 54
/* 44 */      MCD_OPC_CheckPredicate, 74, 5, 0, 0, // Skip to: 54
/* 49 */      MCD_OPC_Decode, 207, 20, 141, 1, // Opcode: SC64
/* 54 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMips32r6_64r632[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 14, 2, 0, // Skip to: 534
/* 8 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 11 */      MCD_OPC_FilterValue, 5, 17, 0, 0, // Skip to: 33
/* 16 */      MCD_OPC_CheckPredicate, 75, 133, 9, 0, // Skip to: 2458
/* 21 */      MCD_OPC_CheckField, 8, 3, 0, 126, 9, 0, // Skip to: 2458
/* 28 */      MCD_OPC_Decode, 250, 15, 185, 1, // Opcode: LSA_R6
/* 33 */      MCD_OPC_FilterValue, 9, 17, 0, 0, // Skip to: 55
/* 38 */      MCD_OPC_CheckPredicate, 75, 111, 9, 0, // Skip to: 2458
/* 43 */      MCD_OPC_CheckField, 6, 15, 16, 104, 9, 0, // Skip to: 2458
/* 50 */      MCD_OPC_Decode, 143, 15, 186, 1, // Opcode: JR_HB_R6
/* 55 */      MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 70
/* 60 */      MCD_OPC_CheckPredicate, 76, 89, 9, 0, // Skip to: 2458
/* 65 */      MCD_OPC_Decode, 226, 20, 188, 1, // Opcode: SDBBP_R6
/* 70 */      MCD_OPC_FilterValue, 16, 23, 0, 0, // Skip to: 98
/* 75 */      MCD_OPC_CheckPredicate, 75, 74, 9, 0, // Skip to: 2458
/* 80 */      MCD_OPC_CheckField, 16, 5, 0, 67, 9, 0, // Skip to: 2458
/* 87 */      MCD_OPC_CheckField, 6, 5, 1, 60, 9, 0, // Skip to: 2458
/* 94 */      MCD_OPC_Decode, 197, 9, 25, // Opcode: CLZ_R6
/* 98 */      MCD_OPC_FilterValue, 17, 23, 0, 0, // Skip to: 126
/* 103 */     MCD_OPC_CheckPredicate, 75, 46, 9, 0, // Skip to: 2458
/* 108 */     MCD_OPC_CheckField, 16, 5, 0, 39, 9, 0, // Skip to: 2458
/* 115 */     MCD_OPC_CheckField, 6, 5, 1, 32, 9, 0, // Skip to: 2458
/* 122 */     MCD_OPC_Decode, 176, 9, 25, // Opcode: CLO_R6
/* 126 */     MCD_OPC_FilterValue, 18, 23, 0, 0, // Skip to: 154
/* 131 */     MCD_OPC_CheckPredicate, 77, 18, 9, 0, // Skip to: 2458
/* 136 */     MCD_OPC_CheckField, 16, 5, 0, 11, 9, 0, // Skip to: 2458
/* 143 */     MCD_OPC_CheckField, 6, 5, 1, 4, 9, 0, // Skip to: 2458
/* 150 */     MCD_OPC_Decode, 203, 11, 26, // Opcode: DCLZ_R6
/* 154 */     MCD_OPC_FilterValue, 19, 23, 0, 0, // Skip to: 182
/* 159 */     MCD_OPC_CheckPredicate, 77, 246, 8, 0, // Skip to: 2458
/* 164 */     MCD_OPC_CheckField, 16, 5, 0, 239, 8, 0, // Skip to: 2458
/* 171 */     MCD_OPC_CheckField, 6, 5, 1, 232, 8, 0, // Skip to: 2458
/* 178 */     MCD_OPC_Decode, 201, 11, 26, // Opcode: DCLO_R6
/* 182 */     MCD_OPC_FilterValue, 21, 17, 0, 0, // Skip to: 204
/* 187 */     MCD_OPC_CheckPredicate, 77, 218, 8, 0, // Skip to: 2458
/* 192 */     MCD_OPC_CheckField, 8, 3, 0, 211, 8, 0, // Skip to: 2458
/* 199 */     MCD_OPC_Decode, 236, 11, 194, 1, // Opcode: DLSA_R6
/* 204 */     MCD_OPC_FilterValue, 24, 31, 0, 0, // Skip to: 240
/* 209 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 212 */     MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 226
/* 217 */     MCD_OPC_CheckPredicate, 76, 188, 8, 0, // Skip to: 2458
/* 222 */     MCD_OPC_Decode, 252, 18, 61, // Opcode: MUL_R6
/* 226 */     MCD_OPC_FilterValue, 3, 179, 8, 0, // Skip to: 2458
/* 231 */     MCD_OPC_CheckPredicate, 76, 174, 8, 0, // Skip to: 2458
/* 236 */     MCD_OPC_Decode, 199, 18, 61, // Opcode: MUH
/* 240 */     MCD_OPC_FilterValue, 25, 31, 0, 0, // Skip to: 276
/* 245 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 248 */     MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 262
/* 253 */     MCD_OPC_CheckPredicate, 76, 152, 8, 0, // Skip to: 2458
/* 258 */     MCD_OPC_Decode, 238, 18, 61, // Opcode: MULU
/* 262 */     MCD_OPC_FilterValue, 3, 143, 8, 0, // Skip to: 2458
/* 267 */     MCD_OPC_CheckPredicate, 76, 138, 8, 0, // Skip to: 2458
/* 272 */     MCD_OPC_Decode, 200, 18, 61, // Opcode: MUHU
/* 276 */     MCD_OPC_FilterValue, 26, 31, 0, 0, // Skip to: 312
/* 281 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 284 */     MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 298
/* 289 */     MCD_OPC_CheckPredicate, 76, 116, 8, 0, // Skip to: 2458
/* 294 */     MCD_OPC_Decode, 218, 11, 61, // Opcode: DIV
/* 298 */     MCD_OPC_FilterValue, 3, 107, 8, 0, // Skip to: 2458
/* 303 */     MCD_OPC_CheckPredicate, 76, 102, 8, 0, // Skip to: 2458
/* 308 */     MCD_OPC_Decode, 192, 17, 61, // Opcode: MOD
/* 312 */     MCD_OPC_FilterValue, 27, 31, 0, 0, // Skip to: 348
/* 317 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 320 */     MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 334
/* 325 */     MCD_OPC_CheckPredicate, 76, 80, 8, 0, // Skip to: 2458
/* 330 */     MCD_OPC_Decode, 219, 11, 61, // Opcode: DIVU
/* 334 */     MCD_OPC_FilterValue, 3, 71, 8, 0, // Skip to: 2458
/* 339 */     MCD_OPC_CheckPredicate, 76, 66, 8, 0, // Skip to: 2458
/* 344 */     MCD_OPC_Decode, 195, 17, 61, // Opcode: MODU
/* 348 */     MCD_OPC_FilterValue, 28, 31, 0, 0, // Skip to: 384
/* 353 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 356 */     MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 370
/* 361 */     MCD_OPC_CheckPredicate, 77, 44, 8, 0, // Skip to: 2458
/* 366 */     MCD_OPC_Decode, 129, 12, 23, // Opcode: DMUL_R6
/* 370 */     MCD_OPC_FilterValue, 3, 35, 8, 0, // Skip to: 2458
/* 375 */     MCD_OPC_CheckPredicate, 77, 30, 8, 0, // Skip to: 2458
/* 380 */     MCD_OPC_Decode, 251, 11, 23, // Opcode: DMUH
/* 384 */     MCD_OPC_FilterValue, 29, 31, 0, 0, // Skip to: 420
/* 389 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 392 */     MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 406
/* 397 */     MCD_OPC_CheckPredicate, 77, 8, 8, 0, // Skip to: 2458
/* 402 */     MCD_OPC_Decode, 128, 12, 23, // Opcode: DMULU
/* 406 */     MCD_OPC_FilterValue, 3, 255, 7, 0, // Skip to: 2458
/* 411 */     MCD_OPC_CheckPredicate, 77, 250, 7, 0, // Skip to: 2458
/* 416 */     MCD_OPC_Decode, 252, 11, 23, // Opcode: DMUHU
/* 420 */     MCD_OPC_FilterValue, 30, 31, 0, 0, // Skip to: 456
/* 425 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 428 */     MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 442
/* 433 */     MCD_OPC_CheckPredicate, 77, 228, 7, 0, // Skip to: 2458
/* 438 */     MCD_OPC_Decode, 204, 11, 23, // Opcode: DDIV
/* 442 */     MCD_OPC_FilterValue, 3, 219, 7, 0, // Skip to: 2458
/* 447 */     MCD_OPC_CheckPredicate, 77, 214, 7, 0, // Skip to: 2458
/* 452 */     MCD_OPC_Decode, 242, 11, 23, // Opcode: DMOD
/* 456 */     MCD_OPC_FilterValue, 31, 31, 0, 0, // Skip to: 492
/* 461 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 464 */     MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 478
/* 469 */     MCD_OPC_CheckPredicate, 77, 192, 7, 0, // Skip to: 2458
/* 474 */     MCD_OPC_Decode, 205, 11, 23, // Opcode: DDIVU
/* 478 */     MCD_OPC_FilterValue, 3, 183, 7, 0, // Skip to: 2458
/* 483 */     MCD_OPC_CheckPredicate, 77, 178, 7, 0, // Skip to: 2458
/* 488 */     MCD_OPC_Decode, 243, 11, 23, // Opcode: DMODU
/* 492 */     MCD_OPC_FilterValue, 53, 16, 0, 0, // Skip to: 513
/* 497 */     MCD_OPC_CheckPredicate, 78, 164, 7, 0, // Skip to: 2458
/* 502 */     MCD_OPC_CheckField, 6, 5, 0, 157, 7, 0, // Skip to: 2458
/* 509 */     MCD_OPC_Decode, 250, 20, 61, // Opcode: SELEQZ
/* 513 */     MCD_OPC_FilterValue, 55, 148, 7, 0, // Skip to: 2458
/* 518 */     MCD_OPC_CheckPredicate, 78, 143, 7, 0, // Skip to: 2458
/* 523 */     MCD_OPC_CheckField, 6, 5, 0, 136, 7, 0, // Skip to: 2458
/* 530 */     MCD_OPC_Decode, 129, 21, 61, // Opcode: SELNEZ
/* 534 */     MCD_OPC_FilterValue, 1, 77, 0, 0, // Skip to: 616
/* 539 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 542 */     MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 557
/* 547 */     MCD_OPC_CheckPredicate, 77, 114, 7, 0, // Skip to: 2458
/* 552 */     MCD_OPC_Decode, 195, 11, 221, 2, // Opcode: DAHI
/* 557 */     MCD_OPC_FilterValue, 17, 17, 0, 0, // Skip to: 579
/* 562 */     MCD_OPC_CheckPredicate, 75, 99, 7, 0, // Skip to: 2458
/* 567 */     MCD_OPC_CheckField, 21, 5, 0, 92, 7, 0, // Skip to: 2458
/* 574 */     MCD_OPC_Decode, 147, 7, 198, 1, // Opcode: BAL
/* 579 */     MCD_OPC_FilterValue, 23, 17, 0, 0, // Skip to: 601
/* 584 */     MCD_OPC_CheckPredicate, 76, 77, 7, 0, // Skip to: 2458
/* 589 */     MCD_OPC_CheckField, 21, 5, 0, 70, 7, 0, // Skip to: 2458
/* 596 */     MCD_OPC_Decode, 208, 21, 222, 2, // Opcode: SIGRIE
/* 601 */     MCD_OPC_FilterValue, 30, 60, 7, 0, // Skip to: 2458
/* 606 */     MCD_OPC_CheckPredicate, 77, 55, 7, 0, // Skip to: 2458
/* 611 */     MCD_OPC_Decode, 197, 11, 221, 2, // Opcode: DATI
/* 616 */     MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 631
/* 621 */     MCD_OPC_CheckPredicate, 76, 40, 7, 0, // Skip to: 2458
/* 626 */     MCD_OPC_Decode, 222, 7, 223, 2, // Opcode: BGEZALC
/* 631 */     MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 646
/* 636 */     MCD_OPC_CheckPredicate, 76, 25, 7, 0, // Skip to: 2458
/* 641 */     MCD_OPC_Decode, 156, 8, 224, 2, // Opcode: BLTZALC
/* 646 */     MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 661
/* 651 */     MCD_OPC_CheckPredicate, 76, 10, 7, 0, // Skip to: 2458
/* 656 */     MCD_OPC_Decode, 190, 7, 225, 2, // Opcode: BEQC
/* 661 */     MCD_OPC_FilterValue, 15, 10, 0, 0, // Skip to: 676
/* 666 */     MCD_OPC_CheckPredicate, 75, 251, 6, 0, // Skip to: 2458
/* 671 */     MCD_OPC_Decode, 244, 6, 203, 1, // Opcode: AUI
/* 676 */     MCD_OPC_FilterValue, 16, 45, 0, 0, // Skip to: 726
/* 681 */     MCD_OPC_ExtractField, 0, 16,  // Inst{15-0} ...
/* 684 */     MCD_OPC_FilterValue, 4, 16, 0, 0, // Skip to: 705
/* 689 */     MCD_OPC_CheckPredicate, 75, 228, 6, 0, // Skip to: 2458
/* 694 */     MCD_OPC_CheckField, 21, 5, 11, 221, 6, 0, // Skip to: 2458
/* 701 */     MCD_OPC_Decode, 223, 12, 92, // Opcode: EVP
/* 705 */     MCD_OPC_FilterValue, 36, 212, 6, 0, // Skip to: 2458
/* 710 */     MCD_OPC_CheckPredicate, 75, 207, 6, 0, // Skip to: 2458
/* 715 */     MCD_OPC_CheckField, 21, 5, 11, 200, 6, 0, // Skip to: 2458
/* 722 */     MCD_OPC_Decode, 200, 12, 92, // Opcode: DVP
/* 726 */     MCD_OPC_FilterValue, 17, 135, 3, 0, // Skip to: 1634
/* 731 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 734 */     MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 749
/* 739 */     MCD_OPC_CheckPredicate, 79, 178, 6, 0, // Skip to: 2458
/* 744 */     MCD_OPC_Decode, 164, 7, 226, 2, // Opcode: BC1EQZ
/* 749 */     MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 764
/* 754 */     MCD_OPC_CheckPredicate, 79, 163, 6, 0, // Skip to: 2458
/* 759 */     MCD_OPC_Decode, 169, 7, 226, 2, // Opcode: BC1NEZ
/* 764 */     MCD_OPC_FilterValue, 16, 182, 0, 0, // Skip to: 951
/* 769 */     MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 772 */     MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 787
/* 777 */     MCD_OPC_CheckPredicate, 79, 140, 6, 0, // Skip to: 2458
/* 782 */     MCD_OPC_Decode, 138, 21, 227, 2, // Opcode: SEL_S
/* 787 */     MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 802
/* 792 */     MCD_OPC_CheckPredicate, 79, 125, 6, 0, // Skip to: 2458
/* 797 */     MCD_OPC_Decode, 255, 20, 218, 1, // Opcode: SELEQZ_S
/* 802 */     MCD_OPC_FilterValue, 23, 10, 0, 0, // Skip to: 817
/* 807 */     MCD_OPC_CheckPredicate, 79, 110, 6, 0, // Skip to: 2458
/* 812 */     MCD_OPC_Decode, 134, 21, 218, 1, // Opcode: SELNEZ_S
/* 817 */     MCD_OPC_FilterValue, 24, 10, 0, 0, // Skip to: 832
/* 822 */     MCD_OPC_CheckPredicate, 79, 95, 6, 0, // Skip to: 2458
/* 827 */     MCD_OPC_Decode, 198, 16, 228, 2, // Opcode: MADDF_S
/* 832 */     MCD_OPC_FilterValue, 25, 10, 0, 0, // Skip to: 847
/* 837 */     MCD_OPC_CheckPredicate, 79, 80, 6, 0, // Skip to: 2458
/* 842 */     MCD_OPC_Decode, 134, 18, 228, 2, // Opcode: MSUBF_S
/* 847 */     MCD_OPC_FilterValue, 26, 17, 0, 0, // Skip to: 869
/* 852 */     MCD_OPC_CheckPredicate, 79, 65, 6, 0, // Skip to: 2458
/* 857 */     MCD_OPC_CheckField, 16, 5, 0, 58, 6, 0, // Skip to: 2458
/* 864 */     MCD_OPC_Decode, 153, 20, 219, 1, // Opcode: RINT_S
/* 869 */     MCD_OPC_FilterValue, 27, 17, 0, 0, // Skip to: 891
/* 874 */     MCD_OPC_CheckPredicate, 79, 43, 6, 0, // Skip to: 2458
/* 879 */     MCD_OPC_CheckField, 16, 5, 0, 36, 6, 0, // Skip to: 2458
/* 886 */     MCD_OPC_Decode, 154, 9, 219, 1, // Opcode: CLASS_S
/* 891 */     MCD_OPC_FilterValue, 28, 10, 0, 0, // Skip to: 906
/* 896 */     MCD_OPC_CheckPredicate, 79, 21, 6, 0, // Skip to: 2458
/* 901 */     MCD_OPC_Decode, 182, 17, 218, 1, // Opcode: MIN_S
/* 906 */     MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 921
/* 911 */     MCD_OPC_CheckPredicate, 79, 6, 6, 0, // Skip to: 2458
/* 916 */     MCD_OPC_Decode, 246, 16, 218, 1, // Opcode: MAX_S
/* 921 */     MCD_OPC_FilterValue, 30, 10, 0, 0, // Skip to: 936
/* 926 */     MCD_OPC_CheckPredicate, 79, 247, 5, 0, // Skip to: 2458
/* 931 */     MCD_OPC_Decode, 166, 17, 218, 1, // Opcode: MINA_S
/* 936 */     MCD_OPC_FilterValue, 31, 237, 5, 0, // Skip to: 2458
/* 941 */     MCD_OPC_CheckPredicate, 79, 232, 5, 0, // Skip to: 2458
/* 946 */     MCD_OPC_Decode, 230, 16, 218, 1, // Opcode: MAXA_S
/* 951 */     MCD_OPC_FilterValue, 17, 182, 0, 0, // Skip to: 1138
/* 956 */     MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 959 */     MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 974
/* 964 */     MCD_OPC_CheckPredicate, 79, 209, 5, 0, // Skip to: 2458
/* 969 */     MCD_OPC_Decode, 136, 21, 229, 2, // Opcode: SEL_D
/* 974 */     MCD_OPC_FilterValue, 20, 10, 0, 0, // Skip to: 989
/* 979 */     MCD_OPC_CheckPredicate, 79, 194, 5, 0, // Skip to: 2458
/* 984 */     MCD_OPC_Decode, 252, 20, 230, 2, // Opcode: SELEQZ_D
/* 989 */     MCD_OPC_FilterValue, 23, 10, 0, 0, // Skip to: 1004
/* 994 */     MCD_OPC_CheckPredicate, 79, 179, 5, 0, // Skip to: 2458
/* 999 */     MCD_OPC_Decode, 131, 21, 230, 2, // Opcode: SELNEZ_D
/* 1004 */    MCD_OPC_FilterValue, 24, 10, 0, 0, // Skip to: 1019
/* 1009 */    MCD_OPC_CheckPredicate, 79, 164, 5, 0, // Skip to: 2458
/* 1014 */    MCD_OPC_Decode, 196, 16, 229, 2, // Opcode: MADDF_D
/* 1019 */    MCD_OPC_FilterValue, 25, 10, 0, 0, // Skip to: 1034
/* 1024 */    MCD_OPC_CheckPredicate, 79, 149, 5, 0, // Skip to: 2458
/* 1029 */    MCD_OPC_Decode, 132, 18, 229, 2, // Opcode: MSUBF_D
/* 1034 */    MCD_OPC_FilterValue, 26, 17, 0, 0, // Skip to: 1056
/* 1039 */    MCD_OPC_CheckPredicate, 79, 134, 5, 0, // Skip to: 2458
/* 1044 */    MCD_OPC_CheckField, 16, 5, 0, 127, 5, 0, // Skip to: 2458
/* 1051 */    MCD_OPC_Decode, 151, 20, 230, 1, // Opcode: RINT_D
/* 1056 */    MCD_OPC_FilterValue, 27, 17, 0, 0, // Skip to: 1078
/* 1061 */    MCD_OPC_CheckPredicate, 79, 112, 5, 0, // Skip to: 2458
/* 1066 */    MCD_OPC_CheckField, 16, 5, 0, 105, 5, 0, // Skip to: 2458
/* 1073 */    MCD_OPC_Decode, 152, 9, 230, 1, // Opcode: CLASS_D
/* 1078 */    MCD_OPC_FilterValue, 28, 10, 0, 0, // Skip to: 1093
/* 1083 */    MCD_OPC_CheckPredicate, 79, 90, 5, 0, // Skip to: 2458
/* 1088 */    MCD_OPC_Decode, 180, 17, 230, 2, // Opcode: MIN_D
/* 1093 */    MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 1108
/* 1098 */    MCD_OPC_CheckPredicate, 79, 75, 5, 0, // Skip to: 2458
/* 1103 */    MCD_OPC_Decode, 244, 16, 230, 2, // Opcode: MAX_D
/* 1108 */    MCD_OPC_FilterValue, 30, 10, 0, 0, // Skip to: 1123
/* 1113 */    MCD_OPC_CheckPredicate, 79, 60, 5, 0, // Skip to: 2458
/* 1118 */    MCD_OPC_Decode, 164, 17, 230, 2, // Opcode: MINA_D
/* 1123 */    MCD_OPC_FilterValue, 31, 50, 5, 0, // Skip to: 2458
/* 1128 */    MCD_OPC_CheckPredicate, 79, 45, 5, 0, // Skip to: 2458
/* 1133 */    MCD_OPC_Decode, 228, 16, 230, 2, // Opcode: MAXA_D
/* 1138 */    MCD_OPC_FilterValue, 20, 243, 0, 0, // Skip to: 1386
/* 1143 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1146 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 1161
/* 1151 */    MCD_OPC_CheckPredicate, 79, 22, 5, 0, // Skip to: 2458
/* 1156 */    MCD_OPC_Decode, 225, 9, 231, 2, // Opcode: CMP_F_S
/* 1161 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 1176
/* 1166 */    MCD_OPC_CheckPredicate, 79, 7, 5, 0, // Skip to: 2458
/* 1171 */    MCD_OPC_Decode, 156, 10, 231, 2, // Opcode: CMP_UN_S
/* 1176 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 1191
/* 1181 */    MCD_OPC_CheckPredicate, 79, 248, 4, 0, // Skip to: 2458
/* 1186 */    MCD_OPC_Decode, 222, 9, 231, 2, // Opcode: CMP_EQ_S
/* 1191 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 1206
/* 1196 */    MCD_OPC_CheckPredicate, 79, 233, 4, 0, // Skip to: 2458
/* 1201 */    MCD_OPC_Decode, 144, 10, 231, 2, // Opcode: CMP_UEQ_S
/* 1206 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 1221
/* 1211 */    MCD_OPC_CheckPredicate, 79, 218, 4, 0, // Skip to: 2458
/* 1216 */    MCD_OPC_Decode, 236, 9, 231, 2, // Opcode: CMP_LT_S
/* 1221 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 1236
/* 1226 */    MCD_OPC_CheckPredicate, 79, 203, 4, 0, // Skip to: 2458
/* 1231 */    MCD_OPC_Decode, 152, 10, 231, 2, // Opcode: CMP_ULT_S
/* 1236 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 1251
/* 1241 */    MCD_OPC_CheckPredicate, 79, 188, 4, 0, // Skip to: 2458
/* 1246 */    MCD_OPC_Decode, 230, 9, 231, 2, // Opcode: CMP_LE_S
/* 1251 */    MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 1266
/* 1256 */    MCD_OPC_CheckPredicate, 79, 173, 4, 0, // Skip to: 2458
/* 1261 */    MCD_OPC_Decode, 148, 10, 231, 2, // Opcode: CMP_ULE_S
/* 1266 */    MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 1281
/* 1271 */    MCD_OPC_CheckPredicate, 79, 158, 4, 0, // Skip to: 2458
/* 1276 */    MCD_OPC_Decode, 240, 9, 231, 2, // Opcode: CMP_SAF_S
/* 1281 */    MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 1296
/* 1286 */    MCD_OPC_CheckPredicate, 79, 143, 4, 0, // Skip to: 2458
/* 1291 */    MCD_OPC_Decode, 140, 10, 231, 2, // Opcode: CMP_SUN_S
/* 1296 */    MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 1311
/* 1301 */    MCD_OPC_CheckPredicate, 79, 128, 4, 0, // Skip to: 2458
/* 1306 */    MCD_OPC_Decode, 244, 9, 231, 2, // Opcode: CMP_SEQ_S
/* 1311 */    MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 1326
/* 1316 */    MCD_OPC_CheckPredicate, 79, 113, 4, 0, // Skip to: 2458
/* 1321 */    MCD_OPC_Decode, 128, 10, 231, 2, // Opcode: CMP_SUEQ_S
/* 1326 */    MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 1341
/* 1331 */    MCD_OPC_CheckPredicate, 79, 98, 4, 0, // Skip to: 2458
/* 1336 */    MCD_OPC_Decode, 252, 9, 231, 2, // Opcode: CMP_SLT_S
/* 1341 */    MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 1356
/* 1346 */    MCD_OPC_CheckPredicate, 79, 83, 4, 0, // Skip to: 2458
/* 1351 */    MCD_OPC_Decode, 136, 10, 231, 2, // Opcode: CMP_SULT_S
/* 1356 */    MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 1371
/* 1361 */    MCD_OPC_CheckPredicate, 79, 68, 4, 0, // Skip to: 2458
/* 1366 */    MCD_OPC_Decode, 248, 9, 231, 2, // Opcode: CMP_SLE_S
/* 1371 */    MCD_OPC_FilterValue, 15, 58, 4, 0, // Skip to: 2458
/* 1376 */    MCD_OPC_CheckPredicate, 79, 53, 4, 0, // Skip to: 2458
/* 1381 */    MCD_OPC_Decode, 132, 10, 231, 2, // Opcode: CMP_SULE_S
/* 1386 */    MCD_OPC_FilterValue, 21, 43, 4, 0, // Skip to: 2458
/* 1391 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1394 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 1409
/* 1399 */    MCD_OPC_CheckPredicate, 79, 30, 4, 0, // Skip to: 2458
/* 1404 */    MCD_OPC_Decode, 224, 9, 232, 2, // Opcode: CMP_F_D
/* 1409 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 1424
/* 1414 */    MCD_OPC_CheckPredicate, 79, 15, 4, 0, // Skip to: 2458
/* 1419 */    MCD_OPC_Decode, 154, 10, 232, 2, // Opcode: CMP_UN_D
/* 1424 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 1439
/* 1429 */    MCD_OPC_CheckPredicate, 79, 0, 4, 0, // Skip to: 2458
/* 1434 */    MCD_OPC_Decode, 218, 9, 232, 2, // Opcode: CMP_EQ_D
/* 1439 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 1454
/* 1444 */    MCD_OPC_CheckPredicate, 79, 241, 3, 0, // Skip to: 2458
/* 1449 */    MCD_OPC_Decode, 142, 10, 232, 2, // Opcode: CMP_UEQ_D
/* 1454 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 1469
/* 1459 */    MCD_OPC_CheckPredicate, 79, 226, 3, 0, // Skip to: 2458
/* 1464 */    MCD_OPC_Decode, 232, 9, 232, 2, // Opcode: CMP_LT_D
/* 1469 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 1484
/* 1474 */    MCD_OPC_CheckPredicate, 79, 211, 3, 0, // Skip to: 2458
/* 1479 */    MCD_OPC_Decode, 150, 10, 232, 2, // Opcode: CMP_ULT_D
/* 1484 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 1499
/* 1489 */    MCD_OPC_CheckPredicate, 79, 196, 3, 0, // Skip to: 2458
/* 1494 */    MCD_OPC_Decode, 226, 9, 232, 2, // Opcode: CMP_LE_D
/* 1499 */    MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 1514
/* 1504 */    MCD_OPC_CheckPredicate, 79, 181, 3, 0, // Skip to: 2458
/* 1509 */    MCD_OPC_Decode, 146, 10, 232, 2, // Opcode: CMP_ULE_D
/* 1514 */    MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 1529
/* 1519 */    MCD_OPC_CheckPredicate, 79, 166, 3, 0, // Skip to: 2458
/* 1524 */    MCD_OPC_Decode, 238, 9, 232, 2, // Opcode: CMP_SAF_D
/* 1529 */    MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 1544
/* 1534 */    MCD_OPC_CheckPredicate, 79, 151, 3, 0, // Skip to: 2458
/* 1539 */    MCD_OPC_Decode, 138, 10, 232, 2, // Opcode: CMP_SUN_D
/* 1544 */    MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 1559
/* 1549 */    MCD_OPC_CheckPredicate, 79, 136, 3, 0, // Skip to: 2458
/* 1554 */    MCD_OPC_Decode, 242, 9, 232, 2, // Opcode: CMP_SEQ_D
/* 1559 */    MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 1574
/* 1564 */    MCD_OPC_CheckPredicate, 79, 121, 3, 0, // Skip to: 2458
/* 1569 */    MCD_OPC_Decode, 254, 9, 232, 2, // Opcode: CMP_SUEQ_D
/* 1574 */    MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 1589
/* 1579 */    MCD_OPC_CheckPredicate, 79, 106, 3, 0, // Skip to: 2458
/* 1584 */    MCD_OPC_Decode, 250, 9, 232, 2, // Opcode: CMP_SLT_D
/* 1589 */    MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 1604
/* 1594 */    MCD_OPC_CheckPredicate, 79, 91, 3, 0, // Skip to: 2458
/* 1599 */    MCD_OPC_Decode, 134, 10, 232, 2, // Opcode: CMP_SULT_D
/* 1604 */    MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 1619
/* 1609 */    MCD_OPC_CheckPredicate, 79, 76, 3, 0, // Skip to: 2458
/* 1614 */    MCD_OPC_Decode, 246, 9, 232, 2, // Opcode: CMP_SLE_D
/* 1619 */    MCD_OPC_FilterValue, 15, 66, 3, 0, // Skip to: 2458
/* 1624 */    MCD_OPC_CheckPredicate, 79, 61, 3, 0, // Skip to: 2458
/* 1629 */    MCD_OPC_Decode, 130, 10, 232, 2, // Opcode: CMP_SULE_D
/* 1634 */    MCD_OPC_FilterValue, 18, 93, 0, 0, // Skip to: 1732
/* 1639 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1642 */    MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 1657
/* 1647 */    MCD_OPC_CheckPredicate, 76, 38, 3, 0, // Skip to: 2458
/* 1652 */    MCD_OPC_Decode, 174, 7, 233, 2, // Opcode: BC2EQZ
/* 1657 */    MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 1672
/* 1662 */    MCD_OPC_CheckPredicate, 76, 23, 3, 0, // Skip to: 2458
/* 1667 */    MCD_OPC_Decode, 140, 16, 234, 2, // Opcode: LWC2_R6
/* 1672 */    MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 1687
/* 1677 */    MCD_OPC_CheckPredicate, 76, 8, 3, 0, // Skip to: 2458
/* 1682 */    MCD_OPC_Decode, 138, 23, 234, 2, // Opcode: SWC2_R6
/* 1687 */    MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 1702
/* 1692 */    MCD_OPC_CheckPredicate, 76, 249, 2, 0, // Skip to: 2458
/* 1697 */    MCD_OPC_Decode, 176, 7, 233, 2, // Opcode: BC2NEZ
/* 1702 */    MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 1717
/* 1707 */    MCD_OPC_CheckPredicate, 76, 234, 2, 0, // Skip to: 2458
/* 1712 */    MCD_OPC_Decode, 187, 15, 234, 2, // Opcode: LDC2_R6
/* 1717 */    MCD_OPC_FilterValue, 15, 224, 2, 0, // Skip to: 2458
/* 1722 */    MCD_OPC_CheckPredicate, 76, 219, 2, 0, // Skip to: 2458
/* 1727 */    MCD_OPC_Decode, 234, 20, 234, 2, // Opcode: SDC2_R6
/* 1732 */    MCD_OPC_FilterValue, 22, 10, 0, 0, // Skip to: 1747
/* 1737 */    MCD_OPC_CheckPredicate, 76, 204, 2, 0, // Skip to: 2458
/* 1742 */    MCD_OPC_Decode, 227, 7, 235, 2, // Opcode: BGEZC
/* 1747 */    MCD_OPC_FilterValue, 23, 10, 0, 0, // Skip to: 1762
/* 1752 */    MCD_OPC_CheckPredicate, 76, 189, 2, 0, // Skip to: 2458
/* 1757 */    MCD_OPC_Decode, 161, 8, 236, 2, // Opcode: BLTZC
/* 1762 */    MCD_OPC_FilterValue, 24, 10, 0, 0, // Skip to: 1777
/* 1767 */    MCD_OPC_CheckPredicate, 76, 174, 2, 0, // Skip to: 2458
/* 1772 */    MCD_OPC_Decode, 172, 8, 237, 2, // Opcode: BNEC
/* 1777 */    MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 1792
/* 1782 */    MCD_OPC_CheckPredicate, 77, 159, 2, 0, // Skip to: 2458
/* 1787 */    MCD_OPC_Decode, 198, 11, 238, 2, // Opcode: DAUI
/* 1792 */    MCD_OPC_FilterValue, 31, 135, 1, 0, // Skip to: 2188
/* 1797 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1800 */    MCD_OPC_FilterValue, 15, 123, 0, 0, // Skip to: 1928
/* 1805 */    MCD_OPC_ExtractField, 6, 10,  // Inst{15-6} ...
/* 1808 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 1823
/* 1813 */    MCD_OPC_CheckPredicate, 80, 128, 2, 0, // Skip to: 2458
/* 1818 */    MCD_OPC_Decode, 165, 10, 239, 2, // Opcode: CRC32B
/* 1823 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 1838
/* 1828 */    MCD_OPC_CheckPredicate, 80, 113, 2, 0, // Skip to: 2458
/* 1833 */    MCD_OPC_Decode, 175, 10, 239, 2, // Opcode: CRC32H
/* 1838 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 1853
/* 1843 */    MCD_OPC_CheckPredicate, 80, 98, 2, 0, // Skip to: 2458
/* 1848 */    MCD_OPC_Decode, 177, 10, 239, 2, // Opcode: CRC32W
/* 1853 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 1868
/* 1858 */    MCD_OPC_CheckPredicate, 81, 83, 2, 0, // Skip to: 2458
/* 1863 */    MCD_OPC_Decode, 174, 10, 239, 2, // Opcode: CRC32D
/* 1868 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 1883
/* 1873 */    MCD_OPC_CheckPredicate, 80, 68, 2, 0, // Skip to: 2458
/* 1878 */    MCD_OPC_Decode, 167, 10, 239, 2, // Opcode: CRC32CB
/* 1883 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 1898
/* 1888 */    MCD_OPC_CheckPredicate, 80, 53, 2, 0, // Skip to: 2458
/* 1893 */    MCD_OPC_Decode, 170, 10, 239, 2, // Opcode: CRC32CH
/* 1898 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 1913
/* 1903 */    MCD_OPC_CheckPredicate, 80, 38, 2, 0, // Skip to: 2458
/* 1908 */    MCD_OPC_Decode, 172, 10, 239, 2, // Opcode: CRC32CW
/* 1913 */    MCD_OPC_FilterValue, 7, 28, 2, 0, // Skip to: 2458
/* 1918 */    MCD_OPC_CheckPredicate, 81, 23, 2, 0, // Skip to: 2458
/* 1923 */    MCD_OPC_Decode, 169, 10, 239, 2, // Opcode: CRC32CD
/* 1928 */    MCD_OPC_FilterValue, 32, 47, 0, 0, // Skip to: 1980
/* 1933 */    MCD_OPC_ExtractField, 8, 3,  // Inst{10-8} ...
/* 1936 */    MCD_OPC_FilterValue, 0, 24, 0, 0, // Skip to: 1965
/* 1941 */    MCD_OPC_CheckPredicate, 75, 0, 2, 0, // Skip to: 2458
/* 1946 */    MCD_OPC_CheckField, 21, 5, 0, 249, 1, 0, // Skip to: 2458
/* 1953 */    MCD_OPC_CheckField, 6, 2, 0, 242, 1, 0, // Skip to: 2458
/* 1960 */    MCD_OPC_Decode, 132, 8, 204, 2, // Opcode: BITSWAP
/* 1965 */    MCD_OPC_FilterValue, 2, 232, 1, 0, // Skip to: 2458
/* 1970 */    MCD_OPC_CheckPredicate, 75, 227, 1, 0, // Skip to: 2458
/* 1975 */    MCD_OPC_Decode, 211, 6, 240, 2, // Opcode: ALIGN
/* 1980 */    MCD_OPC_FilterValue, 36, 47, 0, 0, // Skip to: 2032
/* 1985 */    MCD_OPC_ExtractField, 9, 2,  // Inst{10-9} ...
/* 1988 */    MCD_OPC_FilterValue, 0, 24, 0, 0, // Skip to: 2017
/* 1993 */    MCD_OPC_CheckPredicate, 77, 204, 1, 0, // Skip to: 2458
/* 1998 */    MCD_OPC_CheckField, 21, 5, 0, 197, 1, 0, // Skip to: 2458
/* 2005 */    MCD_OPC_CheckField, 6, 3, 0, 190, 1, 0, // Skip to: 2458
/* 2012 */    MCD_OPC_Decode, 199, 11, 241, 2, // Opcode: DBITSWAP
/* 2017 */    MCD_OPC_FilterValue, 1, 180, 1, 0, // Skip to: 2458
/* 2022 */    MCD_OPC_CheckPredicate, 77, 175, 1, 0, // Skip to: 2458
/* 2027 */    MCD_OPC_Decode, 196, 11, 242, 2, // Opcode: DALIGN
/* 2032 */    MCD_OPC_FilterValue, 37, 17, 0, 0, // Skip to: 2054
/* 2037 */    MCD_OPC_CheckPredicate, 76, 160, 1, 0, // Skip to: 2458
/* 2042 */    MCD_OPC_CheckField, 6, 1, 0, 153, 1, 0, // Skip to: 2458
/* 2049 */    MCD_OPC_Decode, 252, 8, 209, 2, // Opcode: CACHE_R6
/* 2054 */    MCD_OPC_FilterValue, 38, 10, 0, 0, // Skip to: 2069
/* 2059 */    MCD_OPC_CheckPredicate, 82, 138, 1, 0, // Skip to: 2458
/* 2064 */    MCD_OPC_Decode, 217, 20, 243, 2, // Opcode: SC_R6
/* 2069 */    MCD_OPC_FilterValue, 39, 10, 0, 0, // Skip to: 2084
/* 2074 */    MCD_OPC_CheckPredicate, 75, 123, 1, 0, // Skip to: 2458
/* 2079 */    MCD_OPC_Decode, 210, 20, 243, 2, // Opcode: SCD_R6
/* 2084 */    MCD_OPC_FilterValue, 53, 17, 0, 0, // Skip to: 2106
/* 2089 */    MCD_OPC_CheckPredicate, 76, 108, 1, 0, // Skip to: 2458
/* 2094 */    MCD_OPC_CheckField, 6, 1, 0, 101, 1, 0, // Skip to: 2458
/* 2101 */    MCD_OPC_Decode, 245, 19, 209, 2, // Opcode: PREF_R6
/* 2106 */    MCD_OPC_FilterValue, 54, 10, 0, 0, // Skip to: 2121
/* 2111 */    MCD_OPC_CheckPredicate, 82, 86, 1, 0, // Skip to: 2458
/* 2116 */    MCD_OPC_Decode, 246, 15, 243, 2, // Opcode: LL_R6
/* 2121 */    MCD_OPC_FilterValue, 55, 10, 0, 0, // Skip to: 2136
/* 2126 */    MCD_OPC_CheckPredicate, 77, 71, 1, 0, // Skip to: 2458
/* 2131 */    MCD_OPC_Decode, 239, 15, 243, 2, // Opcode: LLD_R6
/* 2136 */    MCD_OPC_FilterValue, 61, 61, 1, 0, // Skip to: 2458
/* 2141 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 2144 */    MCD_OPC_FilterValue, 0, 17, 0, 0, // Skip to: 2166
/* 2149 */    MCD_OPC_CheckPredicate, 83, 48, 1, 0, // Skip to: 2458
/* 2154 */    MCD_OPC_CheckField, 8, 13, 0, 41, 1, 0, // Skip to: 2458
/* 2161 */    MCD_OPC_Decode, 184, 14, 186, 1, // Opcode: GINVI
/* 2166 */    MCD_OPC_FilterValue, 2, 31, 1, 0, // Skip to: 2458
/* 2171 */    MCD_OPC_CheckPredicate, 83, 26, 1, 0, // Skip to: 2458
/* 2176 */    MCD_OPC_CheckField, 10, 11, 0, 19, 1, 0, // Skip to: 2458
/* 2183 */    MCD_OPC_Decode, 187, 14, 244, 2, // Opcode: GINVT
/* 2188 */    MCD_OPC_FilterValue, 50, 10, 0, 0, // Skip to: 2203
/* 2193 */    MCD_OPC_CheckPredicate, 76, 4, 1, 0, // Skip to: 2458
/* 2198 */    MCD_OPC_Decode, 161, 7, 245, 2, // Opcode: BC
/* 2203 */    MCD_OPC_FilterValue, 53, 27, 0, 0, // Skip to: 2235
/* 2208 */    MCD_OPC_CheckPredicate, 24, 12, 0, 0, // Skip to: 2225
/* 2213 */    MCD_OPC_CheckField, 16, 5, 0, 5, 0, 0, // Skip to: 2225
/* 2220 */    MCD_OPC_Decode, 238, 7, 180, 1, // Opcode: BGTZC_MMR6
/* 2225 */    MCD_OPC_CheckPredicate, 24, 228, 0, 0, // Skip to: 2458
/* 2230 */    MCD_OPC_Decode, 163, 8, 180, 1, // Opcode: BLTZC_MMR6
/* 2235 */    MCD_OPC_FilterValue, 54, 26, 0, 0, // Skip to: 2266
/* 2240 */    MCD_OPC_CheckPredicate, 75, 11, 0, 0, // Skip to: 2256
/* 2245 */    MCD_OPC_CheckField, 21, 5, 0, 4, 0, 0, // Skip to: 2256
/* 2252 */    MCD_OPC_Decode, 129, 15, 103, // Opcode: JIC
/* 2256 */    MCD_OPC_CheckPredicate, 76, 197, 0, 0, // Skip to: 2458
/* 2261 */    MCD_OPC_Decode, 201, 7, 246, 2, // Opcode: BEQZC
/* 2266 */    MCD_OPC_FilterValue, 58, 10, 0, 0, // Skip to: 2281
/* 2271 */    MCD_OPC_CheckPredicate, 75, 182, 0, 0, // Skip to: 2458
/* 2276 */    MCD_OPC_Decode, 148, 7, 245, 2, // Opcode: BALC
/* 2281 */    MCD_OPC_FilterValue, 59, 109, 0, 0, // Skip to: 2395
/* 2286 */    MCD_OPC_ExtractField, 19, 2,  // Inst{20-19} ...
/* 2289 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 2304
/* 2294 */    MCD_OPC_CheckPredicate, 75, 159, 0, 0, // Skip to: 2458
/* 2299 */    MCD_OPC_Decode, 129, 6, 174, 1, // Opcode: ADDIUPC
/* 2304 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 2319
/* 2309 */    MCD_OPC_CheckPredicate, 75, 144, 0, 0, // Skip to: 2458
/* 2314 */    MCD_OPC_Decode, 158, 16, 174, 1, // Opcode: LWPC
/* 2319 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 2334
/* 2324 */    MCD_OPC_CheckPredicate, 84, 129, 0, 0, // Skip to: 2458
/* 2329 */    MCD_OPC_Decode, 169, 16, 174, 1, // Opcode: LWUPC
/* 2334 */    MCD_OPC_FilterValue, 3, 119, 0, 0, // Skip to: 2458
/* 2339 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 2342 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 2357
/* 2347 */    MCD_OPC_CheckPredicate, 84, 106, 0, 0, // Skip to: 2458
/* 2352 */    MCD_OPC_Decode, 194, 15, 247, 2, // Opcode: LDPC
/* 2357 */    MCD_OPC_FilterValue, 1, 96, 0, 0, // Skip to: 2458
/* 2362 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 2365 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 2380
/* 2370 */    MCD_OPC_CheckPredicate, 75, 83, 0, 0, // Skip to: 2458
/* 2375 */    MCD_OPC_Decode, 245, 6, 175, 1, // Opcode: AUIPC
/* 2380 */    MCD_OPC_FilterValue, 3, 73, 0, 0, // Skip to: 2458
/* 2385 */    MCD_OPC_CheckPredicate, 75, 68, 0, 0, // Skip to: 2458
/* 2390 */    MCD_OPC_Decode, 213, 6, 175, 1, // Opcode: ALUIPC
/* 2395 */    MCD_OPC_FilterValue, 61, 27, 0, 0, // Skip to: 2427
/* 2400 */    MCD_OPC_CheckPredicate, 24, 12, 0, 0, // Skip to: 2417
/* 2405 */    MCD_OPC_CheckField, 16, 5, 0, 5, 0, 0, // Skip to: 2417
/* 2412 */    MCD_OPC_Decode, 140, 8, 182, 1, // Opcode: BLEZC_MMR6
/* 2417 */    MCD_OPC_CheckPredicate, 24, 36, 0, 0, // Skip to: 2458
/* 2422 */    MCD_OPC_Decode, 229, 7, 182, 1, // Opcode: BGEZC_MMR6
/* 2427 */    MCD_OPC_FilterValue, 62, 26, 0, 0, // Skip to: 2458
/* 2432 */    MCD_OPC_CheckPredicate, 75, 11, 0, 0, // Skip to: 2448
/* 2437 */    MCD_OPC_CheckField, 21, 5, 0, 4, 0, 0, // Skip to: 2448
/* 2444 */    MCD_OPC_Decode, 254, 14, 103, // Opcode: JIALC
/* 2448 */    MCD_OPC_CheckPredicate, 76, 5, 0, 0, // Skip to: 2458
/* 2453 */    MCD_OPC_Decode, 191, 8, 246, 2, // Opcode: BNEZC
/* 2458 */    MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMips32r6_64r6_Ambiguous32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 6, 27, 0, 0, // Skip to: 35
/* 8 */       MCD_OPC_CheckPredicate, 76, 12, 0, 0, // Skip to: 25
/* 13 */      MCD_OPC_CheckField, 21, 5, 0, 5, 0, 0, // Skip to: 25
/* 20 */      MCD_OPC_Decode, 136, 8, 223, 2, // Opcode: BLEZALC
/* 25 */      MCD_OPC_CheckPredicate, 76, 165, 0, 0, // Skip to: 195
/* 30 */      MCD_OPC_Decode, 215, 7, 223, 2, // Opcode: BGEUC
/* 35 */      MCD_OPC_FilterValue, 7, 27, 0, 0, // Skip to: 67
/* 40 */      MCD_OPC_CheckPredicate, 76, 12, 0, 0, // Skip to: 57
/* 45 */      MCD_OPC_CheckField, 21, 5, 0, 5, 0, 0, // Skip to: 57
/* 52 */      MCD_OPC_Decode, 234, 7, 224, 2, // Opcode: BGTZALC
/* 57 */      MCD_OPC_CheckPredicate, 76, 133, 0, 0, // Skip to: 195
/* 62 */      MCD_OPC_Decode, 149, 8, 224, 2, // Opcode: BLTUC
/* 67 */      MCD_OPC_FilterValue, 8, 27, 0, 0, // Skip to: 99
/* 72 */      MCD_OPC_CheckPredicate, 76, 12, 0, 0, // Skip to: 89
/* 77 */      MCD_OPC_CheckField, 21, 5, 0, 5, 0, 0, // Skip to: 89
/* 84 */      MCD_OPC_Decode, 199, 7, 237, 2, // Opcode: BEQZALC
/* 89 */      MCD_OPC_CheckPredicate, 76, 101, 0, 0, // Skip to: 195
/* 94 */      MCD_OPC_Decode, 206, 8, 225, 2, // Opcode: BOVC
/* 99 */      MCD_OPC_FilterValue, 22, 27, 0, 0, // Skip to: 131
/* 104 */     MCD_OPC_CheckPredicate, 76, 12, 0, 0, // Skip to: 121
/* 109 */     MCD_OPC_CheckField, 21, 5, 0, 5, 0, 0, // Skip to: 121
/* 116 */     MCD_OPC_Decode, 138, 8, 235, 2, // Opcode: BLEZC
/* 121 */     MCD_OPC_CheckPredicate, 76, 69, 0, 0, // Skip to: 195
/* 126 */     MCD_OPC_Decode, 209, 7, 235, 2, // Opcode: BGEC
/* 131 */     MCD_OPC_FilterValue, 23, 27, 0, 0, // Skip to: 163
/* 136 */     MCD_OPC_CheckPredicate, 76, 12, 0, 0, // Skip to: 153
/* 141 */     MCD_OPC_CheckField, 21, 5, 0, 5, 0, 0, // Skip to: 153
/* 148 */     MCD_OPC_Decode, 236, 7, 236, 2, // Opcode: BGTZC
/* 153 */     MCD_OPC_CheckPredicate, 76, 37, 0, 0, // Skip to: 195
/* 158 */     MCD_OPC_Decode, 143, 8, 236, 2, // Opcode: BLTC
/* 163 */     MCD_OPC_FilterValue, 24, 27, 0, 0, // Skip to: 195
/* 168 */     MCD_OPC_CheckPredicate, 76, 12, 0, 0, // Skip to: 185
/* 173 */     MCD_OPC_CheckField, 21, 5, 0, 5, 0, 0, // Skip to: 185
/* 180 */     MCD_OPC_Decode, 189, 8, 237, 2, // Opcode: BNEZALC
/* 185 */     MCD_OPC_CheckPredicate, 76, 5, 0, 0, // Skip to: 195
/* 190 */     MCD_OPC_Decode, 199, 8, 237, 2, // Opcode: BNVC
/* 195 */     MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMips32r6_64r6_BranchZero32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 22, 10, 0, 0, // Skip to: 18
/* 8 */       MCD_OPC_CheckPredicate, 85, 20, 0, 0, // Skip to: 33
/* 13 */      MCD_OPC_Decode, 228, 7, 235, 2, // Opcode: BGEZC64
/* 18 */      MCD_OPC_FilterValue, 23, 10, 0, 0, // Skip to: 33
/* 23 */      MCD_OPC_CheckPredicate, 85, 5, 0, 0, // Skip to: 33
/* 28 */      MCD_OPC_Decode, 162, 8, 236, 2, // Opcode: BLTZC64
/* 33 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMips32r6_64r6_GP6432[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 53, 0, 0, // Skip to: 61
/* 8 */       MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 11 */      MCD_OPC_FilterValue, 53, 9, 0, 0, // Skip to: 25
/* 16 */      MCD_OPC_CheckPredicate, 86, 226, 0, 0, // Skip to: 247
/* 21 */      MCD_OPC_Decode, 251, 20, 23, // Opcode: SELEQZ64
/* 25 */      MCD_OPC_FilterValue, 55, 9, 0, 0, // Skip to: 39
/* 30 */      MCD_OPC_CheckPredicate, 86, 212, 0, 0, // Skip to: 247
/* 35 */      MCD_OPC_Decode, 130, 21, 23, // Opcode: SELNEZ64
/* 39 */      MCD_OPC_FilterValue, 137, 8, 202, 0, 0, // Skip to: 247
/* 45 */      MCD_OPC_CheckPredicate, 75, 197, 0, 0, // Skip to: 247
/* 50 */      MCD_OPC_CheckField, 11, 10, 0, 190, 0, 0, // Skip to: 247
/* 57 */      MCD_OPC_Decode, 142, 15, 24, // Opcode: JR_HB64_R6
/* 61 */      MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 76
/* 66 */      MCD_OPC_CheckPredicate, 85, 176, 0, 0, // Skip to: 247
/* 71 */      MCD_OPC_Decode, 216, 7, 223, 2, // Opcode: BGEUC64
/* 76 */      MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 91
/* 81 */      MCD_OPC_CheckPredicate, 85, 161, 0, 0, // Skip to: 247
/* 86 */      MCD_OPC_Decode, 150, 8, 224, 2, // Opcode: BLTUC64
/* 91 */      MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 106
/* 96 */      MCD_OPC_CheckPredicate, 85, 146, 0, 0, // Skip to: 247
/* 101 */     MCD_OPC_Decode, 192, 7, 225, 2, // Opcode: BEQC64
/* 106 */     MCD_OPC_FilterValue, 22, 27, 0, 0, // Skip to: 138
/* 111 */     MCD_OPC_CheckPredicate, 85, 12, 0, 0, // Skip to: 128
/* 116 */     MCD_OPC_CheckField, 21, 5, 0, 5, 0, 0, // Skip to: 128
/* 123 */     MCD_OPC_Decode, 139, 8, 235, 2, // Opcode: BLEZC64
/* 128 */     MCD_OPC_CheckPredicate, 85, 114, 0, 0, // Skip to: 247
/* 133 */     MCD_OPC_Decode, 210, 7, 235, 2, // Opcode: BGEC64
/* 138 */     MCD_OPC_FilterValue, 23, 27, 0, 0, // Skip to: 170
/* 143 */     MCD_OPC_CheckPredicate, 85, 12, 0, 0, // Skip to: 160
/* 148 */     MCD_OPC_CheckField, 21, 5, 0, 5, 0, 0, // Skip to: 160
/* 155 */     MCD_OPC_Decode, 237, 7, 236, 2, // Opcode: BGTZC64
/* 160 */     MCD_OPC_CheckPredicate, 85, 82, 0, 0, // Skip to: 247
/* 165 */     MCD_OPC_Decode, 144, 8, 236, 2, // Opcode: BLTC64
/* 170 */     MCD_OPC_FilterValue, 24, 10, 0, 0, // Skip to: 185
/* 175 */     MCD_OPC_CheckPredicate, 85, 67, 0, 0, // Skip to: 247
/* 180 */     MCD_OPC_Decode, 174, 8, 237, 2, // Opcode: BNEC64
/* 185 */     MCD_OPC_FilterValue, 54, 26, 0, 0, // Skip to: 216
/* 190 */     MCD_OPC_CheckPredicate, 85, 11, 0, 0, // Skip to: 206
/* 195 */     MCD_OPC_CheckField, 21, 5, 0, 4, 0, 0, // Skip to: 206
/* 202 */     MCD_OPC_Decode, 130, 15, 22, // Opcode: JIC64
/* 206 */     MCD_OPC_CheckPredicate, 85, 36, 0, 0, // Skip to: 247
/* 211 */     MCD_OPC_Decode, 204, 7, 248, 2, // Opcode: BEQZC64
/* 216 */     MCD_OPC_FilterValue, 62, 26, 0, 0, // Skip to: 247
/* 221 */     MCD_OPC_CheckPredicate, 85, 11, 0, 0, // Skip to: 237
/* 226 */     MCD_OPC_CheckField, 21, 5, 0, 4, 0, 0, // Skip to: 237
/* 233 */     MCD_OPC_Decode, 255, 14, 22, // Opcode: JIALC64
/* 237 */     MCD_OPC_CheckPredicate, 85, 5, 0, 0, // Skip to: 247
/* 242 */     MCD_OPC_Decode, 194, 8, 248, 2, // Opcode: BNEZC64
/* 247 */     MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMips32r6_64r6_PTR6432[] = {
/* 0 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 3 */       MCD_OPC_FilterValue, 38, 17, 0, 0, // Skip to: 25
/* 8 */       MCD_OPC_CheckPredicate, 87, 34, 0, 0, // Skip to: 47
/* 13 */      MCD_OPC_CheckField, 26, 6, 31, 27, 0, 0, // Skip to: 47
/* 20 */      MCD_OPC_Decode, 208, 20, 243, 2, // Opcode: SC64_R6
/* 25 */      MCD_OPC_FilterValue, 54, 17, 0, 0, // Skip to: 47
/* 30 */      MCD_OPC_CheckPredicate, 87, 12, 0, 0, // Skip to: 47
/* 35 */      MCD_OPC_CheckField, 26, 6, 31, 5, 0, 0, // Skip to: 47
/* 42 */      MCD_OPC_Decode, 237, 15, 243, 2, // Opcode: LL64_R6
/* 47 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMips6432[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 236, 1, 0, // Skip to: 500
/* 8 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 11 */      MCD_OPC_FilterValue, 8, 16, 0, 0, // Skip to: 32
/* 16 */      MCD_OPC_CheckPredicate, 88, 244, 4, 0, // Skip to: 1289
/* 21 */      MCD_OPC_CheckField, 6, 15, 16, 237, 4, 0, // Skip to: 1289
/* 28 */      MCD_OPC_Decode, 141, 15, 24, // Opcode: JR_HB64
/* 32 */      MCD_OPC_FilterValue, 9, 45, 0, 0, // Skip to: 82
/* 37 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 40 */      MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 61
/* 45 */      MCD_OPC_CheckPredicate, 89, 215, 4, 0, // Skip to: 1289
/* 50 */      MCD_OPC_CheckField, 16, 5, 0, 208, 4, 0, // Skip to: 1289
/* 57 */      MCD_OPC_Decode, 238, 14, 26, // Opcode: JALR64
/* 61 */      MCD_OPC_FilterValue, 16, 199, 4, 0, // Skip to: 1289
/* 66 */      MCD_OPC_CheckPredicate, 90, 194, 4, 0, // Skip to: 1289
/* 71 */      MCD_OPC_CheckField, 16, 5, 0, 187, 4, 0, // Skip to: 1289
/* 78 */      MCD_OPC_Decode, 248, 14, 26, // Opcode: JALR_HB64
/* 82 */      MCD_OPC_FilterValue, 20, 17, 0, 0, // Skip to: 104
/* 87 */      MCD_OPC_CheckPredicate, 91, 173, 4, 0, // Skip to: 1289
/* 92 */      MCD_OPC_CheckField, 6, 5, 0, 166, 4, 0, // Skip to: 1289
/* 99 */      MCD_OPC_Decode, 190, 12, 249, 2, // Opcode: DSLLV
/* 104 */     MCD_OPC_FilterValue, 22, 33, 0, 0, // Skip to: 142
/* 109 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 112 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 127
/* 117 */     MCD_OPC_CheckPredicate, 91, 143, 4, 0, // Skip to: 1289
/* 122 */     MCD_OPC_Decode, 196, 12, 249, 2, // Opcode: DSRLV
/* 127 */     MCD_OPC_FilterValue, 1, 133, 4, 0, // Skip to: 1289
/* 132 */     MCD_OPC_CheckPredicate, 90, 128, 4, 0, // Skip to: 1289
/* 137 */     MCD_OPC_Decode, 183, 12, 249, 2, // Opcode: DROTRV
/* 142 */     MCD_OPC_FilterValue, 23, 17, 0, 0, // Skip to: 164
/* 147 */     MCD_OPC_CheckPredicate, 91, 113, 4, 0, // Skip to: 1289
/* 152 */     MCD_OPC_CheckField, 6, 5, 0, 106, 4, 0, // Skip to: 1289
/* 159 */     MCD_OPC_Decode, 193, 12, 249, 2, // Opcode: DSRAV
/* 164 */     MCD_OPC_FilterValue, 28, 17, 0, 0, // Skip to: 186
/* 169 */     MCD_OPC_CheckPredicate, 92, 91, 4, 0, // Skip to: 1289
/* 174 */     MCD_OPC_CheckField, 6, 10, 0, 84, 4, 0, // Skip to: 1289
/* 181 */     MCD_OPC_Decode, 254, 11, 250, 2, // Opcode: DMULT
/* 186 */     MCD_OPC_FilterValue, 29, 17, 0, 0, // Skip to: 208
/* 191 */     MCD_OPC_CheckPredicate, 92, 69, 4, 0, // Skip to: 1289
/* 196 */     MCD_OPC_CheckField, 6, 10, 0, 62, 4, 0, // Skip to: 1289
/* 203 */     MCD_OPC_Decode, 255, 11, 250, 2, // Opcode: DMULTu
/* 208 */     MCD_OPC_FilterValue, 30, 17, 0, 0, // Skip to: 230
/* 213 */     MCD_OPC_CheckPredicate, 92, 47, 4, 0, // Skip to: 1289
/* 218 */     MCD_OPC_CheckField, 6, 10, 0, 40, 4, 0, // Skip to: 1289
/* 225 */     MCD_OPC_Decode, 185, 12, 250, 2, // Opcode: DSDIV
/* 230 */     MCD_OPC_FilterValue, 31, 17, 0, 0, // Skip to: 252
/* 235 */     MCD_OPC_CheckPredicate, 92, 25, 4, 0, // Skip to: 1289
/* 240 */     MCD_OPC_CheckField, 6, 10, 0, 18, 4, 0, // Skip to: 1289
/* 247 */     MCD_OPC_Decode, 199, 12, 250, 2, // Opcode: DUDIV
/* 252 */     MCD_OPC_FilterValue, 44, 16, 0, 0, // Skip to: 273
/* 257 */     MCD_OPC_CheckPredicate, 91, 3, 4, 0, // Skip to: 1289
/* 262 */     MCD_OPC_CheckField, 6, 5, 0, 252, 3, 0, // Skip to: 1289
/* 269 */     MCD_OPC_Decode, 191, 11, 23, // Opcode: DADD
/* 273 */     MCD_OPC_FilterValue, 45, 16, 0, 0, // Skip to: 294
/* 278 */     MCD_OPC_CheckPredicate, 91, 238, 3, 0, // Skip to: 1289
/* 283 */     MCD_OPC_CheckField, 6, 5, 0, 231, 3, 0, // Skip to: 1289
/* 290 */     MCD_OPC_Decode, 194, 11, 23, // Opcode: DADDu
/* 294 */     MCD_OPC_FilterValue, 46, 16, 0, 0, // Skip to: 315
/* 299 */     MCD_OPC_CheckPredicate, 91, 217, 3, 0, // Skip to: 1289
/* 304 */     MCD_OPC_CheckField, 6, 5, 0, 210, 3, 0, // Skip to: 1289
/* 311 */     MCD_OPC_Decode, 197, 12, 23, // Opcode: DSUB
/* 315 */     MCD_OPC_FilterValue, 47, 16, 0, 0, // Skip to: 336
/* 320 */     MCD_OPC_CheckPredicate, 91, 196, 3, 0, // Skip to: 1289
/* 325 */     MCD_OPC_CheckField, 6, 5, 0, 189, 3, 0, // Skip to: 1289
/* 332 */     MCD_OPC_Decode, 198, 12, 23, // Opcode: DSUBu
/* 336 */     MCD_OPC_FilterValue, 56, 17, 0, 0, // Skip to: 358
/* 341 */     MCD_OPC_CheckPredicate, 91, 175, 3, 0, // Skip to: 1289
/* 346 */     MCD_OPC_CheckField, 21, 5, 0, 168, 3, 0, // Skip to: 1289
/* 353 */     MCD_OPC_Decode, 187, 12, 251, 2, // Opcode: DSLL
/* 358 */     MCD_OPC_FilterValue, 58, 33, 0, 0, // Skip to: 396
/* 363 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 366 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 381
/* 371 */     MCD_OPC_CheckPredicate, 91, 145, 3, 0, // Skip to: 1289
/* 376 */     MCD_OPC_Decode, 194, 12, 251, 2, // Opcode: DSRL
/* 381 */     MCD_OPC_FilterValue, 1, 135, 3, 0, // Skip to: 1289
/* 386 */     MCD_OPC_CheckPredicate, 90, 130, 3, 0, // Skip to: 1289
/* 391 */     MCD_OPC_Decode, 181, 12, 251, 2, // Opcode: DROTR
/* 396 */     MCD_OPC_FilterValue, 59, 17, 0, 0, // Skip to: 418
/* 401 */     MCD_OPC_CheckPredicate, 91, 115, 3, 0, // Skip to: 1289
/* 406 */     MCD_OPC_CheckField, 21, 5, 0, 108, 3, 0, // Skip to: 1289
/* 413 */     MCD_OPC_Decode, 191, 12, 251, 2, // Opcode: DSRA
/* 418 */     MCD_OPC_FilterValue, 60, 17, 0, 0, // Skip to: 440
/* 423 */     MCD_OPC_CheckPredicate, 91, 93, 3, 0, // Skip to: 1289
/* 428 */     MCD_OPC_CheckField, 21, 5, 0, 86, 3, 0, // Skip to: 1289
/* 435 */     MCD_OPC_Decode, 188, 12, 251, 2, // Opcode: DSLL32
/* 440 */     MCD_OPC_FilterValue, 62, 33, 0, 0, // Skip to: 478
/* 445 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 448 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 463
/* 453 */     MCD_OPC_CheckPredicate, 91, 63, 3, 0, // Skip to: 1289
/* 458 */     MCD_OPC_Decode, 195, 12, 251, 2, // Opcode: DSRL32
/* 463 */     MCD_OPC_FilterValue, 1, 53, 3, 0, // Skip to: 1289
/* 468 */     MCD_OPC_CheckPredicate, 90, 48, 3, 0, // Skip to: 1289
/* 473 */     MCD_OPC_Decode, 182, 12, 251, 2, // Opcode: DROTR32
/* 478 */     MCD_OPC_FilterValue, 63, 38, 3, 0, // Skip to: 1289
/* 483 */     MCD_OPC_CheckPredicate, 91, 33, 3, 0, // Skip to: 1289
/* 488 */     MCD_OPC_CheckField, 21, 5, 0, 26, 3, 0, // Skip to: 1289
/* 495 */     MCD_OPC_Decode, 192, 12, 251, 2, // Opcode: DSRA32
/* 500 */     MCD_OPC_FilterValue, 16, 85, 0, 0, // Skip to: 590
/* 505 */     MCD_OPC_ExtractField, 3, 8,  // Inst{10-3} ...
/* 508 */     MCD_OPC_FilterValue, 0, 33, 0, 0, // Skip to: 546
/* 513 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 516 */     MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 531
/* 521 */     MCD_OPC_CheckPredicate, 93, 251, 2, 0, // Skip to: 1289
/* 526 */     MCD_OPC_Decode, 237, 11, 252, 2, // Opcode: DMFC0
/* 531 */     MCD_OPC_FilterValue, 5, 241, 2, 0, // Skip to: 1289
/* 536 */     MCD_OPC_CheckPredicate, 93, 236, 2, 0, // Skip to: 1289
/* 541 */     MCD_OPC_Decode, 245, 11, 253, 2, // Opcode: DMTC0
/* 546 */     MCD_OPC_FilterValue, 32, 17, 0, 0, // Skip to: 568
/* 551 */     MCD_OPC_CheckPredicate, 94, 221, 2, 0, // Skip to: 1289
/* 556 */     MCD_OPC_CheckField, 21, 5, 3, 214, 2, 0, // Skip to: 1289
/* 563 */     MCD_OPC_Decode, 241, 11, 252, 2, // Opcode: DMFGC0
/* 568 */     MCD_OPC_FilterValue, 96, 204, 2, 0, // Skip to: 1289
/* 573 */     MCD_OPC_CheckPredicate, 94, 199, 2, 0, // Skip to: 1289
/* 578 */     MCD_OPC_CheckField, 21, 5, 3, 192, 2, 0, // Skip to: 1289
/* 585 */     MCD_OPC_Decode, 249, 11, 253, 2, // Opcode: DMTGC0
/* 590 */     MCD_OPC_FilterValue, 18, 47, 0, 0, // Skip to: 642
/* 595 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 598 */     MCD_OPC_FilterValue, 1, 17, 0, 0, // Skip to: 620
/* 603 */     MCD_OPC_CheckPredicate, 93, 169, 2, 0, // Skip to: 1289
/* 608 */     MCD_OPC_CheckField, 3, 8, 0, 162, 2, 0, // Skip to: 1289
/* 615 */     MCD_OPC_Decode, 239, 11, 254, 2, // Opcode: DMFC2
/* 620 */     MCD_OPC_FilterValue, 5, 152, 2, 0, // Skip to: 1289
/* 625 */     MCD_OPC_CheckPredicate, 93, 147, 2, 0, // Skip to: 1289
/* 630 */     MCD_OPC_CheckField, 3, 8, 0, 140, 2, 0, // Skip to: 1289
/* 637 */     MCD_OPC_Decode, 247, 11, 255, 2, // Opcode: DMTC2
/* 642 */     MCD_OPC_FilterValue, 21, 3, 1, 0, // Skip to: 906
/* 647 */     MCD_OPC_ExtractField, 0, 13,  // Inst{12-0} ...
/* 650 */     MCD_OPC_FilterValue, 188, 8, 10, 0, 0, // Skip to: 666
/* 656 */     MCD_OPC_CheckPredicate, 15, 116, 2, 0, // Skip to: 1289
/* 661 */     MCD_OPC_Decode, 229, 10, 128, 3, // Opcode: C_F_D64_MM
/* 666 */     MCD_OPC_FilterValue, 252, 8, 10, 0, 0, // Skip to: 682
/* 672 */     MCD_OPC_CheckPredicate, 15, 100, 2, 0, // Skip to: 1289
/* 677 */     MCD_OPC_Decode, 185, 11, 128, 3, // Opcode: C_UN_D64_MM
/* 682 */     MCD_OPC_FilterValue, 188, 9, 10, 0, 0, // Skip to: 698
/* 688 */     MCD_OPC_CheckPredicate, 15, 84, 2, 0, // Skip to: 1289
/* 693 */     MCD_OPC_Decode, 223, 10, 128, 3, // Opcode: C_EQ_D64_MM
/* 698 */     MCD_OPC_FilterValue, 252, 9, 10, 0, 0, // Skip to: 714
/* 704 */     MCD_OPC_CheckPredicate, 15, 68, 2, 0, // Skip to: 1289
/* 709 */     MCD_OPC_Decode, 167, 11, 128, 3, // Opcode: C_UEQ_D64_MM
/* 714 */     MCD_OPC_FilterValue, 188, 10, 10, 0, 0, // Skip to: 730
/* 720 */     MCD_OPC_CheckPredicate, 15, 52, 2, 0, // Skip to: 1289
/* 725 */     MCD_OPC_Decode, 149, 11, 128, 3, // Opcode: C_OLT_D64_MM
/* 730 */     MCD_OPC_FilterValue, 252, 10, 10, 0, 0, // Skip to: 746
/* 736 */     MCD_OPC_CheckPredicate, 15, 36, 2, 0, // Skip to: 1289
/* 741 */     MCD_OPC_Decode, 179, 11, 128, 3, // Opcode: C_ULT_D64_MM
/* 746 */     MCD_OPC_FilterValue, 188, 11, 10, 0, 0, // Skip to: 762
/* 752 */     MCD_OPC_CheckPredicate, 15, 20, 2, 0, // Skip to: 1289
/* 757 */     MCD_OPC_Decode, 143, 11, 128, 3, // Opcode: C_OLE_D64_MM
/* 762 */     MCD_OPC_FilterValue, 252, 11, 10, 0, 0, // Skip to: 778
/* 768 */     MCD_OPC_CheckPredicate, 15, 4, 2, 0, // Skip to: 1289
/* 773 */     MCD_OPC_Decode, 173, 11, 128, 3, // Opcode: C_ULE_D64_MM
/* 778 */     MCD_OPC_FilterValue, 188, 12, 10, 0, 0, // Skip to: 794
/* 784 */     MCD_OPC_CheckPredicate, 15, 244, 1, 0, // Skip to: 1289
/* 789 */     MCD_OPC_Decode, 161, 11, 128, 3, // Opcode: C_SF_D64_MM
/* 794 */     MCD_OPC_FilterValue, 252, 12, 10, 0, 0, // Skip to: 810
/* 800 */     MCD_OPC_CheckPredicate, 15, 228, 1, 0, // Skip to: 1289
/* 805 */     MCD_OPC_Decode, 253, 10, 128, 3, // Opcode: C_NGLE_D64_MM
/* 810 */     MCD_OPC_FilterValue, 188, 13, 10, 0, 0, // Skip to: 826
/* 816 */     MCD_OPC_CheckPredicate, 15, 212, 1, 0, // Skip to: 1289
/* 821 */     MCD_OPC_Decode, 155, 11, 128, 3, // Opcode: C_SEQ_D64_MM
/* 826 */     MCD_OPC_FilterValue, 252, 13, 10, 0, 0, // Skip to: 842
/* 832 */     MCD_OPC_CheckPredicate, 15, 196, 1, 0, // Skip to: 1289
/* 837 */     MCD_OPC_Decode, 131, 11, 128, 3, // Opcode: C_NGL_D64_MM
/* 842 */     MCD_OPC_FilterValue, 188, 14, 10, 0, 0, // Skip to: 858
/* 848 */     MCD_OPC_CheckPredicate, 15, 180, 1, 0, // Skip to: 1289
/* 853 */     MCD_OPC_Decode, 241, 10, 128, 3, // Opcode: C_LT_D64_MM
/* 858 */     MCD_OPC_FilterValue, 252, 14, 10, 0, 0, // Skip to: 874
/* 864 */     MCD_OPC_CheckPredicate, 15, 164, 1, 0, // Skip to: 1289
/* 869 */     MCD_OPC_Decode, 247, 10, 128, 3, // Opcode: C_NGE_D64_MM
/* 874 */     MCD_OPC_FilterValue, 188, 15, 10, 0, 0, // Skip to: 890
/* 880 */     MCD_OPC_CheckPredicate, 15, 148, 1, 0, // Skip to: 1289
/* 885 */     MCD_OPC_Decode, 235, 10, 128, 3, // Opcode: C_LE_D64_MM
/* 890 */     MCD_OPC_FilterValue, 252, 15, 137, 1, 0, // Skip to: 1289
/* 896 */     MCD_OPC_CheckPredicate, 15, 132, 1, 0, // Skip to: 1289
/* 901 */     MCD_OPC_Decode, 137, 11, 128, 3, // Opcode: C_NGT_D64_MM
/* 906 */     MCD_OPC_FilterValue, 24, 10, 0, 0, // Skip to: 921
/* 911 */     MCD_OPC_CheckPredicate, 95, 117, 1, 0, // Skip to: 1289
/* 916 */     MCD_OPC_Decode, 192, 11, 129, 3, // Opcode: DADDi
/* 921 */     MCD_OPC_FilterValue, 25, 10, 0, 0, // Skip to: 936
/* 926 */     MCD_OPC_CheckPredicate, 91, 102, 1, 0, // Skip to: 1289
/* 931 */     MCD_OPC_Decode, 193, 11, 129, 3, // Opcode: DADDiu
/* 936 */     MCD_OPC_FilterValue, 26, 10, 0, 0, // Skip to: 951
/* 941 */     MCD_OPC_CheckPredicate, 95, 87, 1, 0, // Skip to: 1289
/* 946 */     MCD_OPC_Decode, 193, 15, 141, 1, // Opcode: LDL
/* 951 */     MCD_OPC_FilterValue, 27, 10, 0, 0, // Skip to: 966
/* 956 */     MCD_OPC_CheckPredicate, 95, 72, 1, 0, // Skip to: 1289
/* 961 */     MCD_OPC_Decode, 195, 15, 141, 1, // Opcode: LDR
/* 966 */     MCD_OPC_FilterValue, 28, 33, 0, 0, // Skip to: 1004
/* 971 */     MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 974 */     MCD_OPC_FilterValue, 36, 10, 0, 0, // Skip to: 989
/* 979 */     MCD_OPC_CheckPredicate, 96, 49, 1, 0, // Skip to: 1289
/* 984 */     MCD_OPC_Decode, 202, 11, 130, 3, // Opcode: DCLZ
/* 989 */     MCD_OPC_FilterValue, 37, 39, 1, 0, // Skip to: 1289
/* 994 */     MCD_OPC_CheckPredicate, 96, 34, 1, 0, // Skip to: 1289
/* 999 */     MCD_OPC_Decode, 200, 11, 130, 3, // Opcode: DCLO
/* 1004 */    MCD_OPC_FilterValue, 31, 145, 0, 0, // Skip to: 1154
/* 1009 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1012 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 1027
/* 1017 */    MCD_OPC_CheckPredicate, 90, 11, 1, 0, // Skip to: 1289
/* 1022 */    MCD_OPC_Decode, 212, 11, 131, 3, // Opcode: DEXTM
/* 1027 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 1042
/* 1032 */    MCD_OPC_CheckPredicate, 90, 252, 0, 0, // Skip to: 1289
/* 1037 */    MCD_OPC_Decode, 213, 11, 131, 3, // Opcode: DEXTU
/* 1042 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 1057
/* 1047 */    MCD_OPC_CheckPredicate, 90, 237, 0, 0, // Skip to: 1289
/* 1052 */    MCD_OPC_Decode, 210, 11, 131, 3, // Opcode: DEXT
/* 1057 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 1072
/* 1062 */    MCD_OPC_CheckPredicate, 90, 222, 0, 0, // Skip to: 1289
/* 1067 */    MCD_OPC_Decode, 216, 11, 132, 3, // Opcode: DINSM
/* 1072 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 1087
/* 1077 */    MCD_OPC_CheckPredicate, 90, 207, 0, 0, // Skip to: 1289
/* 1082 */    MCD_OPC_Decode, 217, 11, 132, 3, // Opcode: DINSU
/* 1087 */    MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 1102
/* 1092 */    MCD_OPC_CheckPredicate, 90, 192, 0, 0, // Skip to: 1289
/* 1097 */    MCD_OPC_Decode, 215, 11, 132, 3, // Opcode: DINS
/* 1102 */    MCD_OPC_FilterValue, 36, 182, 0, 0, // Skip to: 1289
/* 1107 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 1110 */    MCD_OPC_FilterValue, 2, 17, 0, 0, // Skip to: 1132
/* 1115 */    MCD_OPC_CheckPredicate, 90, 169, 0, 0, // Skip to: 1289
/* 1120 */    MCD_OPC_CheckField, 21, 5, 0, 162, 0, 0, // Skip to: 1289
/* 1127 */    MCD_OPC_Decode, 184, 12, 241, 2, // Opcode: DSBH
/* 1132 */    MCD_OPC_FilterValue, 5, 152, 0, 0, // Skip to: 1289
/* 1137 */    MCD_OPC_CheckPredicate, 90, 147, 0, 0, // Skip to: 1289
/* 1142 */    MCD_OPC_CheckField, 21, 5, 0, 140, 0, 0, // Skip to: 1289
/* 1149 */    MCD_OPC_Decode, 186, 12, 241, 2, // Opcode: DSHD
/* 1154 */    MCD_OPC_FilterValue, 39, 10, 0, 0, // Skip to: 1169
/* 1159 */    MCD_OPC_CheckPredicate, 91, 125, 0, 0, // Skip to: 1289
/* 1164 */    MCD_OPC_Decode, 183, 16, 141, 1, // Opcode: LWu
/* 1169 */    MCD_OPC_FilterValue, 44, 10, 0, 0, // Skip to: 1184
/* 1174 */    MCD_OPC_CheckPredicate, 95, 110, 0, 0, // Skip to: 1289
/* 1179 */    MCD_OPC_Decode, 238, 20, 141, 1, // Opcode: SDL
/* 1184 */    MCD_OPC_FilterValue, 45, 10, 0, 0, // Skip to: 1199
/* 1189 */    MCD_OPC_CheckPredicate, 95, 95, 0, 0, // Skip to: 1289
/* 1194 */    MCD_OPC_Decode, 239, 20, 141, 1, // Opcode: SDR
/* 1199 */    MCD_OPC_FilterValue, 46, 10, 0, 0, // Skip to: 1214
/* 1204 */    MCD_OPC_CheckPredicate, 20, 80, 0, 0, // Skip to: 1289
/* 1209 */    MCD_OPC_Decode, 231, 20, 139, 1, // Opcode: SDC1_MM_D64
/* 1214 */    MCD_OPC_FilterValue, 47, 10, 0, 0, // Skip to: 1229
/* 1219 */    MCD_OPC_CheckPredicate, 20, 65, 0, 0, // Skip to: 1289
/* 1224 */    MCD_OPC_Decode, 184, 15, 139, 1, // Opcode: LDC1_MM_D64
/* 1229 */    MCD_OPC_FilterValue, 52, 10, 0, 0, // Skip to: 1244
/* 1234 */    MCD_OPC_CheckPredicate, 92, 50, 0, 0, // Skip to: 1289
/* 1239 */    MCD_OPC_Decode, 238, 15, 141, 1, // Opcode: LLD
/* 1244 */    MCD_OPC_FilterValue, 55, 10, 0, 0, // Skip to: 1259
/* 1249 */    MCD_OPC_CheckPredicate, 91, 35, 0, 0, // Skip to: 1289
/* 1254 */    MCD_OPC_Decode, 179, 15, 141, 1, // Opcode: LD
/* 1259 */    MCD_OPC_FilterValue, 60, 10, 0, 0, // Skip to: 1274
/* 1264 */    MCD_OPC_CheckPredicate, 95, 20, 0, 0, // Skip to: 1289
/* 1269 */    MCD_OPC_Decode, 209, 20, 141, 1, // Opcode: SCD
/* 1274 */    MCD_OPC_FilterValue, 63, 10, 0, 0, // Skip to: 1289
/* 1279 */    MCD_OPC_CheckPredicate, 91, 5, 0, 0, // Skip to: 1289
/* 1284 */    MCD_OPC_Decode, 218, 20, 141, 1, // Opcode: SD
/* 1289 */    MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMipsDSP32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 35, 10, 0, 0, // Skip to: 18
/* 8 */       MCD_OPC_CheckPredicate, 97, 20, 0, 0, // Skip to: 33
/* 13 */      MCD_OPC_Decode, 142, 16, 141, 1, // Opcode: LWDSP
/* 18 */      MCD_OPC_FilterValue, 43, 10, 0, 0, // Skip to: 33
/* 23 */      MCD_OPC_CheckPredicate, 97, 5, 0, 0, // Skip to: 33
/* 28 */      MCD_OPC_Decode, 140, 23, 141, 1, // Opcode: SWDSP
/* 33 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMipsFP6432[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 17, 249, 5, 0, // Skip to: 1537
/* 8 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 11 */      MCD_OPC_FilterValue, 0, 121, 0, 0, // Skip to: 137
/* 16 */      MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 19 */      MCD_OPC_FilterValue, 0, 17, 0, 0, // Skip to: 41
/* 24 */      MCD_OPC_CheckPredicate, 98, 158, 6, 0, // Skip to: 1723
/* 29 */      MCD_OPC_CheckField, 6, 5, 0, 151, 6, 0, // Skip to: 1723
/* 36 */      MCD_OPC_Decode, 133, 17, 133, 3, // Opcode: MFC1_D64
/* 41 */      MCD_OPC_FilterValue, 3, 17, 0, 0, // Skip to: 63
/* 46 */      MCD_OPC_CheckPredicate, 99, 136, 6, 0, // Skip to: 1723
/* 51 */      MCD_OPC_CheckField, 6, 5, 0, 129, 6, 0, // Skip to: 1723
/* 58 */      MCD_OPC_Decode, 145, 17, 133, 3, // Opcode: MFHC1_D64
/* 63 */      MCD_OPC_FilterValue, 4, 17, 0, 0, // Skip to: 85
/* 68 */      MCD_OPC_CheckPredicate, 98, 114, 6, 0, // Skip to: 1723
/* 73 */      MCD_OPC_CheckField, 6, 5, 0, 107, 6, 0, // Skip to: 1723
/* 80 */      MCD_OPC_Decode, 161, 18, 134, 3, // Opcode: MTC1_D64
/* 85 */      MCD_OPC_FilterValue, 7, 17, 0, 0, // Skip to: 107
/* 90 */      MCD_OPC_CheckPredicate, 99, 92, 6, 0, // Skip to: 1723
/* 95 */      MCD_OPC_CheckField, 6, 5, 0, 85, 6, 0, // Skip to: 1723
/* 102 */     MCD_OPC_Decode, 174, 18, 135, 3, // Opcode: MTHC1_D64
/* 107 */     MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 122
/* 112 */     MCD_OPC_CheckPredicate, 98, 70, 6, 0, // Skip to: 1723
/* 117 */     MCD_OPC_Decode, 139, 13, 230, 2, // Opcode: FADD_D64
/* 122 */     MCD_OPC_FilterValue, 22, 60, 6, 0, // Skip to: 1723
/* 127 */     MCD_OPC_CheckPredicate, 100, 55, 6, 0, // Skip to: 1723
/* 132 */     MCD_OPC_Decode, 141, 13, 230, 2, // Opcode: FADD_PS64
/* 137 */     MCD_OPC_FilterValue, 1, 33, 0, 0, // Skip to: 175
/* 142 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 145 */     MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 160
/* 150 */     MCD_OPC_CheckPredicate, 98, 32, 6, 0, // Skip to: 1723
/* 155 */     MCD_OPC_Decode, 157, 14, 230, 2, // Opcode: FSUB_D64
/* 160 */     MCD_OPC_FilterValue, 22, 22, 6, 0, // Skip to: 1723
/* 165 */     MCD_OPC_CheckPredicate, 100, 17, 6, 0, // Skip to: 1723
/* 170 */     MCD_OPC_Decode, 159, 14, 230, 2, // Opcode: FSUB_PS64
/* 175 */     MCD_OPC_FilterValue, 2, 33, 0, 0, // Skip to: 213
/* 180 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 183 */     MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 198
/* 188 */     MCD_OPC_CheckPredicate, 98, 250, 5, 0, // Skip to: 1723
/* 193 */     MCD_OPC_Decode, 240, 13, 230, 2, // Opcode: FMUL_D64
/* 198 */     MCD_OPC_FilterValue, 22, 240, 5, 0, // Skip to: 1723
/* 203 */     MCD_OPC_CheckPredicate, 100, 235, 5, 0, // Skip to: 1723
/* 208 */     MCD_OPC_Decode, 242, 13, 230, 2, // Opcode: FMUL_PS64
/* 213 */     MCD_OPC_FilterValue, 3, 17, 0, 0, // Skip to: 235
/* 218 */     MCD_OPC_CheckPredicate, 98, 220, 5, 0, // Skip to: 1723
/* 223 */     MCD_OPC_CheckField, 21, 5, 17, 213, 5, 0, // Skip to: 1723
/* 230 */     MCD_OPC_Decode, 178, 13, 230, 2, // Opcode: FDIV_D64
/* 235 */     MCD_OPC_FilterValue, 4, 18, 0, 0, // Skip to: 258
/* 240 */     MCD_OPC_CheckPredicate, 101, 198, 5, 0, // Skip to: 1723
/* 245 */     MCD_OPC_CheckField, 16, 10, 160, 4, 190, 5, 0, // Skip to: 1723
/* 253 */     MCD_OPC_Decode, 149, 14, 230, 1, // Opcode: FSQRT_D64
/* 258 */     MCD_OPC_FilterValue, 5, 18, 0, 0, // Skip to: 281
/* 263 */     MCD_OPC_CheckPredicate, 98, 175, 5, 0, // Skip to: 1723
/* 268 */     MCD_OPC_CheckField, 16, 10, 160, 4, 167, 5, 0, // Skip to: 1723
/* 276 */     MCD_OPC_Decode, 132, 13, 230, 1, // Opcode: FABS_D64
/* 281 */     MCD_OPC_FilterValue, 6, 18, 0, 0, // Skip to: 304
/* 286 */     MCD_OPC_CheckPredicate, 98, 152, 5, 0, // Skip to: 1723
/* 291 */     MCD_OPC_CheckField, 16, 10, 160, 4, 144, 5, 0, // Skip to: 1723
/* 299 */     MCD_OPC_Decode, 229, 13, 230, 1, // Opcode: FMOV_D64
/* 304 */     MCD_OPC_FilterValue, 7, 18, 0, 0, // Skip to: 327
/* 309 */     MCD_OPC_CheckPredicate, 98, 129, 5, 0, // Skip to: 1723
/* 314 */     MCD_OPC_CheckField, 16, 10, 160, 4, 121, 5, 0, // Skip to: 1723
/* 322 */     MCD_OPC_Decode, 249, 13, 230, 1, // Opcode: FNEG_D64
/* 327 */     MCD_OPC_FilterValue, 8, 35, 0, 0, // Skip to: 367
/* 332 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 335 */     MCD_OPC_FilterValue, 128, 4, 10, 0, 0, // Skip to: 351
/* 341 */     MCD_OPC_CheckPredicate, 101, 97, 5, 0, // Skip to: 1723
/* 346 */     MCD_OPC_Decode, 164, 20, 223, 1, // Opcode: ROUND_L_S
/* 351 */     MCD_OPC_FilterValue, 160, 4, 86, 5, 0, // Skip to: 1723
/* 357 */     MCD_OPC_CheckPredicate, 102, 81, 5, 0, // Skip to: 1723
/* 362 */     MCD_OPC_Decode, 162, 20, 230, 1, // Opcode: ROUND_L_D64
/* 367 */     MCD_OPC_FilterValue, 9, 35, 0, 0, // Skip to: 407
/* 372 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 375 */     MCD_OPC_FilterValue, 128, 4, 10, 0, 0, // Skip to: 391
/* 381 */     MCD_OPC_CheckPredicate, 101, 57, 5, 0, // Skip to: 1723
/* 386 */     MCD_OPC_Decode, 136, 24, 223, 1, // Opcode: TRUNC_L_S
/* 391 */     MCD_OPC_FilterValue, 160, 4, 46, 5, 0, // Skip to: 1723
/* 397 */     MCD_OPC_CheckPredicate, 102, 41, 5, 0, // Skip to: 1723
/* 402 */     MCD_OPC_Decode, 134, 24, 230, 1, // Opcode: TRUNC_L_D64
/* 407 */     MCD_OPC_FilterValue, 10, 35, 0, 0, // Skip to: 447
/* 412 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 415 */     MCD_OPC_FilterValue, 128, 4, 10, 0, 0, // Skip to: 431
/* 421 */     MCD_OPC_CheckPredicate, 101, 17, 5, 0, // Skip to: 1723
/* 426 */     MCD_OPC_Decode, 255, 8, 223, 1, // Opcode: CEIL_L_S
/* 431 */     MCD_OPC_FilterValue, 160, 4, 6, 5, 0, // Skip to: 1723
/* 437 */     MCD_OPC_CheckPredicate, 102, 1, 5, 0, // Skip to: 1723
/* 442 */     MCD_OPC_Decode, 253, 8, 230, 1, // Opcode: CEIL_L_D64
/* 447 */     MCD_OPC_FilterValue, 11, 35, 0, 0, // Skip to: 487
/* 452 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 455 */     MCD_OPC_FilterValue, 128, 4, 10, 0, 0, // Skip to: 471
/* 461 */     MCD_OPC_CheckPredicate, 101, 233, 4, 0, // Skip to: 1723
/* 466 */     MCD_OPC_Decode, 208, 13, 223, 1, // Opcode: FLOOR_L_S
/* 471 */     MCD_OPC_FilterValue, 160, 4, 222, 4, 0, // Skip to: 1723
/* 477 */     MCD_OPC_CheckPredicate, 102, 217, 4, 0, // Skip to: 1723
/* 482 */     MCD_OPC_Decode, 206, 13, 230, 1, // Opcode: FLOOR_L_D64
/* 487 */     MCD_OPC_FilterValue, 12, 18, 0, 0, // Skip to: 510
/* 492 */     MCD_OPC_CheckPredicate, 101, 202, 4, 0, // Skip to: 1723
/* 497 */     MCD_OPC_CheckField, 16, 10, 160, 4, 194, 4, 0, // Skip to: 1723
/* 505 */     MCD_OPC_Decode, 167, 20, 136, 3, // Opcode: ROUND_W_D64
/* 510 */     MCD_OPC_FilterValue, 13, 18, 0, 0, // Skip to: 533
/* 515 */     MCD_OPC_CheckPredicate, 101, 179, 4, 0, // Skip to: 1723
/* 520 */     MCD_OPC_CheckField, 16, 10, 160, 4, 171, 4, 0, // Skip to: 1723
/* 528 */     MCD_OPC_Decode, 139, 24, 136, 3, // Opcode: TRUNC_W_D64
/* 533 */     MCD_OPC_FilterValue, 14, 18, 0, 0, // Skip to: 556
/* 538 */     MCD_OPC_CheckPredicate, 101, 156, 4, 0, // Skip to: 1723
/* 543 */     MCD_OPC_CheckField, 16, 10, 160, 4, 148, 4, 0, // Skip to: 1723
/* 551 */     MCD_OPC_Decode, 130, 9, 136, 3, // Opcode: CEIL_W_D64
/* 556 */     MCD_OPC_FilterValue, 15, 18, 0, 0, // Skip to: 579
/* 561 */     MCD_OPC_CheckPredicate, 101, 133, 4, 0, // Skip to: 1723
/* 566 */     MCD_OPC_CheckField, 16, 10, 160, 4, 125, 4, 0, // Skip to: 1723
/* 574 */     MCD_OPC_Decode, 211, 13, 136, 3, // Opcode: FLOOR_W_D64
/* 579 */     MCD_OPC_FilterValue, 17, 47, 0, 0, // Skip to: 631
/* 584 */     MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 587 */     MCD_OPC_FilterValue, 0, 17, 0, 0, // Skip to: 609
/* 592 */     MCD_OPC_CheckPredicate, 103, 102, 4, 0, // Skip to: 1723
/* 597 */     MCD_OPC_CheckField, 21, 5, 17, 95, 4, 0, // Skip to: 1723
/* 604 */     MCD_OPC_Decode, 219, 17, 137, 3, // Opcode: MOVF_D64
/* 609 */     MCD_OPC_FilterValue, 1, 85, 4, 0, // Skip to: 1723
/* 614 */     MCD_OPC_CheckPredicate, 103, 80, 4, 0, // Skip to: 1723
/* 619 */     MCD_OPC_CheckField, 21, 5, 17, 73, 4, 0, // Skip to: 1723
/* 626 */     MCD_OPC_Decode, 240, 17, 137, 3, // Opcode: MOVT_D64
/* 631 */     MCD_OPC_FilterValue, 18, 17, 0, 0, // Skip to: 653
/* 636 */     MCD_OPC_CheckPredicate, 103, 58, 4, 0, // Skip to: 1723
/* 641 */     MCD_OPC_CheckField, 21, 5, 17, 51, 4, 0, // Skip to: 1723
/* 648 */     MCD_OPC_Decode, 252, 17, 138, 3, // Opcode: MOVZ_I_D64
/* 653 */     MCD_OPC_FilterValue, 19, 17, 0, 0, // Skip to: 675
/* 658 */     MCD_OPC_CheckPredicate, 103, 36, 4, 0, // Skip to: 1723
/* 663 */     MCD_OPC_CheckField, 21, 5, 17, 29, 4, 0, // Skip to: 1723
/* 670 */     MCD_OPC_Decode, 231, 17, 138, 3, // Opcode: MOVN_I_D64
/* 675 */     MCD_OPC_FilterValue, 21, 18, 0, 0, // Skip to: 698
/* 680 */     MCD_OPC_CheckPredicate, 104, 14, 4, 0, // Skip to: 1723
/* 685 */     MCD_OPC_CheckField, 16, 10, 160, 4, 6, 4, 0, // Skip to: 1723
/* 693 */     MCD_OPC_Decode, 136, 20, 230, 1, // Opcode: RECIP_D64
/* 698 */     MCD_OPC_FilterValue, 22, 18, 0, 0, // Skip to: 721
/* 703 */     MCD_OPC_CheckPredicate, 104, 247, 3, 0, // Skip to: 1723
/* 708 */     MCD_OPC_CheckField, 16, 10, 160, 4, 239, 3, 0, // Skip to: 1723
/* 716 */     MCD_OPC_Decode, 175, 20, 230, 1, // Opcode: RSQRT_D64
/* 721 */     MCD_OPC_FilterValue, 24, 17, 0, 0, // Skip to: 743
/* 726 */     MCD_OPC_CheckPredicate, 105, 224, 3, 0, // Skip to: 1723
/* 731 */     MCD_OPC_CheckField, 21, 5, 22, 217, 3, 0, // Skip to: 1723
/* 738 */     MCD_OPC_Decode, 155, 6, 230, 2, // Opcode: ADDR_PS64
/* 743 */     MCD_OPC_FilterValue, 26, 17, 0, 0, // Skip to: 765
/* 748 */     MCD_OPC_CheckPredicate, 105, 202, 3, 0, // Skip to: 1723
/* 753 */     MCD_OPC_CheckField, 21, 5, 22, 195, 3, 0, // Skip to: 1723
/* 760 */     MCD_OPC_Decode, 223, 18, 230, 2, // Opcode: MULR_PS64
/* 765 */     MCD_OPC_FilterValue, 32, 51, 0, 0, // Skip to: 821
/* 770 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 773 */     MCD_OPC_FilterValue, 160, 4, 10, 0, 0, // Skip to: 789
/* 779 */     MCD_OPC_CheckPredicate, 98, 171, 3, 0, // Skip to: 1723
/* 784 */     MCD_OPC_Decode, 204, 10, 136, 3, // Opcode: CVT_S_D64
/* 789 */     MCD_OPC_FilterValue, 160, 5, 10, 0, 0, // Skip to: 805
/* 795 */     MCD_OPC_CheckPredicate, 106, 155, 3, 0, // Skip to: 1723
/* 800 */     MCD_OPC_Decode, 206, 10, 136, 3, // Opcode: CVT_S_L
/* 805 */     MCD_OPC_FilterValue, 192, 5, 144, 3, 0, // Skip to: 1723
/* 811 */     MCD_OPC_CheckPredicate, 100, 139, 3, 0, // Skip to: 1723
/* 816 */     MCD_OPC_Decode, 209, 10, 136, 3, // Opcode: CVT_S_PU64
/* 821 */     MCD_OPC_FilterValue, 33, 51, 0, 0, // Skip to: 877
/* 826 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 829 */     MCD_OPC_FilterValue, 128, 4, 10, 0, 0, // Skip to: 845
/* 835 */     MCD_OPC_CheckPredicate, 98, 115, 3, 0, // Skip to: 1723
/* 840 */     MCD_OPC_Decode, 188, 10, 223, 1, // Opcode: CVT_D64_S
/* 845 */     MCD_OPC_FilterValue, 128, 5, 10, 0, 0, // Skip to: 861
/* 851 */     MCD_OPC_CheckPredicate, 98, 99, 3, 0, // Skip to: 1723
/* 856 */     MCD_OPC_Decode, 190, 10, 223, 1, // Opcode: CVT_D64_W
/* 861 */     MCD_OPC_FilterValue, 160, 5, 88, 3, 0, // Skip to: 1723
/* 867 */     MCD_OPC_CheckPredicate, 106, 83, 3, 0, // Skip to: 1723
/* 872 */     MCD_OPC_Decode, 187, 10, 230, 1, // Opcode: CVT_D64_L
/* 877 */     MCD_OPC_FilterValue, 36, 35, 0, 0, // Skip to: 917
/* 882 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 885 */     MCD_OPC_FilterValue, 160, 4, 10, 0, 0, // Skip to: 901
/* 891 */     MCD_OPC_CheckPredicate, 98, 59, 3, 0, // Skip to: 1723
/* 896 */     MCD_OPC_Decode, 215, 10, 136, 3, // Opcode: CVT_W_D64
/* 901 */     MCD_OPC_FilterValue, 192, 5, 48, 3, 0, // Skip to: 1723
/* 907 */     MCD_OPC_CheckPredicate, 105, 43, 3, 0, // Skip to: 1723
/* 912 */     MCD_OPC_Decode, 201, 10, 230, 1, // Opcode: CVT_PW_PS64
/* 917 */     MCD_OPC_FilterValue, 38, 40, 0, 0, // Skip to: 962
/* 922 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 925 */     MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 940
/* 930 */     MCD_OPC_CheckPredicate, 100, 20, 3, 0, // Skip to: 1723
/* 935 */     MCD_OPC_Decode, 200, 10, 139, 3, // Opcode: CVT_PS_S64
/* 940 */     MCD_OPC_FilterValue, 20, 10, 3, 0, // Skip to: 1723
/* 945 */     MCD_OPC_CheckPredicate, 105, 5, 3, 0, // Skip to: 1723
/* 950 */     MCD_OPC_CheckField, 16, 5, 0, 254, 2, 0, // Skip to: 1723
/* 957 */     MCD_OPC_Decode, 199, 10, 230, 1, // Opcode: CVT_PS_PW64
/* 962 */     MCD_OPC_FilterValue, 40, 18, 0, 0, // Skip to: 985
/* 967 */     MCD_OPC_CheckPredicate, 100, 239, 2, 0, // Skip to: 1723
/* 972 */     MCD_OPC_CheckField, 16, 10, 192, 5, 231, 2, 0, // Skip to: 1723
/* 980 */     MCD_OPC_Decode, 208, 10, 136, 3, // Opcode: CVT_S_PL64
/* 985 */     MCD_OPC_FilterValue, 44, 17, 0, 0, // Skip to: 1007
/* 990 */     MCD_OPC_CheckPredicate, 100, 216, 2, 0, // Skip to: 1723
/* 995 */     MCD_OPC_CheckField, 21, 5, 22, 209, 2, 0, // Skip to: 1723
/* 1002 */    MCD_OPC_Decode, 201, 19, 230, 2, // Opcode: PLL_PS64
/* 1007 */    MCD_OPC_FilterValue, 45, 17, 0, 0, // Skip to: 1029
/* 1012 */    MCD_OPC_CheckPredicate, 100, 194, 2, 0, // Skip to: 1723
/* 1017 */    MCD_OPC_CheckField, 21, 5, 22, 187, 2, 0, // Skip to: 1723
/* 1024 */    MCD_OPC_Decode, 202, 19, 230, 2, // Opcode: PLU_PS64
/* 1029 */    MCD_OPC_FilterValue, 46, 17, 0, 0, // Skip to: 1051
/* 1034 */    MCD_OPC_CheckPredicate, 100, 172, 2, 0, // Skip to: 1723
/* 1039 */    MCD_OPC_CheckField, 21, 5, 22, 165, 2, 0, // Skip to: 1723
/* 1046 */    MCD_OPC_Decode, 249, 19, 230, 2, // Opcode: PUL_PS64
/* 1051 */    MCD_OPC_FilterValue, 47, 17, 0, 0, // Skip to: 1073
/* 1056 */    MCD_OPC_CheckPredicate, 100, 150, 2, 0, // Skip to: 1723
/* 1061 */    MCD_OPC_CheckField, 21, 5, 22, 143, 2, 0, // Skip to: 1723
/* 1068 */    MCD_OPC_Decode, 250, 19, 230, 2, // Opcode: PUU_PS64
/* 1073 */    MCD_OPC_FilterValue, 48, 24, 0, 0, // Skip to: 1102
/* 1078 */    MCD_OPC_CheckPredicate, 107, 128, 2, 0, // Skip to: 1723
/* 1083 */    MCD_OPC_CheckField, 21, 5, 17, 121, 2, 0, // Skip to: 1723
/* 1090 */    MCD_OPC_CheckField, 6, 2, 0, 114, 2, 0, // Skip to: 1723
/* 1097 */    MCD_OPC_Decode, 228, 10, 140, 3, // Opcode: C_F_D64
/* 1102 */    MCD_OPC_FilterValue, 49, 24, 0, 0, // Skip to: 1131
/* 1107 */    MCD_OPC_CheckPredicate, 107, 99, 2, 0, // Skip to: 1723
/* 1112 */    MCD_OPC_CheckField, 21, 5, 17, 92, 2, 0, // Skip to: 1723
/* 1119 */    MCD_OPC_CheckField, 6, 2, 0, 85, 2, 0, // Skip to: 1723
/* 1126 */    MCD_OPC_Decode, 184, 11, 140, 3, // Opcode: C_UN_D64
/* 1131 */    MCD_OPC_FilterValue, 50, 24, 0, 0, // Skip to: 1160
/* 1136 */    MCD_OPC_CheckPredicate, 107, 70, 2, 0, // Skip to: 1723
/* 1141 */    MCD_OPC_CheckField, 21, 5, 17, 63, 2, 0, // Skip to: 1723
/* 1148 */    MCD_OPC_CheckField, 6, 2, 0, 56, 2, 0, // Skip to: 1723
/* 1155 */    MCD_OPC_Decode, 222, 10, 140, 3, // Opcode: C_EQ_D64
/* 1160 */    MCD_OPC_FilterValue, 51, 24, 0, 0, // Skip to: 1189
/* 1165 */    MCD_OPC_CheckPredicate, 107, 41, 2, 0, // Skip to: 1723
/* 1170 */    MCD_OPC_CheckField, 21, 5, 17, 34, 2, 0, // Skip to: 1723
/* 1177 */    MCD_OPC_CheckField, 6, 2, 0, 27, 2, 0, // Skip to: 1723
/* 1184 */    MCD_OPC_Decode, 166, 11, 140, 3, // Opcode: C_UEQ_D64
/* 1189 */    MCD_OPC_FilterValue, 52, 24, 0, 0, // Skip to: 1218
/* 1194 */    MCD_OPC_CheckPredicate, 107, 12, 2, 0, // Skip to: 1723
/* 1199 */    MCD_OPC_CheckField, 21, 5, 17, 5, 2, 0, // Skip to: 1723
/* 1206 */    MCD_OPC_CheckField, 6, 2, 0, 254, 1, 0, // Skip to: 1723
/* 1213 */    MCD_OPC_Decode, 148, 11, 140, 3, // Opcode: C_OLT_D64
/* 1218 */    MCD_OPC_FilterValue, 53, 24, 0, 0, // Skip to: 1247
/* 1223 */    MCD_OPC_CheckPredicate, 107, 239, 1, 0, // Skip to: 1723
/* 1228 */    MCD_OPC_CheckField, 21, 5, 17, 232, 1, 0, // Skip to: 1723
/* 1235 */    MCD_OPC_CheckField, 6, 2, 0, 225, 1, 0, // Skip to: 1723
/* 1242 */    MCD_OPC_Decode, 178, 11, 140, 3, // Opcode: C_ULT_D64
/* 1247 */    MCD_OPC_FilterValue, 54, 24, 0, 0, // Skip to: 1276
/* 1252 */    MCD_OPC_CheckPredicate, 107, 210, 1, 0, // Skip to: 1723
/* 1257 */    MCD_OPC_CheckField, 21, 5, 17, 203, 1, 0, // Skip to: 1723
/* 1264 */    MCD_OPC_CheckField, 6, 2, 0, 196, 1, 0, // Skip to: 1723
/* 1271 */    MCD_OPC_Decode, 142, 11, 140, 3, // Opcode: C_OLE_D64
/* 1276 */    MCD_OPC_FilterValue, 55, 24, 0, 0, // Skip to: 1305
/* 1281 */    MCD_OPC_CheckPredicate, 107, 181, 1, 0, // Skip to: 1723
/* 1286 */    MCD_OPC_CheckField, 21, 5, 17, 174, 1, 0, // Skip to: 1723
/* 1293 */    MCD_OPC_CheckField, 6, 2, 0, 167, 1, 0, // Skip to: 1723
/* 1300 */    MCD_OPC_Decode, 172, 11, 140, 3, // Opcode: C_ULE_D64
/* 1305 */    MCD_OPC_FilterValue, 56, 24, 0, 0, // Skip to: 1334
/* 1310 */    MCD_OPC_CheckPredicate, 107, 152, 1, 0, // Skip to: 1723
/* 1315 */    MCD_OPC_CheckField, 21, 5, 17, 145, 1, 0, // Skip to: 1723
/* 1322 */    MCD_OPC_CheckField, 6, 2, 0, 138, 1, 0, // Skip to: 1723
/* 1329 */    MCD_OPC_Decode, 160, 11, 140, 3, // Opcode: C_SF_D64
/* 1334 */    MCD_OPC_FilterValue, 57, 24, 0, 0, // Skip to: 1363
/* 1339 */    MCD_OPC_CheckPredicate, 107, 123, 1, 0, // Skip to: 1723
/* 1344 */    MCD_OPC_CheckField, 21, 5, 17, 116, 1, 0, // Skip to: 1723
/* 1351 */    MCD_OPC_CheckField, 6, 2, 0, 109, 1, 0, // Skip to: 1723
/* 1358 */    MCD_OPC_Decode, 252, 10, 140, 3, // Opcode: C_NGLE_D64
/* 1363 */    MCD_OPC_FilterValue, 58, 24, 0, 0, // Skip to: 1392
/* 1368 */    MCD_OPC_CheckPredicate, 107, 94, 1, 0, // Skip to: 1723
/* 1373 */    MCD_OPC_CheckField, 21, 5, 17, 87, 1, 0, // Skip to: 1723
/* 1380 */    MCD_OPC_CheckField, 6, 2, 0, 80, 1, 0, // Skip to: 1723
/* 1387 */    MCD_OPC_Decode, 154, 11, 140, 3, // Opcode: C_SEQ_D64
/* 1392 */    MCD_OPC_FilterValue, 59, 24, 0, 0, // Skip to: 1421
/* 1397 */    MCD_OPC_CheckPredicate, 107, 65, 1, 0, // Skip to: 1723
/* 1402 */    MCD_OPC_CheckField, 21, 5, 17, 58, 1, 0, // Skip to: 1723
/* 1409 */    MCD_OPC_CheckField, 6, 2, 0, 51, 1, 0, // Skip to: 1723
/* 1416 */    MCD_OPC_Decode, 130, 11, 140, 3, // Opcode: C_NGL_D64
/* 1421 */    MCD_OPC_FilterValue, 60, 24, 0, 0, // Skip to: 1450
/* 1426 */    MCD_OPC_CheckPredicate, 107, 36, 1, 0, // Skip to: 1723
/* 1431 */    MCD_OPC_CheckField, 21, 5, 17, 29, 1, 0, // Skip to: 1723
/* 1438 */    MCD_OPC_CheckField, 6, 2, 0, 22, 1, 0, // Skip to: 1723
/* 1445 */    MCD_OPC_Decode, 240, 10, 140, 3, // Opcode: C_LT_D64
/* 1450 */    MCD_OPC_FilterValue, 61, 24, 0, 0, // Skip to: 1479
/* 1455 */    MCD_OPC_CheckPredicate, 107, 7, 1, 0, // Skip to: 1723
/* 1460 */    MCD_OPC_CheckField, 21, 5, 17, 0, 1, 0, // Skip to: 1723
/* 1467 */    MCD_OPC_CheckField, 6, 2, 0, 249, 0, 0, // Skip to: 1723
/* 1474 */    MCD_OPC_Decode, 246, 10, 140, 3, // Opcode: C_NGE_D64
/* 1479 */    MCD_OPC_FilterValue, 62, 24, 0, 0, // Skip to: 1508
/* 1484 */    MCD_OPC_CheckPredicate, 107, 234, 0, 0, // Skip to: 1723
/* 1489 */    MCD_OPC_CheckField, 21, 5, 17, 227, 0, 0, // Skip to: 1723
/* 1496 */    MCD_OPC_CheckField, 6, 2, 0, 220, 0, 0, // Skip to: 1723
/* 1503 */    MCD_OPC_Decode, 234, 10, 140, 3, // Opcode: C_LE_D64
/* 1508 */    MCD_OPC_FilterValue, 63, 210, 0, 0, // Skip to: 1723
/* 1513 */    MCD_OPC_CheckPredicate, 107, 205, 0, 0, // Skip to: 1723
/* 1518 */    MCD_OPC_CheckField, 21, 5, 17, 198, 0, 0, // Skip to: 1723
/* 1525 */    MCD_OPC_CheckField, 6, 2, 0, 191, 0, 0, // Skip to: 1723
/* 1532 */    MCD_OPC_Decode, 136, 11, 140, 3, // Opcode: C_NGT_D64
/* 1537 */    MCD_OPC_FilterValue, 19, 151, 0, 0, // Skip to: 1693
/* 1542 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1545 */    MCD_OPC_FilterValue, 1, 17, 0, 0, // Skip to: 1567
/* 1550 */    MCD_OPC_CheckPredicate, 108, 168, 0, 0, // Skip to: 1723
/* 1555 */    MCD_OPC_CheckField, 11, 5, 0, 161, 0, 0, // Skip to: 1723
/* 1562 */    MCD_OPC_Decode, 197, 15, 141, 3, // Opcode: LDXC164
/* 1567 */    MCD_OPC_FilterValue, 5, 17, 0, 0, // Skip to: 1589
/* 1572 */    MCD_OPC_CheckPredicate, 109, 146, 0, 0, // Skip to: 1723
/* 1577 */    MCD_OPC_CheckField, 11, 5, 0, 139, 0, 0, // Skip to: 1723
/* 1584 */    MCD_OPC_Decode, 254, 15, 141, 3, // Opcode: LUXC164
/* 1589 */    MCD_OPC_FilterValue, 9, 17, 0, 0, // Skip to: 1611
/* 1594 */    MCD_OPC_CheckPredicate, 108, 124, 0, 0, // Skip to: 1723
/* 1599 */    MCD_OPC_CheckField, 6, 5, 0, 117, 0, 0, // Skip to: 1723
/* 1606 */    MCD_OPC_Decode, 241, 20, 142, 3, // Opcode: SDXC164
/* 1611 */    MCD_OPC_FilterValue, 13, 17, 0, 0, // Skip to: 1633
/* 1616 */    MCD_OPC_CheckPredicate, 109, 102, 0, 0, // Skip to: 1723
/* 1621 */    MCD_OPC_CheckField, 6, 5, 0, 95, 0, 0, // Skip to: 1723
/* 1628 */    MCD_OPC_Decode, 254, 22, 142, 3, // Opcode: SUXC164
/* 1633 */    MCD_OPC_FilterValue, 33, 10, 0, 0, // Skip to: 1648
/* 1638 */    MCD_OPC_CheckPredicate, 110, 80, 0, 0, // Skip to: 1723
/* 1643 */    MCD_OPC_Decode, 212, 16, 143, 3, // Opcode: MADD_D64
/* 1648 */    MCD_OPC_FilterValue, 41, 10, 0, 0, // Skip to: 1663
/* 1653 */    MCD_OPC_CheckPredicate, 110, 65, 0, 0, // Skip to: 1723
/* 1658 */    MCD_OPC_Decode, 148, 18, 143, 3, // Opcode: MSUB_D64
/* 1663 */    MCD_OPC_FilterValue, 49, 10, 0, 0, // Skip to: 1678
/* 1668 */    MCD_OPC_CheckPredicate, 111, 50, 0, 0, // Skip to: 1723
/* 1673 */    MCD_OPC_Decode, 141, 19, 143, 3, // Opcode: NMADD_D64
/* 1678 */    MCD_OPC_FilterValue, 57, 40, 0, 0, // Skip to: 1723
/* 1683 */    MCD_OPC_CheckPredicate, 111, 35, 0, 0, // Skip to: 1723
/* 1688 */    MCD_OPC_Decode, 146, 19, 143, 3, // Opcode: NMSUB_D64
/* 1693 */    MCD_OPC_FilterValue, 53, 10, 0, 0, // Skip to: 1708
/* 1698 */    MCD_OPC_CheckPredicate, 101, 20, 0, 0, // Skip to: 1723
/* 1703 */    MCD_OPC_Decode, 181, 15, 219, 2, // Opcode: LDC164
/* 1708 */    MCD_OPC_FilterValue, 61, 10, 0, 0, // Skip to: 1723
/* 1713 */    MCD_OPC_CheckPredicate, 101, 5, 0, 0, // Skip to: 1723
/* 1718 */    MCD_OPC_Decode, 228, 20, 219, 2, // Opcode: SDC164
/* 1723 */    MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableNanoMips16[] = {
/* 0 */       MCD_OPC_ExtractField, 10, 6,  // Inst{15-10} ...
/* 3 */       MCD_OPC_FilterValue, 4, 60, 0, 0, // Skip to: 68
/* 8 */       MCD_OPC_CheckPredicate, 112, 12, 0, 0, // Skip to: 25
/* 13 */      MCD_OPC_CheckField, 2, 8, 2, 5, 0, 0, // Skip to: 25
/* 20 */      MCD_OPC_Decode, 183, 23, 144, 3, // Opcode: SYSCALL16_NM
/* 25 */      MCD_OPC_ExtractField, 3, 7,  // Inst{9-3} ...
/* 28 */      MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 43
/* 33 */      MCD_OPC_CheckPredicate, 112, 20, 0, 0, // Skip to: 58
/* 38 */      MCD_OPC_Decode, 214, 8, 145, 3, // Opcode: BREAK16_NM
/* 43 */      MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 58
/* 48 */      MCD_OPC_CheckPredicate, 112, 5, 0, 0, // Skip to: 58
/* 53 */      MCD_OPC_Decode, 222, 20, 145, 3, // Opcode: SDBBP16_NM
/* 58 */      MCD_OPC_CheckPredicate, 112, 243, 2, 0, // Skip to: 818
/* 63 */      MCD_OPC_Decode, 215, 17, 146, 3, // Opcode: MOVE_NM
/* 68 */      MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 83
/* 73 */      MCD_OPC_CheckPredicate, 112, 228, 2, 0, // Skip to: 818
/* 78 */      MCD_OPC_Decode, 133, 16, 147, 3, // Opcode: LW16_NM
/* 83 */      MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 98
/* 88 */      MCD_OPC_CheckPredicate, 112, 213, 2, 0, // Skip to: 818
/* 93 */      MCD_OPC_Decode, 163, 7, 148, 3, // Opcode: BC16_NM
/* 98 */      MCD_OPC_FilterValue, 7, 33, 0, 0, // Skip to: 136
/* 103 */     MCD_OPC_ExtractField, 8, 1,  // Inst{8} ...
/* 106 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 121
/* 111 */     MCD_OPC_CheckPredicate, 112, 190, 2, 0, // Skip to: 818
/* 116 */     MCD_OPC_Decode, 191, 20, 149, 3, // Opcode: SAVE16_NM
/* 121 */     MCD_OPC_FilterValue, 1, 180, 2, 0, // Skip to: 818
/* 126 */     MCD_OPC_CheckPredicate, 112, 175, 2, 0, // Skip to: 818
/* 131 */     MCD_OPC_Decode, 148, 20, 149, 3, // Opcode: RESTOREJRC16_NM
/* 136 */     MCD_OPC_FilterValue, 12, 33, 0, 0, // Skip to: 174
/* 141 */     MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 144 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 159
/* 149 */     MCD_OPC_CheckPredicate, 112, 152, 2, 0, // Skip to: 818
/* 154 */     MCD_OPC_Decode, 222, 21, 150, 3, // Opcode: SLL16_NM
/* 159 */     MCD_OPC_FilterValue, 1, 142, 2, 0, // Skip to: 818
/* 164 */     MCD_OPC_CheckPredicate, 112, 137, 2, 0, // Skip to: 818
/* 169 */     MCD_OPC_Decode, 163, 22, 150, 3, // Opcode: SRL16_NM
/* 174 */     MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 189
/* 179 */     MCD_OPC_CheckPredicate, 112, 122, 2, 0, // Skip to: 818
/* 184 */     MCD_OPC_Decode, 167, 16, 151, 3, // Opcode: LWSP16_NM
/* 189 */     MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 204
/* 194 */     MCD_OPC_CheckPredicate, 112, 107, 2, 0, // Skip to: 818
/* 199 */     MCD_OPC_Decode, 149, 7, 148, 3, // Opcode: BALC16_NM
/* 204 */     MCD_OPC_FilterValue, 15, 47, 0, 0, // Skip to: 256
/* 209 */     MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 212 */     MCD_OPC_FilterValue, 0, 17, 0, 0, // Skip to: 234
/* 217 */     MCD_OPC_CheckPredicate, 112, 84, 2, 0, // Skip to: 818
/* 222 */     MCD_OPC_CheckField, 8, 1, 0, 77, 2, 0, // Skip to: 818
/* 229 */     MCD_OPC_Decode, 208, 6, 152, 3, // Opcode: ADDu4x4_NM
/* 234 */     MCD_OPC_FilterValue, 1, 67, 2, 0, // Skip to: 818
/* 239 */     MCD_OPC_CheckPredicate, 112, 62, 2, 0, // Skip to: 818
/* 244 */     MCD_OPC_CheckField, 8, 1, 0, 55, 2, 0, // Skip to: 818
/* 251 */     MCD_OPC_Decode, 206, 18, 152, 3, // Opcode: MUL4x4_NM
/* 256 */     MCD_OPC_FilterValue, 20, 86, 0, 0, // Skip to: 347
/* 261 */     MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 264 */     MCD_OPC_FilterValue, 0, 63, 0, 0, // Skip to: 332
/* 269 */     MCD_OPC_ExtractField, 1, 3,  // Inst{3-1} ...
/* 272 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 287
/* 277 */     MCD_OPC_CheckPredicate, 112, 24, 2, 0, // Skip to: 818
/* 282 */     MCD_OPC_Decode, 160, 19, 153, 3, // Opcode: NOT16_NM
/* 287 */     MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 302
/* 292 */     MCD_OPC_CheckPredicate, 112, 9, 2, 0, // Skip to: 818
/* 297 */     MCD_OPC_Decode, 175, 24, 154, 3, // Opcode: XOR16_NM
/* 302 */     MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 317
/* 307 */     MCD_OPC_CheckPredicate, 112, 250, 1, 0, // Skip to: 818
/* 312 */     MCD_OPC_Decode, 219, 6, 154, 3, // Opcode: AND16_NM
/* 317 */     MCD_OPC_FilterValue, 6, 240, 1, 0, // Skip to: 818
/* 322 */     MCD_OPC_CheckPredicate, 112, 235, 1, 0, // Skip to: 818
/* 327 */     MCD_OPC_Decode, 166, 19, 154, 3, // Opcode: OR16_NM
/* 332 */     MCD_OPC_FilterValue, 1, 225, 1, 0, // Skip to: 818
/* 337 */     MCD_OPC_CheckPredicate, 112, 220, 1, 0, // Skip to: 818
/* 342 */     MCD_OPC_Decode, 174, 16, 155, 3, // Opcode: LWXS16_NM
/* 347 */     MCD_OPC_FilterValue, 21, 10, 0, 0, // Skip to: 362
/* 352 */     MCD_OPC_CheckPredicate, 112, 205, 1, 0, // Skip to: 818
/* 357 */     MCD_OPC_Decode, 146, 16, 156, 3, // Opcode: LWGP16_NM
/* 362 */     MCD_OPC_FilterValue, 23, 48, 0, 0, // Skip to: 415
/* 367 */     MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 370 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 385
/* 375 */     MCD_OPC_CheckPredicate, 112, 182, 1, 0, // Skip to: 818
/* 380 */     MCD_OPC_Decode, 155, 15, 157, 3, // Opcode: LB16_NM
/* 385 */     MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 400
/* 390 */     MCD_OPC_CheckPredicate, 112, 167, 1, 0, // Skip to: 818
/* 395 */     MCD_OPC_Decode, 196, 20, 158, 3, // Opcode: SB16_NM
/* 400 */     MCD_OPC_FilterValue, 2, 157, 1, 0, // Skip to: 818
/* 405 */     MCD_OPC_CheckPredicate, 112, 152, 1, 0, // Skip to: 818
/* 410 */     MCD_OPC_Decode, 161, 15, 157, 3, // Opcode: LBU16_NM
/* 415 */     MCD_OPC_FilterValue, 28, 17, 0, 0, // Skip to: 437
/* 420 */     MCD_OPC_CheckPredicate, 112, 137, 1, 0, // Skip to: 818
/* 425 */     MCD_OPC_CheckField, 6, 1, 1, 130, 1, 0, // Skip to: 818
/* 432 */     MCD_OPC_Decode, 133, 6, 159, 3, // Opcode: ADDIUR1SP_NM
/* 437 */     MCD_OPC_FilterValue, 29, 10, 0, 0, // Skip to: 452
/* 442 */     MCD_OPC_CheckPredicate, 112, 115, 1, 0, // Skip to: 818
/* 447 */     MCD_OPC_Decode, 134, 16, 160, 3, // Opcode: LW4x4_NM
/* 452 */     MCD_OPC_FilterValue, 31, 63, 0, 0, // Skip to: 520
/* 457 */     MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 460 */     MCD_OPC_FilterValue, 0, 33, 0, 0, // Skip to: 498
/* 465 */     MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 468 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 483
/* 473 */     MCD_OPC_CheckPredicate, 112, 84, 1, 0, // Skip to: 818
/* 478 */     MCD_OPC_Decode, 207, 15, 161, 3, // Opcode: LH16_NM
/* 483 */     MCD_OPC_FilterValue, 1, 74, 1, 0, // Skip to: 818
/* 488 */     MCD_OPC_CheckPredicate, 112, 69, 1, 0, // Skip to: 818
/* 493 */     MCD_OPC_Decode, 213, 15, 161, 3, // Opcode: LHU16_NM
/* 498 */     MCD_OPC_FilterValue, 1, 59, 1, 0, // Skip to: 818
/* 503 */     MCD_OPC_CheckPredicate, 112, 54, 1, 0, // Skip to: 818
/* 508 */     MCD_OPC_CheckField, 3, 1, 0, 47, 1, 0, // Skip to: 818
/* 515 */     MCD_OPC_Decode, 146, 21, 162, 3, // Opcode: SH16_NM
/* 520 */     MCD_OPC_FilterValue, 36, 56, 0, 0, // Skip to: 581
/* 525 */     MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 528 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 543
/* 533 */     MCD_OPC_CheckPredicate, 112, 24, 1, 0, // Skip to: 818
/* 538 */     MCD_OPC_Decode, 135, 6, 163, 3, // Opcode: ADDIUR2_NM
/* 543 */     MCD_OPC_FilterValue, 1, 14, 1, 0, // Skip to: 818
/* 548 */     MCD_OPC_CheckPredicate, 112, 18, 0, 0, // Skip to: 571
/* 553 */     MCD_OPC_CheckField, 4, 6, 0, 11, 0, 0, // Skip to: 571
/* 560 */     MCD_OPC_CheckField, 0, 3, 0, 4, 0, 0, // Skip to: 571
/* 567 */     MCD_OPC_Decode, 150, 19, 10, // Opcode: NOP_NM
/* 571 */     MCD_OPC_CheckPredicate, 112, 242, 0, 0, // Skip to: 818
/* 576 */     MCD_OPC_Decode, 136, 6, 164, 3, // Opcode: ADDIURS5_NM
/* 581 */     MCD_OPC_FilterValue, 37, 10, 0, 0, // Skip to: 596
/* 586 */     MCD_OPC_CheckPredicate, 112, 227, 0, 0, // Skip to: 818
/* 591 */     MCD_OPC_Decode, 131, 23, 165, 3, // Opcode: SW16_NM
/* 596 */     MCD_OPC_FilterValue, 38, 10, 0, 0, // Skip to: 611
/* 601 */     MCD_OPC_CheckPredicate, 112, 212, 0, 0, // Skip to: 818
/* 606 */     MCD_OPC_Decode, 203, 7, 166, 3, // Opcode: BEQZC16_NM
/* 611 */     MCD_OPC_FilterValue, 44, 33, 0, 0, // Skip to: 649
/* 616 */     MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 619 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 634
/* 624 */     MCD_OPC_CheckPredicate, 112, 189, 0, 0, // Skip to: 818
/* 629 */     MCD_OPC_Decode, 207, 6, 167, 3, // Opcode: ADDu16_NM
/* 634 */     MCD_OPC_FilterValue, 1, 179, 0, 0, // Skip to: 818
/* 639 */     MCD_OPC_CheckPredicate, 112, 174, 0, 0, // Skip to: 818
/* 644 */     MCD_OPC_Decode, 250, 22, 167, 3, // Opcode: SUBu16_NM
/* 649 */     MCD_OPC_FilterValue, 45, 10, 0, 0, // Skip to: 664
/* 654 */     MCD_OPC_CheckPredicate, 112, 159, 0, 0, // Skip to: 818
/* 659 */     MCD_OPC_Decode, 162, 23, 151, 3, // Opcode: SWSP16_NM
/* 664 */     MCD_OPC_FilterValue, 46, 10, 0, 0, // Skip to: 679
/* 669 */     MCD_OPC_CheckPredicate, 112, 144, 0, 0, // Skip to: 818
/* 674 */     MCD_OPC_Decode, 193, 8, 166, 3, // Opcode: BNEZC16_NM
/* 679 */     MCD_OPC_FilterValue, 47, 10, 0, 0, // Skip to: 694
/* 684 */     MCD_OPC_CheckPredicate, 112, 129, 0, 0, // Skip to: 818
/* 689 */     MCD_OPC_Decode, 214, 17, 168, 3, // Opcode: MOVEP_NM
/* 694 */     MCD_OPC_FilterValue, 52, 10, 0, 0, // Skip to: 709
/* 699 */     MCD_OPC_CheckPredicate, 112, 114, 0, 0, // Skip to: 818
/* 704 */     MCD_OPC_Decode, 233, 15, 169, 3, // Opcode: LI16_NM
/* 709 */     MCD_OPC_FilterValue, 53, 10, 0, 0, // Skip to: 724
/* 714 */     MCD_OPC_CheckPredicate, 112, 99, 0, 0, // Skip to: 818
/* 719 */     MCD_OPC_Decode, 144, 23, 170, 3, // Opcode: SWGP16_NM
/* 724 */     MCD_OPC_FilterValue, 54, 44, 0, 0, // Skip to: 773
/* 729 */     MCD_OPC_CheckPredicate, 112, 12, 0, 0, // Skip to: 746
/* 734 */     MCD_OPC_CheckField, 0, 5, 0, 5, 0, 0, // Skip to: 746
/* 741 */     MCD_OPC_Decode, 139, 15, 171, 3, // Opcode: JRC_NM
/* 746 */     MCD_OPC_CheckPredicate, 112, 12, 0, 0, // Skip to: 763
/* 751 */     MCD_OPC_CheckField, 0, 4, 0, 5, 0, 0, // Skip to: 763
/* 758 */     MCD_OPC_Decode, 240, 14, 172, 3, // Opcode: JALRC16_NM
/* 763 */     MCD_OPC_CheckPredicate, 112, 50, 0, 0, // Skip to: 818
/* 768 */     MCD_OPC_Decode, 191, 7, 173, 3, // Opcode: BEQC16_NM
/* 773 */     MCD_OPC_FilterValue, 60, 10, 0, 0, // Skip to: 788
/* 778 */     MCD_OPC_CheckPredicate, 112, 35, 0, 0, // Skip to: 818
/* 783 */     MCD_OPC_Decode, 223, 6, 174, 3, // Opcode: ANDI16_NM
/* 788 */     MCD_OPC_FilterValue, 61, 10, 0, 0, // Skip to: 803
/* 793 */     MCD_OPC_CheckPredicate, 112, 20, 0, 0, // Skip to: 818
/* 798 */     MCD_OPC_Decode, 132, 23, 175, 3, // Opcode: SW4x4_NM
/* 803 */     MCD_OPC_FilterValue, 63, 10, 0, 0, // Skip to: 818
/* 808 */     MCD_OPC_CheckPredicate, 112, 5, 0, 0, // Skip to: 818
/* 813 */     MCD_OPC_Decode, 211, 17, 176, 3, // Opcode: MOVEPREV_NM
/* 818 */     MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableNanoMips32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 75, 0, 0, // Skip to: 83
/* 8 */       MCD_OPC_CheckPredicate, 112, 12, 0, 0, // Skip to: 25
/* 13 */      MCD_OPC_CheckField, 18, 8, 2, 5, 0, 0, // Skip to: 25
/* 20 */      MCD_OPC_Decode, 185, 23, 177, 3, // Opcode: SYSCALL_NM
/* 25 */      MCD_OPC_ExtractField, 19, 7,  // Inst{25-19} ...
/* 28 */      MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 43
/* 33 */      MCD_OPC_CheckPredicate, 112, 35, 0, 0, // Skip to: 73
/* 38 */      MCD_OPC_Decode, 210, 21, 178, 3, // Opcode: SIGRIE_NM
/* 43 */      MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 58
/* 48 */      MCD_OPC_CheckPredicate, 112, 20, 0, 0, // Skip to: 73
/* 53 */      MCD_OPC_Decode, 217, 8, 178, 3, // Opcode: BREAK_NM
/* 58 */      MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 73
/* 63 */      MCD_OPC_CheckPredicate, 112, 5, 0, 0, // Skip to: 73
/* 68 */      MCD_OPC_Decode, 225, 20, 178, 3, // Opcode: SDBBP_NM
/* 73 */      MCD_OPC_CheckPredicate, 112, 165, 12, 0, // Skip to: 3315
/* 78 */      MCD_OPC_Decode, 140, 6, 179, 3, // Opcode: ADDIU_NM
/* 83 */      MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 98
/* 88 */      MCD_OPC_CheckPredicate, 112, 150, 12, 0, // Skip to: 3315
/* 93 */      MCD_OPC_Decode, 152, 15, 180, 3, // Opcode: LAPC32_NM
/* 98 */      MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 113
/* 103 */     MCD_OPC_CheckPredicate, 112, 135, 12, 0, // Skip to: 3315
/* 108 */     MCD_OPC_Decode, 210, 17, 181, 3, // Opcode: MOVEBALC_NM
/* 113 */     MCD_OPC_FilterValue, 8, 55, 6, 0, // Skip to: 1709
/* 118 */     MCD_OPC_ExtractField, 4, 2,  // Inst{5-4} ...
/* 121 */     MCD_OPC_FilterValue, 0, 64, 1, 0, // Skip to: 446
/* 126 */     MCD_OPC_ExtractField, 0, 4,  // Inst{3-0} ...
/* 129 */     MCD_OPC_FilterValue, 0, 56, 0, 0, // Skip to: 190
/* 134 */     MCD_OPC_ExtractField, 6, 4,  // Inst{9-6} ...
/* 137 */     MCD_OPC_FilterValue, 0, 33, 0, 0, // Skip to: 175
/* 142 */     MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 145 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 160
/* 150 */     MCD_OPC_CheckPredicate, 112, 88, 12, 0, // Skip to: 3315
/* 155 */     MCD_OPC_Decode, 211, 23, 182, 3, // Opcode: TEQ_NM
/* 160 */     MCD_OPC_FilterValue, 1, 78, 12, 0, // Skip to: 3315
/* 165 */     MCD_OPC_CheckPredicate, 112, 73, 12, 0, // Skip to: 3315
/* 170 */     MCD_OPC_Decode, 133, 24, 182, 3, // Opcode: TNE_NM
/* 175 */     MCD_OPC_FilterValue, 7, 63, 12, 0, // Skip to: 3315
/* 180 */     MCD_OPC_CheckPredicate, 112, 58, 12, 0, // Skip to: 3315
/* 185 */     MCD_OPC_Decode, 131, 20, 183, 3, // Opcode: RDHWR_NM
/* 190 */     MCD_OPC_FilterValue, 7, 198, 0, 0, // Skip to: 393
/* 195 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 198 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 213
/* 203 */     MCD_OPC_CheckPredicate, 112, 35, 12, 0, // Skip to: 3315
/* 208 */     MCD_OPC_Decode, 169, 15, 184, 3, // Opcode: LBX_NM
/* 213 */     MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 228
/* 218 */     MCD_OPC_CheckPredicate, 112, 20, 12, 0, // Skip to: 3315
/* 223 */     MCD_OPC_Decode, 201, 20, 184, 3, // Opcode: SBX_NM
/* 228 */     MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 243
/* 233 */     MCD_OPC_CheckPredicate, 112, 5, 12, 0, // Skip to: 3315
/* 238 */     MCD_OPC_Decode, 165, 15, 184, 3, // Opcode: LBUX_NM
/* 243 */     MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 258
/* 248 */     MCD_OPC_CheckPredicate, 112, 246, 11, 0, // Skip to: 3315
/* 253 */     MCD_OPC_Decode, 222, 15, 184, 3, // Opcode: LHX_NM
/* 258 */     MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 273
/* 263 */     MCD_OPC_CheckPredicate, 112, 231, 11, 0, // Skip to: 3315
/* 268 */     MCD_OPC_Decode, 220, 15, 184, 3, // Opcode: LHXS_NM
/* 273 */     MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 288
/* 278 */     MCD_OPC_CheckPredicate, 112, 216, 11, 0, // Skip to: 3315
/* 283 */     MCD_OPC_Decode, 203, 21, 184, 3, // Opcode: SHX_NM
/* 288 */     MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 303
/* 293 */     MCD_OPC_CheckPredicate, 112, 201, 11, 0, // Skip to: 3315
/* 298 */     MCD_OPC_Decode, 202, 21, 184, 3, // Opcode: SHXS_NM
/* 303 */     MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 318
/* 308 */     MCD_OPC_CheckPredicate, 112, 186, 11, 0, // Skip to: 3315
/* 313 */     MCD_OPC_Decode, 216, 15, 184, 3, // Opcode: LHUX_NM
/* 318 */     MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 333
/* 323 */     MCD_OPC_CheckPredicate, 112, 171, 11, 0, // Skip to: 3315
/* 328 */     MCD_OPC_Decode, 215, 15, 184, 3, // Opcode: LHUXS_NM
/* 333 */     MCD_OPC_FilterValue, 16, 10, 0, 0, // Skip to: 348
/* 338 */     MCD_OPC_CheckPredicate, 112, 156, 11, 0, // Skip to: 3315
/* 343 */     MCD_OPC_Decode, 178, 16, 184, 3, // Opcode: LWX_NM
/* 348 */     MCD_OPC_FilterValue, 17, 10, 0, 0, // Skip to: 363
/* 353 */     MCD_OPC_CheckPredicate, 112, 141, 11, 0, // Skip to: 3315
/* 358 */     MCD_OPC_Decode, 176, 16, 184, 3, // Opcode: LWXS_NM
/* 363 */     MCD_OPC_FilterValue, 18, 10, 0, 0, // Skip to: 378
/* 368 */     MCD_OPC_CheckPredicate, 112, 126, 11, 0, // Skip to: 3315
/* 373 */     MCD_OPC_Decode, 168, 23, 184, 3, // Opcode: SWX_NM
/* 378 */     MCD_OPC_FilterValue, 19, 116, 11, 0, // Skip to: 3315
/* 383 */     MCD_OPC_CheckPredicate, 112, 111, 11, 0, // Skip to: 3315
/* 388 */     MCD_OPC_Decode, 167, 23, 184, 3, // Opcode: SWXS_NM
/* 393 */     MCD_OPC_FilterValue, 8, 33, 0, 0, // Skip to: 431
/* 398 */     MCD_OPC_ExtractField, 6, 4,  // Inst{9-6} ...
/* 401 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 416
/* 406 */     MCD_OPC_CheckPredicate, 112, 88, 11, 0, // Skip to: 3315
/* 411 */     MCD_OPC_Decode, 245, 20, 185, 3, // Opcode: SEB_NM
/* 416 */     MCD_OPC_FilterValue, 1, 78, 11, 0, // Skip to: 3315
/* 421 */     MCD_OPC_CheckPredicate, 112, 73, 11, 0, // Skip to: 3315
/* 426 */     MCD_OPC_Decode, 249, 20, 185, 3, // Opcode: SEH_NM
/* 431 */     MCD_OPC_FilterValue, 15, 63, 11, 0, // Skip to: 3315
/* 436 */     MCD_OPC_CheckPredicate, 112, 58, 11, 0, // Skip to: 3315
/* 441 */     MCD_OPC_Decode, 249, 15, 186, 3, // Opcode: LSA_NM
/* 446 */     MCD_OPC_FilterValue, 1, 161, 1, 0, // Skip to: 868
/* 451 */     MCD_OPC_ExtractField, 0, 4,  // Inst{3-0} ...
/* 454 */     MCD_OPC_FilterValue, 0, 10, 1, 0, // Skip to: 725
/* 459 */     MCD_OPC_ExtractField, 6, 4,  // Inst{9-6} ...
/* 462 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 477
/* 467 */     MCD_OPC_CheckPredicate, 112, 27, 11, 0, // Skip to: 3315
/* 472 */     MCD_OPC_Decode, 231, 21, 187, 3, // Opcode: SLLV_NM
/* 477 */     MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 492
/* 482 */     MCD_OPC_CheckPredicate, 112, 12, 11, 0, // Skip to: 3315
/* 487 */     MCD_OPC_Decode, 178, 22, 187, 3, // Opcode: SRLV_NM
/* 492 */     MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 507
/* 497 */     MCD_OPC_CheckPredicate, 112, 253, 10, 0, // Skip to: 3315
/* 502 */     MCD_OPC_Decode, 153, 22, 187, 3, // Opcode: SRAV_NM
/* 507 */     MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 522
/* 512 */     MCD_OPC_CheckPredicate, 112, 238, 10, 0, // Skip to: 3315
/* 517 */     MCD_OPC_Decode, 158, 20, 187, 3, // Opcode: ROTRV_NM
/* 522 */     MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 537
/* 527 */     MCD_OPC_CheckPredicate, 112, 223, 10, 0, // Skip to: 3315
/* 532 */     MCD_OPC_Decode, 201, 6, 187, 3, // Opcode: ADD_NM
/* 537 */     MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 552
/* 542 */     MCD_OPC_CheckPredicate, 112, 208, 10, 0, // Skip to: 3315
/* 547 */     MCD_OPC_Decode, 210, 6, 187, 3, // Opcode: ADDu_NM
/* 552 */     MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 567
/* 557 */     MCD_OPC_CheckPredicate, 112, 193, 10, 0, // Skip to: 3315
/* 562 */     MCD_OPC_Decode, 248, 22, 187, 3, // Opcode: SUB_NM
/* 567 */     MCD_OPC_FilterValue, 7, 10, 0, 0, // Skip to: 582
/* 572 */     MCD_OPC_CheckPredicate, 112, 178, 10, 0, // Skip to: 3315
/* 577 */     MCD_OPC_Decode, 252, 22, 187, 3, // Opcode: SUBu_NM
/* 582 */     MCD_OPC_FilterValue, 8, 33, 0, 0, // Skip to: 620
/* 587 */     MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 590 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 605
/* 595 */     MCD_OPC_CheckPredicate, 112, 155, 10, 0, // Skip to: 3315
/* 600 */     MCD_OPC_Decode, 130, 18, 188, 3, // Opcode: MOVZ_NM
/* 605 */     MCD_OPC_FilterValue, 1, 145, 10, 0, // Skip to: 3315
/* 610 */     MCD_OPC_CheckPredicate, 112, 140, 10, 0, // Skip to: 3315
/* 615 */     MCD_OPC_Decode, 237, 17, 188, 3, // Opcode: MOVN_NM
/* 620 */     MCD_OPC_FilterValue, 9, 10, 0, 0, // Skip to: 635
/* 625 */     MCD_OPC_CheckPredicate, 112, 125, 10, 0, // Skip to: 3315
/* 630 */     MCD_OPC_Decode, 229, 6, 187, 3, // Opcode: AND_NM
/* 635 */     MCD_OPC_FilterValue, 10, 10, 0, 0, // Skip to: 650
/* 640 */     MCD_OPC_CheckPredicate, 112, 110, 10, 0, // Skip to: 3315
/* 645 */     MCD_OPC_Decode, 173, 19, 187, 3, // Opcode: OR_NM
/* 650 */     MCD_OPC_FilterValue, 11, 10, 0, 0, // Skip to: 665
/* 655 */     MCD_OPC_CheckPredicate, 112, 95, 10, 0, // Skip to: 3315
/* 660 */     MCD_OPC_Decode, 156, 19, 187, 3, // Opcode: NOR_NM
/* 665 */     MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 680
/* 670 */     MCD_OPC_CheckPredicate, 112, 80, 10, 0, // Skip to: 3315
/* 675 */     MCD_OPC_Decode, 182, 24, 187, 3, // Opcode: XOR_NM
/* 680 */     MCD_OPC_FilterValue, 13, 10, 0, 0, // Skip to: 695
/* 685 */     MCD_OPC_CheckPredicate, 112, 65, 10, 0, // Skip to: 3315
/* 690 */     MCD_OPC_Decode, 245, 21, 187, 3, // Opcode: SLT_NM
/* 695 */     MCD_OPC_FilterValue, 14, 10, 0, 0, // Skip to: 710
/* 700 */     MCD_OPC_CheckPredicate, 112, 50, 10, 0, // Skip to: 3315
/* 705 */     MCD_OPC_Decode, 243, 21, 187, 3, // Opcode: SLTU_NM
/* 710 */     MCD_OPC_FilterValue, 15, 40, 10, 0, // Skip to: 3315
/* 715 */     MCD_OPC_CheckPredicate, 112, 35, 10, 0, // Skip to: 3315
/* 720 */     MCD_OPC_Decode, 129, 22, 187, 3, // Opcode: SOV_NM
/* 725 */     MCD_OPC_FilterValue, 8, 123, 0, 0, // Skip to: 853
/* 730 */     MCD_OPC_ExtractField, 6, 4,  // Inst{9-6} ...
/* 733 */     MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 748
/* 738 */     MCD_OPC_CheckPredicate, 112, 12, 10, 0, // Skip to: 3315
/* 743 */     MCD_OPC_Decode, 247, 18, 187, 3, // Opcode: MUL_NM
/* 748 */     MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 763
/* 753 */     MCD_OPC_CheckPredicate, 112, 253, 9, 0, // Skip to: 3315
/* 758 */     MCD_OPC_Decode, 204, 18, 187, 3, // Opcode: MUH_NM
/* 763 */     MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 778
/* 768 */     MCD_OPC_CheckPredicate, 112, 238, 9, 0, // Skip to: 3315
/* 773 */     MCD_OPC_Decode, 240, 18, 187, 3, // Opcode: MULU_NM
/* 778 */     MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 793
/* 783 */     MCD_OPC_CheckPredicate, 112, 223, 9, 0, // Skip to: 3315
/* 788 */     MCD_OPC_Decode, 202, 18, 187, 3, // Opcode: MUHU_NM
/* 793 */     MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 808
/* 798 */     MCD_OPC_CheckPredicate, 112, 208, 9, 0, // Skip to: 3315
/* 803 */     MCD_OPC_Decode, 223, 11, 187, 3, // Opcode: DIV_NM
/* 808 */     MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 823
/* 813 */     MCD_OPC_CheckPredicate, 112, 193, 9, 0, // Skip to: 3315
/* 818 */     MCD_OPC_Decode, 199, 17, 187, 3, // Opcode: MOD_NM
/* 823 */     MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 838
/* 828 */     MCD_OPC_CheckPredicate, 112, 178, 9, 0, // Skip to: 3315
/* 833 */     MCD_OPC_Decode, 221, 11, 187, 3, // Opcode: DIVU_NM
/* 838 */     MCD_OPC_FilterValue, 7, 168, 9, 0, // Skip to: 3315
/* 843 */     MCD_OPC_CheckPredicate, 112, 163, 9, 0, // Skip to: 3315
/* 848 */     MCD_OPC_Decode, 197, 17, 187, 3, // Opcode: MODU_NM
/* 853 */     MCD_OPC_FilterValue, 15, 153, 9, 0, // Skip to: 3315
/* 858 */     MCD_OPC_CheckPredicate, 112, 148, 9, 0, // Skip to: 3315
/* 863 */     MCD_OPC_Decode, 254, 12, 189, 3, // Opcode: EXTW_NM
/* 868 */     MCD_OPC_FilterValue, 2, 194, 0, 0, // Skip to: 1067
/* 873 */     MCD_OPC_ExtractField, 6, 4,  // Inst{9-6} ...
/* 876 */     MCD_OPC_FilterValue, 8, 17, 0, 0, // Skip to: 898
/* 881 */     MCD_OPC_CheckPredicate, 113, 125, 9, 0, // Skip to: 3315
/* 886 */     MCD_OPC_CheckField, 0, 4, 8, 118, 9, 0, // Skip to: 3315
/* 893 */     MCD_OPC_Decode, 255, 13, 190, 3, // Opcode: FORK_NM
/* 898 */     MCD_OPC_FilterValue, 9, 24, 0, 0, // Skip to: 927
/* 903 */     MCD_OPC_CheckPredicate, 113, 103, 9, 0, // Skip to: 3315
/* 908 */     MCD_OPC_CheckField, 10, 6, 0, 96, 9, 0, // Skip to: 3315
/* 915 */     MCD_OPC_CheckField, 0, 4, 8, 89, 9, 0, // Skip to: 3315
/* 922 */     MCD_OPC_Decode, 189, 24, 185, 3, // Opcode: YIELD_NM
/* 927 */     MCD_OPC_FilterValue, 15, 79, 9, 0, // Skip to: 3315
/* 932 */     MCD_OPC_ExtractField, 10, 3,  // Inst{12-10} ...
/* 935 */     MCD_OPC_FilterValue, 0, 17, 0, 0, // Skip to: 957
/* 940 */     MCD_OPC_CheckPredicate, 114, 66, 9, 0, // Skip to: 3315
/* 945 */     MCD_OPC_CheckField, 0, 4, 8, 59, 9, 0, // Skip to: 3315
/* 952 */     MCD_OPC_Decode, 166, 10, 191, 3, // Opcode: CRC32B_NM
/* 957 */     MCD_OPC_FilterValue, 1, 17, 0, 0, // Skip to: 979
/* 962 */     MCD_OPC_CheckPredicate, 114, 44, 9, 0, // Skip to: 3315
/* 967 */     MCD_OPC_CheckField, 0, 4, 8, 37, 9, 0, // Skip to: 3315
/* 974 */     MCD_OPC_Decode, 176, 10, 191, 3, // Opcode: CRC32H_NM
/* 979 */     MCD_OPC_FilterValue, 2, 17, 0, 0, // Skip to: 1001
/* 984 */     MCD_OPC_CheckPredicate, 114, 22, 9, 0, // Skip to: 3315
/* 989 */     MCD_OPC_CheckField, 0, 4, 8, 15, 9, 0, // Skip to: 3315
/* 996 */     MCD_OPC_Decode, 178, 10, 191, 3, // Opcode: CRC32W_NM
/* 1001 */    MCD_OPC_FilterValue, 4, 17, 0, 0, // Skip to: 1023
/* 1006 */    MCD_OPC_CheckPredicate, 114, 0, 9, 0, // Skip to: 3315
/* 1011 */    MCD_OPC_CheckField, 0, 4, 8, 249, 8, 0, // Skip to: 3315
/* 1018 */    MCD_OPC_Decode, 168, 10, 191, 3, // Opcode: CRC32CB_NM
/* 1023 */    MCD_OPC_FilterValue, 5, 17, 0, 0, // Skip to: 1045
/* 1028 */    MCD_OPC_CheckPredicate, 114, 234, 8, 0, // Skip to: 3315
/* 1033 */    MCD_OPC_CheckField, 0, 4, 8, 227, 8, 0, // Skip to: 3315
/* 1040 */    MCD_OPC_Decode, 171, 10, 191, 3, // Opcode: CRC32CH_NM
/* 1045 */    MCD_OPC_FilterValue, 6, 217, 8, 0, // Skip to: 3315
/* 1050 */    MCD_OPC_CheckPredicate, 114, 212, 8, 0, // Skip to: 3315
/* 1055 */    MCD_OPC_CheckField, 0, 4, 8, 205, 8, 0, // Skip to: 3315
/* 1062 */    MCD_OPC_Decode, 173, 10, 191, 3, // Opcode: CRC32CW_NM
/* 1067 */    MCD_OPC_FilterValue, 3, 195, 8, 0, // Skip to: 3315
/* 1072 */    MCD_OPC_ExtractField, 6, 4,  // Inst{9-6} ...
/* 1075 */    MCD_OPC_FilterValue, 0, 33, 0, 0, // Skip to: 1113
/* 1080 */    MCD_OPC_ExtractField, 0, 4,  // Inst{3-0} ...
/* 1083 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 1098
/* 1088 */    MCD_OPC_CheckPredicate, 112, 174, 8, 0, // Skip to: 3315
/* 1093 */    MCD_OPC_Decode, 129, 17, 192, 3, // Opcode: MFC0Sel_NM
/* 1098 */    MCD_OPC_FilterValue, 8, 164, 8, 0, // Skip to: 3315
/* 1103 */    MCD_OPC_CheckPredicate, 112, 159, 8, 0, // Skip to: 3315
/* 1108 */    MCD_OPC_Decode, 140, 17, 192, 3, // Opcode: MFHC0Sel_NM
/* 1113 */    MCD_OPC_FilterValue, 1, 33, 0, 0, // Skip to: 1151
/* 1118 */    MCD_OPC_ExtractField, 0, 4,  // Inst{3-0} ...
/* 1121 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 1136
/* 1126 */    MCD_OPC_CheckPredicate, 112, 136, 8, 0, // Skip to: 3315
/* 1131 */    MCD_OPC_Decode, 157, 18, 192, 3, // Opcode: MTC0Sel_NM
/* 1136 */    MCD_OPC_FilterValue, 8, 126, 8, 0, // Skip to: 3315
/* 1141 */    MCD_OPC_CheckPredicate, 112, 121, 8, 0, // Skip to: 3315
/* 1146 */    MCD_OPC_Decode, 169, 18, 192, 3, // Opcode: MTHC0Sel_NM
/* 1151 */    MCD_OPC_FilterValue, 5, 47, 0, 0, // Skip to: 1203
/* 1156 */    MCD_OPC_ExtractField, 10, 6,  // Inst{15-10} ...
/* 1159 */    MCD_OPC_FilterValue, 56, 17, 0, 0, // Skip to: 1181
/* 1164 */    MCD_OPC_CheckPredicate, 112, 98, 8, 0, // Skip to: 3315
/* 1169 */    MCD_OPC_CheckField, 0, 4, 15, 91, 8, 0, // Skip to: 3315
/* 1176 */    MCD_OPC_Decode, 133, 20, 185, 3, // Opcode: RDPGPR_NM
/* 1181 */    MCD_OPC_FilterValue, 60, 81, 8, 0, // Skip to: 3315
/* 1186 */    MCD_OPC_CheckPredicate, 112, 76, 8, 0, // Skip to: 3315
/* 1191 */    MCD_OPC_CheckField, 0, 4, 15, 69, 8, 0, // Skip to: 3315
/* 1198 */    MCD_OPC_Decode, 168, 24, 185, 3, // Opcode: WRPGPR_NM
/* 1203 */    MCD_OPC_FilterValue, 8, 17, 0, 0, // Skip to: 1225
/* 1208 */    MCD_OPC_CheckPredicate, 113, 54, 8, 0, // Skip to: 3315
/* 1213 */    MCD_OPC_CheckField, 0, 3, 0, 47, 8, 0, // Skip to: 3315
/* 1220 */    MCD_OPC_Decode, 163, 17, 193, 3, // Opcode: MFTR_NM
/* 1225 */    MCD_OPC_FilterValue, 9, 17, 0, 0, // Skip to: 1247
/* 1230 */    MCD_OPC_CheckPredicate, 113, 32, 8, 0, // Skip to: 3315
/* 1235 */    MCD_OPC_CheckField, 0, 3, 0, 25, 8, 0, // Skip to: 3315
/* 1242 */    MCD_OPC_Decode, 198, 18, 194, 3, // Opcode: MTTR_NM
/* 1247 */    MCD_OPC_FilterValue, 10, 91, 0, 0, // Skip to: 1343
/* 1252 */    MCD_OPC_ExtractField, 10, 11,  // Inst{20-10} ...
/* 1255 */    MCD_OPC_FilterValue, 2, 17, 0, 0, // Skip to: 1277
/* 1260 */    MCD_OPC_CheckPredicate, 113, 2, 8, 0, // Skip to: 3315
/* 1265 */    MCD_OPC_CheckField, 0, 4, 0, 251, 7, 0, // Skip to: 3315
/* 1272 */    MCD_OPC_Decode, 202, 12, 195, 3, // Opcode: DVPE_NM
/* 1277 */    MCD_OPC_FilterValue, 3, 17, 0, 0, // Skip to: 1299
/* 1282 */    MCD_OPC_CheckPredicate, 113, 236, 7, 0, // Skip to: 3315
/* 1287 */    MCD_OPC_CheckField, 0, 4, 0, 229, 7, 0, // Skip to: 3315
/* 1294 */    MCD_OPC_Decode, 225, 12, 195, 3, // Opcode: EVPE_NM
/* 1299 */    MCD_OPC_FilterValue, 66, 17, 0, 0, // Skip to: 1321
/* 1304 */    MCD_OPC_CheckPredicate, 113, 214, 7, 0, // Skip to: 3315
/* 1309 */    MCD_OPC_CheckField, 0, 4, 0, 207, 7, 0, // Skip to: 3315
/* 1316 */    MCD_OPC_Decode, 250, 11, 195, 3, // Opcode: DMT_NM
/* 1321 */    MCD_OPC_FilterValue, 67, 197, 7, 0, // Skip to: 3315
/* 1326 */    MCD_OPC_CheckPredicate, 113, 192, 7, 0, // Skip to: 3315
/* 1331 */    MCD_OPC_CheckField, 0, 4, 0, 185, 7, 0, // Skip to: 3315
/* 1338 */    MCD_OPC_Decode, 215, 12, 195, 3, // Opcode: EMT_NM
/* 1343 */    MCD_OPC_FilterValue, 12, 47, 0, 0, // Skip to: 1395
/* 1348 */    MCD_OPC_ExtractField, 10, 6,  // Inst{15-10} ...
/* 1351 */    MCD_OPC_FilterValue, 18, 17, 0, 0, // Skip to: 1373
/* 1356 */    MCD_OPC_CheckPredicate, 112, 162, 7, 0, // Skip to: 3315
/* 1361 */    MCD_OPC_CheckField, 0, 4, 15, 155, 7, 0, // Skip to: 3315
/* 1368 */    MCD_OPC_Decode, 175, 9, 185, 3, // Opcode: CLO_NM
/* 1373 */    MCD_OPC_FilterValue, 22, 145, 7, 0, // Skip to: 3315
/* 1378 */    MCD_OPC_CheckPredicate, 112, 140, 7, 0, // Skip to: 3315
/* 1383 */    MCD_OPC_CheckField, 0, 4, 15, 133, 7, 0, // Skip to: 3315
/* 1390 */    MCD_OPC_Decode, 196, 9, 185, 3, // Opcode: CLZ_NM
/* 1395 */    MCD_OPC_FilterValue, 13, 123, 7, 0, // Skip to: 3315
/* 1400 */    MCD_OPC_ExtractField, 10, 6,  // Inst{15-10} ...
/* 1403 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 1424
/* 1408 */    MCD_OPC_CheckPredicate, 115, 110, 7, 0, // Skip to: 3315
/* 1413 */    MCD_OPC_CheckField, 0, 4, 15, 103, 7, 0, // Skip to: 3315
/* 1420 */    MCD_OPC_Decode, 240, 23, 10, // Opcode: TLBP_NM
/* 1424 */    MCD_OPC_FilterValue, 1, 16, 0, 0, // Skip to: 1445
/* 1429 */    MCD_OPC_CheckPredicate, 115, 89, 7, 0, // Skip to: 3315
/* 1434 */    MCD_OPC_CheckField, 0, 4, 15, 82, 7, 0, // Skip to: 3315
/* 1441 */    MCD_OPC_Decode, 237, 23, 10, // Opcode: TLBINV_NM
/* 1445 */    MCD_OPC_FilterValue, 3, 17, 0, 0, // Skip to: 1467
/* 1450 */    MCD_OPC_CheckPredicate, 116, 68, 7, 0, // Skip to: 3315
/* 1455 */    MCD_OPC_CheckField, 0, 4, 15, 61, 7, 0, // Skip to: 3315
/* 1462 */    MCD_OPC_Decode, 189, 14, 196, 3, // Opcode: GINVT_NM
/* 1467 */    MCD_OPC_FilterValue, 4, 16, 0, 0, // Skip to: 1488
/* 1472 */    MCD_OPC_CheckPredicate, 115, 46, 7, 0, // Skip to: 3315
/* 1477 */    MCD_OPC_CheckField, 0, 4, 15, 39, 7, 0, // Skip to: 3315
/* 1484 */    MCD_OPC_Decode, 243, 23, 10, // Opcode: TLBR_NM
/* 1488 */    MCD_OPC_FilterValue, 5, 16, 0, 0, // Skip to: 1509
/* 1493 */    MCD_OPC_CheckPredicate, 115, 25, 7, 0, // Skip to: 3315
/* 1498 */    MCD_OPC_CheckField, 0, 4, 15, 18, 7, 0, // Skip to: 3315
/* 1505 */    MCD_OPC_Decode, 235, 23, 10, // Opcode: TLBINVF_NM
/* 1509 */    MCD_OPC_FilterValue, 7, 17, 0, 0, // Skip to: 1531
/* 1514 */    MCD_OPC_CheckPredicate, 116, 4, 7, 0, // Skip to: 3315
/* 1519 */    MCD_OPC_CheckField, 0, 4, 15, 253, 6, 0, // Skip to: 3315
/* 1526 */    MCD_OPC_Decode, 186, 14, 197, 3, // Opcode: GINVI_NM
/* 1531 */    MCD_OPC_FilterValue, 8, 16, 0, 0, // Skip to: 1552
/* 1536 */    MCD_OPC_CheckPredicate, 115, 238, 6, 0, // Skip to: 3315
/* 1541 */    MCD_OPC_CheckField, 0, 4, 15, 231, 6, 0, // Skip to: 3315
/* 1548 */    MCD_OPC_Decode, 246, 23, 10, // Opcode: TLBWI_NM
/* 1552 */    MCD_OPC_FilterValue, 12, 16, 0, 0, // Skip to: 1573
/* 1557 */    MCD_OPC_CheckPredicate, 115, 217, 6, 0, // Skip to: 3315
/* 1562 */    MCD_OPC_CheckField, 0, 4, 15, 210, 6, 0, // Skip to: 3315
/* 1569 */    MCD_OPC_Decode, 249, 23, 10, // Opcode: TLBWR_NM
/* 1573 */    MCD_OPC_FilterValue, 17, 17, 0, 0, // Skip to: 1595
/* 1578 */    MCD_OPC_CheckPredicate, 112, 196, 6, 0, // Skip to: 3315
/* 1583 */    MCD_OPC_CheckField, 0, 4, 15, 189, 6, 0, // Skip to: 3315
/* 1590 */    MCD_OPC_Decode, 234, 11, 195, 3, // Opcode: DI_NM
/* 1595 */    MCD_OPC_FilterValue, 21, 17, 0, 0, // Skip to: 1617
/* 1600 */    MCD_OPC_CheckPredicate, 112, 174, 6, 0, // Skip to: 3315
/* 1605 */    MCD_OPC_CheckField, 0, 4, 15, 167, 6, 0, // Skip to: 3315
/* 1612 */    MCD_OPC_Decode, 213, 12, 195, 3, // Opcode: EI_NM
/* 1617 */    MCD_OPC_FilterValue, 48, 16, 0, 0, // Skip to: 1638
/* 1622 */    MCD_OPC_CheckPredicate, 112, 152, 6, 0, // Skip to: 3315
/* 1627 */    MCD_OPC_CheckField, 0, 4, 15, 145, 6, 0, // Skip to: 3315
/* 1634 */    MCD_OPC_Decode, 164, 24, 88, // Opcode: WAIT_NM
/* 1638 */    MCD_OPC_FilterValue, 56, 16, 0, 0, // Skip to: 1659
/* 1643 */    MCD_OPC_CheckPredicate, 112, 131, 6, 0, // Skip to: 3315
/* 1648 */    MCD_OPC_CheckField, 0, 4, 15, 124, 6, 0, // Skip to: 3315
/* 1655 */    MCD_OPC_Decode, 209, 11, 10, // Opcode: DERET_NM
/* 1659 */    MCD_OPC_FilterValue, 60, 115, 6, 0, // Skip to: 3315
/* 1664 */    MCD_OPC_ExtractField, 16, 1,  // Inst{16} ...
/* 1667 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 1688
/* 1672 */    MCD_OPC_CheckPredicate, 112, 102, 6, 0, // Skip to: 3315
/* 1677 */    MCD_OPC_CheckField, 0, 4, 15, 95, 6, 0, // Skip to: 3315
/* 1684 */    MCD_OPC_Decode, 222, 12, 10, // Opcode: ERET_NM
/* 1688 */    MCD_OPC_FilterValue, 1, 86, 6, 0, // Skip to: 3315
/* 1693 */    MCD_OPC_CheckPredicate, 112, 81, 6, 0, // Skip to: 3315
/* 1698 */    MCD_OPC_CheckField, 0, 4, 15, 74, 6, 0, // Skip to: 3315
/* 1705 */    MCD_OPC_Decode, 219, 12, 10, // Opcode: ERETNC_NM
/* 1709 */    MCD_OPC_FilterValue, 10, 33, 0, 0, // Skip to: 1747
/* 1714 */    MCD_OPC_ExtractField, 25, 1,  // Inst{25} ...
/* 1717 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 1732
/* 1722 */    MCD_OPC_CheckPredicate, 112, 52, 6, 0, // Skip to: 3315
/* 1727 */    MCD_OPC_Decode, 187, 7, 198, 3, // Opcode: BC_NM
/* 1732 */    MCD_OPC_FilterValue, 1, 42, 6, 0, // Skip to: 3315
/* 1737 */    MCD_OPC_CheckPredicate, 112, 37, 6, 0, // Skip to: 3315
/* 1742 */    MCD_OPC_Decode, 151, 7, 198, 3, // Opcode: BALC_NM
/* 1747 */    MCD_OPC_FilterValue, 16, 48, 0, 0, // Skip to: 1800
/* 1752 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 1755 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 1770
/* 1760 */    MCD_OPC_CheckPredicate, 112, 14, 6, 0, // Skip to: 3315
/* 1765 */    MCD_OPC_Decode, 255, 5, 199, 3, // Opcode: ADDIUGPW_NM
/* 1770 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 1785
/* 1775 */    MCD_OPC_CheckPredicate, 112, 255, 5, 0, // Skip to: 3315
/* 1780 */    MCD_OPC_Decode, 148, 16, 200, 3, // Opcode: LWGP_NM
/* 1785 */    MCD_OPC_FilterValue, 3, 245, 5, 0, // Skip to: 3315
/* 1790 */    MCD_OPC_CheckPredicate, 112, 240, 5, 0, // Skip to: 3315
/* 1795 */    MCD_OPC_Decode, 145, 23, 200, 3, // Opcode: SWGP_NM
/* 1800 */    MCD_OPC_FilterValue, 17, 123, 0, 0, // Skip to: 1928
/* 1805 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 1808 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 1823
/* 1813 */    MCD_OPC_CheckPredicate, 112, 217, 5, 0, // Skip to: 3315
/* 1818 */    MCD_OPC_Decode, 159, 15, 201, 3, // Opcode: LBGP_NM
/* 1823 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 1838
/* 1828 */    MCD_OPC_CheckPredicate, 112, 202, 5, 0, // Skip to: 3315
/* 1833 */    MCD_OPC_Decode, 200, 20, 201, 3, // Opcode: SBGP_NM
/* 1838 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 1853
/* 1843 */    MCD_OPC_CheckPredicate, 112, 187, 5, 0, // Skip to: 3315
/* 1848 */    MCD_OPC_Decode, 162, 15, 201, 3, // Opcode: LBUGP_NM
/* 1853 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 1868
/* 1858 */    MCD_OPC_CheckPredicate, 112, 172, 5, 0, // Skip to: 3315
/* 1863 */    MCD_OPC_Decode, 254, 5, 202, 3, // Opcode: ADDIUGPB_NM
/* 1868 */    MCD_OPC_FilterValue, 4, 33, 0, 0, // Skip to: 1906
/* 1873 */    MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 1876 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 1891
/* 1881 */    MCD_OPC_CheckPredicate, 112, 149, 5, 0, // Skip to: 3315
/* 1886 */    MCD_OPC_Decode, 211, 15, 203, 3, // Opcode: LHGP_NM
/* 1891 */    MCD_OPC_FilterValue, 1, 139, 5, 0, // Skip to: 3315
/* 1896 */    MCD_OPC_CheckPredicate, 112, 134, 5, 0, // Skip to: 3315
/* 1901 */    MCD_OPC_Decode, 214, 15, 203, 3, // Opcode: LHUGP_NM
/* 1906 */    MCD_OPC_FilterValue, 5, 124, 5, 0, // Skip to: 3315
/* 1911 */    MCD_OPC_CheckPredicate, 112, 119, 5, 0, // Skip to: 3315
/* 1916 */    MCD_OPC_CheckField, 0, 1, 0, 112, 5, 0, // Skip to: 3315
/* 1923 */    MCD_OPC_Decode, 153, 21, 203, 3, // Opcode: SHGP_NM
/* 1928 */    MCD_OPC_FilterValue, 18, 65, 0, 0, // Skip to: 1998
/* 1933 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 1936 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 1951
/* 1941 */    MCD_OPC_CheckPredicate, 112, 89, 5, 0, // Skip to: 3315
/* 1946 */    MCD_OPC_Decode, 244, 14, 185, 3, // Opcode: JALRC_NM
/* 1951 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 1966
/* 1956 */    MCD_OPC_CheckPredicate, 112, 74, 5, 0, // Skip to: 3315
/* 1961 */    MCD_OPC_Decode, 241, 14, 185, 3, // Opcode: JALRCHB_NM
/* 1966 */    MCD_OPC_FilterValue, 8, 64, 5, 0, // Skip to: 3315
/* 1971 */    MCD_OPC_CheckPredicate, 112, 12, 0, 0, // Skip to: 1988
/* 1976 */    MCD_OPC_CheckField, 21, 5, 0, 5, 0, 0, // Skip to: 1988
/* 1983 */    MCD_OPC_Decode, 218, 8, 197, 3, // Opcode: BRSC_NM
/* 1988 */    MCD_OPC_CheckPredicate, 112, 42, 5, 0, // Skip to: 3315
/* 1993 */    MCD_OPC_Decode, 154, 7, 204, 3, // Opcode: BALRSC_NM
/* 1998 */    MCD_OPC_FilterValue, 32, 217, 1, 0, // Skip to: 2476
/* 2003 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 2006 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 2021
/* 2011 */    MCD_OPC_CheckPredicate, 112, 19, 5, 0, // Skip to: 3315
/* 2016 */    MCD_OPC_Decode, 170, 19, 205, 3, // Opcode: ORI_NM
/* 2021 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 2036
/* 2026 */    MCD_OPC_CheckPredicate, 112, 4, 5, 0, // Skip to: 3315
/* 2031 */    MCD_OPC_Decode, 179, 24, 205, 3, // Opcode: XORI_NM
/* 2036 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 2051
/* 2041 */    MCD_OPC_CheckPredicate, 112, 245, 4, 0, // Skip to: 3315
/* 2046 */    MCD_OPC_Decode, 226, 6, 205, 3, // Opcode: ANDI_NM
/* 2051 */    MCD_OPC_FilterValue, 3, 69, 0, 0, // Skip to: 2125
/* 2056 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 2059 */    MCD_OPC_FilterValue, 0, 17, 0, 0, // Skip to: 2081
/* 2064 */    MCD_OPC_CheckPredicate, 112, 222, 4, 0, // Skip to: 3315
/* 2069 */    MCD_OPC_CheckField, 20, 1, 0, 215, 4, 0, // Skip to: 3315
/* 2076 */    MCD_OPC_Decode, 192, 20, 206, 3, // Opcode: SAVE_NM
/* 2081 */    MCD_OPC_FilterValue, 2, 17, 0, 0, // Skip to: 2103
/* 2086 */    MCD_OPC_CheckPredicate, 112, 200, 4, 0, // Skip to: 3315
/* 2091 */    MCD_OPC_CheckField, 20, 1, 0, 193, 4, 0, // Skip to: 3315
/* 2098 */    MCD_OPC_Decode, 150, 20, 206, 3, // Opcode: RESTORE_NM
/* 2103 */    MCD_OPC_FilterValue, 3, 183, 4, 0, // Skip to: 3315
/* 2108 */    MCD_OPC_CheckPredicate, 112, 178, 4, 0, // Skip to: 3315
/* 2113 */    MCD_OPC_CheckField, 20, 1, 0, 171, 4, 0, // Skip to: 3315
/* 2120 */    MCD_OPC_Decode, 149, 20, 206, 3, // Opcode: RESTOREJRC_NM
/* 2125 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 2140
/* 2130 */    MCD_OPC_CheckPredicate, 112, 156, 4, 0, // Skip to: 3315
/* 2135 */    MCD_OPC_Decode, 242, 21, 205, 3, // Opcode: SLTI_NM
/* 2140 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 2155
/* 2145 */    MCD_OPC_CheckPredicate, 112, 141, 4, 0, // Skip to: 3315
/* 2150 */    MCD_OPC_Decode, 241, 21, 205, 3, // Opcode: SLTIU_NM
/* 2155 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 2170
/* 2160 */    MCD_OPC_CheckPredicate, 112, 126, 4, 0, // Skip to: 3315
/* 2165 */    MCD_OPC_Decode, 141, 21, 205, 3, // Opcode: SEQI_NM
/* 2170 */    MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 2185
/* 2175 */    MCD_OPC_CheckPredicate, 112, 111, 4, 0, // Skip to: 3315
/* 2180 */    MCD_OPC_Decode, 128, 6, 207, 3, // Opcode: ADDIUNEG_NM
/* 2185 */    MCD_OPC_FilterValue, 12, 150, 0, 0, // Skip to: 2340
/* 2190 */    MCD_OPC_ExtractField, 5, 4,  // Inst{8-5} ...
/* 2193 */    MCD_OPC_FilterValue, 0, 97, 0, 0, // Skip to: 2295
/* 2198 */    MCD_OPC_ExtractField, 0, 5,  // Inst{4-0} ...
/* 2201 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 2222
/* 2206 */    MCD_OPC_CheckPredicate, 112, 74, 0, 0, // Skip to: 2285
/* 2211 */    MCD_OPC_CheckField, 16, 10, 0, 67, 0, 0, // Skip to: 2285
/* 2218 */    MCD_OPC_Decode, 149, 19, 10, // Opcode: NOP32_NM
/* 2222 */    MCD_OPC_FilterValue, 3, 16, 0, 0, // Skip to: 2243
/* 2227 */    MCD_OPC_CheckPredicate, 112, 53, 0, 0, // Skip to: 2285
/* 2232 */    MCD_OPC_CheckField, 16, 10, 0, 46, 0, 0, // Skip to: 2285
/* 2239 */    MCD_OPC_Decode, 209, 12, 10, // Opcode: EHB_NM
/* 2243 */    MCD_OPC_FilterValue, 5, 16, 0, 0, // Skip to: 2264
/* 2248 */    MCD_OPC_CheckPredicate, 112, 32, 0, 0, // Skip to: 2285
/* 2253 */    MCD_OPC_CheckField, 16, 10, 0, 25, 0, 0, // Skip to: 2285
/* 2260 */    MCD_OPC_Decode, 184, 19, 10, // Opcode: PAUSE_NM
/* 2264 */    MCD_OPC_FilterValue, 6, 16, 0, 0, // Skip to: 2285
/* 2269 */    MCD_OPC_CheckPredicate, 112, 11, 0, 0, // Skip to: 2285
/* 2274 */    MCD_OPC_CheckField, 21, 5, 0, 4, 0, 0, // Skip to: 2285
/* 2281 */    MCD_OPC_Decode, 181, 23, 87, // Opcode: SYNC_NM
/* 2285 */    MCD_OPC_CheckPredicate, 112, 1, 4, 0, // Skip to: 3315
/* 2290 */    MCD_OPC_Decode, 237, 21, 208, 3, // Opcode: SLL_NM
/* 2295 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 2310
/* 2300 */    MCD_OPC_CheckPredicate, 112, 242, 3, 0, // Skip to: 3315
/* 2305 */    MCD_OPC_Decode, 183, 22, 208, 3, // Opcode: SRL_NM
/* 2310 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 2325
/* 2315 */    MCD_OPC_CheckPredicate, 112, 227, 3, 0, // Skip to: 3315
/* 2320 */    MCD_OPC_Decode, 158, 22, 208, 3, // Opcode: SRA_NM
/* 2325 */    MCD_OPC_FilterValue, 6, 217, 3, 0, // Skip to: 3315
/* 2330 */    MCD_OPC_CheckPredicate, 112, 212, 3, 0, // Skip to: 3315
/* 2335 */    MCD_OPC_Decode, 160, 20, 208, 3, // Opcode: ROTR_NM
/* 2340 */    MCD_OPC_FilterValue, 13, 73, 0, 0, // Skip to: 2418
/* 2345 */    MCD_OPC_ExtractField, 5, 1,  // Inst{5} ...
/* 2348 */    MCD_OPC_FilterValue, 0, 194, 3, 0, // Skip to: 3315
/* 2353 */    MCD_OPC_ExtractField, 11, 1,  // Inst{11} ...
/* 2356 */    MCD_OPC_FilterValue, 0, 186, 3, 0, // Skip to: 3315
/* 2361 */    MCD_OPC_ExtractField, 0, 5,  // Inst{4-0} ...
/* 2364 */    MCD_OPC_FilterValue, 24, 17, 0, 0, // Skip to: 2386
/* 2369 */    MCD_OPC_CheckPredicate, 112, 34, 0, 0, // Skip to: 2408
/* 2374 */    MCD_OPC_CheckField, 6, 5, 8, 27, 0, 0, // Skip to: 2408
/* 2381 */    MCD_OPC_Decode, 229, 8, 185, 3, // Opcode: BYTEREVW_NM
/* 2386 */    MCD_OPC_FilterValue, 31, 17, 0, 0, // Skip to: 2408
/* 2391 */    MCD_OPC_CheckPredicate, 112, 12, 0, 0, // Skip to: 2408
/* 2396 */    MCD_OPC_CheckField, 6, 5, 0, 5, 0, 0, // Skip to: 2408
/* 2403 */    MCD_OPC_Decode, 130, 8, 185, 3, // Opcode: BITREVW_NM
/* 2408 */    MCD_OPC_CheckPredicate, 112, 134, 3, 0, // Skip to: 3315
/* 2413 */    MCD_OPC_Decode, 161, 20, 209, 3, // Opcode: ROTX_NM
/* 2418 */    MCD_OPC_FilterValue, 14, 24, 0, 0, // Skip to: 2447
/* 2423 */    MCD_OPC_CheckPredicate, 112, 119, 3, 0, // Skip to: 3315
/* 2428 */    MCD_OPC_CheckField, 11, 1, 0, 112, 3, 0, // Skip to: 3315
/* 2435 */    MCD_OPC_CheckField, 5, 1, 0, 105, 3, 0, // Skip to: 3315
/* 2442 */    MCD_OPC_Decode, 233, 14, 210, 3, // Opcode: INS_NM
/* 2447 */    MCD_OPC_FilterValue, 15, 95, 3, 0, // Skip to: 3315
/* 2452 */    MCD_OPC_CheckPredicate, 112, 90, 3, 0, // Skip to: 3315
/* 2457 */    MCD_OPC_CheckField, 11, 1, 0, 83, 3, 0, // Skip to: 3315
/* 2464 */    MCD_OPC_CheckField, 5, 1, 0, 76, 3, 0, // Skip to: 3315
/* 2471 */    MCD_OPC_Decode, 129, 13, 211, 3, // Opcode: EXT_NM
/* 2476 */    MCD_OPC_FilterValue, 33, 155, 0, 0, // Skip to: 2636
/* 2481 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 2484 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 2499
/* 2489 */    MCD_OPC_CheckPredicate, 112, 53, 3, 0, // Skip to: 3315
/* 2494 */    MCD_OPC_Decode, 172, 15, 212, 3, // Opcode: LB_NM
/* 2499 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 2514
/* 2504 */    MCD_OPC_CheckPredicate, 112, 38, 3, 0, // Skip to: 3315
/* 2509 */    MCD_OPC_Decode, 204, 20, 212, 3, // Opcode: SB_NM
/* 2514 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 2529
/* 2519 */    MCD_OPC_CheckPredicate, 112, 23, 3, 0, // Skip to: 3315
/* 2524 */    MCD_OPC_Decode, 167, 15, 212, 3, // Opcode: LBU_NM
/* 2529 */    MCD_OPC_FilterValue, 3, 27, 0, 0, // Skip to: 2561
/* 2534 */    MCD_OPC_CheckPredicate, 112, 12, 0, 0, // Skip to: 2551
/* 2539 */    MCD_OPC_CheckField, 21, 5, 31, 5, 0, 0, // Skip to: 2551
/* 2546 */    MCD_OPC_Decode, 177, 23, 213, 3, // Opcode: SYNCI_NM
/* 2551 */    MCD_OPC_CheckPredicate, 112, 247, 2, 0, // Skip to: 3315
/* 2556 */    MCD_OPC_Decode, 244, 19, 214, 3, // Opcode: PREF_NM
/* 2561 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 2576
/* 2566 */    MCD_OPC_CheckPredicate, 112, 232, 2, 0, // Skip to: 3315
/* 2571 */    MCD_OPC_Decode, 224, 15, 212, 3, // Opcode: LH_NM
/* 2576 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 2591
/* 2581 */    MCD_OPC_CheckPredicate, 112, 217, 2, 0, // Skip to: 3315
/* 2586 */    MCD_OPC_Decode, 206, 21, 212, 3, // Opcode: SH_NM
/* 2591 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 2606
/* 2596 */    MCD_OPC_CheckPredicate, 112, 202, 2, 0, // Skip to: 3315
/* 2601 */    MCD_OPC_Decode, 217, 15, 212, 3, // Opcode: LHU_NM
/* 2606 */    MCD_OPC_FilterValue, 8, 10, 0, 0, // Skip to: 2621
/* 2611 */    MCD_OPC_CheckPredicate, 112, 187, 2, 0, // Skip to: 3315
/* 2616 */    MCD_OPC_Decode, 181, 16, 212, 3, // Opcode: LW_NM
/* 2621 */    MCD_OPC_FilterValue, 9, 177, 2, 0, // Skip to: 3315
/* 2626 */    MCD_OPC_CheckPredicate, 112, 172, 2, 0, // Skip to: 3315
/* 2631 */    MCD_OPC_Decode, 171, 23, 212, 3, // Opcode: SW_NM
/* 2636 */    MCD_OPC_FilterValue, 34, 48, 0, 0, // Skip to: 2689
/* 2641 */    MCD_OPC_ExtractField, 14, 2,  // Inst{15-14} ...
/* 2644 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 2659
/* 2649 */    MCD_OPC_CheckPredicate, 112, 149, 2, 0, // Skip to: 3315
/* 2654 */    MCD_OPC_Decode, 194, 7, 215, 3, // Opcode: BEQC_NM
/* 2659 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 2674
/* 2664 */    MCD_OPC_CheckPredicate, 112, 134, 2, 0, // Skip to: 3315
/* 2669 */    MCD_OPC_Decode, 212, 7, 215, 3, // Opcode: BGEC_NM
/* 2674 */    MCD_OPC_FilterValue, 3, 124, 2, 0, // Skip to: 3315
/* 2679 */    MCD_OPC_CheckPredicate, 112, 119, 2, 0, // Skip to: 3315
/* 2684 */    MCD_OPC_Decode, 218, 7, 215, 3, // Opcode: BGEUC_NM
/* 2689 */    MCD_OPC_FilterValue, 41, 146, 1, 0, // Skip to: 3096
/* 2694 */    MCD_OPC_ExtractField, 8, 4,  // Inst{11-8} ...
/* 2697 */    MCD_OPC_FilterValue, 0, 78, 0, 0, // Skip to: 2780
/* 2702 */    MCD_OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 2705 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 2720
/* 2710 */    MCD_OPC_CheckPredicate, 112, 88, 2, 0, // Skip to: 3315
/* 2715 */    MCD_OPC_Decode, 173, 15, 216, 3, // Opcode: LBs9_NM
/* 2720 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 2735
/* 2725 */    MCD_OPC_CheckPredicate, 112, 73, 2, 0, // Skip to: 3315
/* 2730 */    MCD_OPC_Decode, 168, 15, 216, 3, // Opcode: LBUs9_NM
/* 2735 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 2750
/* 2740 */    MCD_OPC_CheckPredicate, 112, 58, 2, 0, // Skip to: 3315
/* 2745 */    MCD_OPC_Decode, 225, 15, 216, 3, // Opcode: LHs9_NM
/* 2750 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 2765
/* 2755 */    MCD_OPC_CheckPredicate, 112, 43, 2, 0, // Skip to: 3315
/* 2760 */    MCD_OPC_Decode, 218, 15, 216, 3, // Opcode: LHUs9_NM
/* 2765 */    MCD_OPC_FilterValue, 4, 33, 2, 0, // Skip to: 3315
/* 2770 */    MCD_OPC_CheckPredicate, 112, 28, 2, 0, // Skip to: 3315
/* 2775 */    MCD_OPC_Decode, 182, 16, 216, 3, // Opcode: LWs9_NM
/* 2780 */    MCD_OPC_FilterValue, 1, 56, 0, 0, // Skip to: 2841
/* 2785 */    MCD_OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 2788 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 2803
/* 2793 */    MCD_OPC_CheckPredicate, 112, 5, 2, 0, // Skip to: 3315
/* 2798 */    MCD_OPC_Decode, 146, 24, 141, 1, // Opcode: UALH_NM
/* 2803 */    MCD_OPC_FilterValue, 5, 251, 1, 0, // Skip to: 3315
/* 2808 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 2811 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 2826
/* 2816 */    MCD_OPC_CheckPredicate, 112, 238, 1, 0, // Skip to: 3315
/* 2821 */    MCD_OPC_Decode, 245, 15, 217, 3, // Opcode: LL_NM
/* 2826 */    MCD_OPC_FilterValue, 1, 228, 1, 0, // Skip to: 3315
/* 2831 */    MCD_OPC_CheckPredicate, 112, 223, 1, 0, // Skip to: 3315
/* 2836 */    MCD_OPC_Decode, 242, 15, 218, 3, // Opcode: LLWP_NM
/* 2841 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 2856
/* 2846 */    MCD_OPC_CheckPredicate, 112, 208, 1, 0, // Skip to: 3315
/* 2851 */    MCD_OPC_Decode, 157, 16, 219, 3, // Opcode: LWM_NM
/* 2856 */    MCD_OPC_FilterValue, 5, 27, 0, 0, // Skip to: 2888
/* 2861 */    MCD_OPC_CheckPredicate, 112, 12, 0, 0, // Skip to: 2878
/* 2866 */    MCD_OPC_CheckField, 12, 3, 1, 5, 0, 0, // Skip to: 2878
/* 2873 */    MCD_OPC_Decode, 148, 24, 141, 1, // Opcode: UALW_NM
/* 2878 */    MCD_OPC_CheckPredicate, 112, 176, 1, 0, // Skip to: 3315
/* 2883 */    MCD_OPC_Decode, 147, 24, 219, 3, // Opcode: UALWM_NM
/* 2888 */    MCD_OPC_FilterValue, 8, 80, 0, 0, // Skip to: 2973
/* 2893 */    MCD_OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 2896 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 2911
/* 2901 */    MCD_OPC_CheckPredicate, 112, 153, 1, 0, // Skip to: 3315
/* 2906 */    MCD_OPC_Decode, 205, 20, 216, 3, // Opcode: SBs9_NM
/* 2911 */    MCD_OPC_FilterValue, 1, 27, 0, 0, // Skip to: 2943
/* 2916 */    MCD_OPC_CheckPredicate, 112, 12, 0, 0, // Skip to: 2933
/* 2921 */    MCD_OPC_CheckField, 21, 5, 31, 5, 0, 0, // Skip to: 2933
/* 2928 */    MCD_OPC_Decode, 178, 23, 220, 3, // Opcode: SYNCIs9_NM
/* 2933 */    MCD_OPC_CheckPredicate, 112, 121, 1, 0, // Skip to: 3315
/* 2938 */    MCD_OPC_Decode, 246, 19, 221, 3, // Opcode: PREFs9_NM
/* 2943 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 2958
/* 2948 */    MCD_OPC_CheckPredicate, 112, 106, 1, 0, // Skip to: 3315
/* 2953 */    MCD_OPC_Decode, 207, 21, 216, 3, // Opcode: SHs9_NM
/* 2958 */    MCD_OPC_FilterValue, 4, 96, 1, 0, // Skip to: 3315
/* 2963 */    MCD_OPC_CheckPredicate, 112, 91, 1, 0, // Skip to: 3315
/* 2968 */    MCD_OPC_Decode, 172, 23, 216, 3, // Opcode: SWs9_NM
/* 2973 */    MCD_OPC_FilterValue, 9, 71, 0, 0, // Skip to: 3049
/* 2978 */    MCD_OPC_ExtractField, 12, 3,  // Inst{14-12} ...
/* 2981 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 2996
/* 2986 */    MCD_OPC_CheckPredicate, 112, 68, 1, 0, // Skip to: 3315
/* 2991 */    MCD_OPC_Decode, 149, 24, 141, 1, // Opcode: UASH_NM
/* 2996 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 3011
/* 3001 */    MCD_OPC_CheckPredicate, 112, 53, 1, 0, // Skip to: 3315
/* 3006 */    MCD_OPC_Decode, 251, 8, 221, 3, // Opcode: CACHE_NM
/* 3011 */    MCD_OPC_FilterValue, 5, 43, 1, 0, // Skip to: 3315
/* 3016 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3019 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 3034
/* 3024 */    MCD_OPC_CheckPredicate, 112, 30, 1, 0, // Skip to: 3315
/* 3029 */    MCD_OPC_Decode, 216, 20, 222, 3, // Opcode: SC_NM
/* 3034 */    MCD_OPC_FilterValue, 1, 20, 1, 0, // Skip to: 3315
/* 3039 */    MCD_OPC_CheckPredicate, 112, 15, 1, 0, // Skip to: 3315
/* 3044 */    MCD_OPC_Decode, 213, 20, 223, 3, // Opcode: SCWP_NM
/* 3049 */    MCD_OPC_FilterValue, 12, 10, 0, 0, // Skip to: 3064
/* 3054 */    MCD_OPC_CheckPredicate, 112, 0, 1, 0, // Skip to: 3315
/* 3059 */    MCD_OPC_Decode, 154, 23, 219, 3, // Opcode: SWM_NM
/* 3064 */    MCD_OPC_FilterValue, 13, 246, 0, 0, // Skip to: 3315
/* 3069 */    MCD_OPC_CheckPredicate, 112, 12, 0, 0, // Skip to: 3086
/* 3074 */    MCD_OPC_CheckField, 12, 3, 1, 5, 0, 0, // Skip to: 3086
/* 3081 */    MCD_OPC_Decode, 151, 24, 141, 1, // Opcode: UASW_NM
/* 3086 */    MCD_OPC_CheckPredicate, 112, 224, 0, 0, // Skip to: 3315
/* 3091 */    MCD_OPC_Decode, 150, 24, 219, 3, // Opcode: UASWM_NM
/* 3096 */    MCD_OPC_FilterValue, 42, 48, 0, 0, // Skip to: 3149
/* 3101 */    MCD_OPC_ExtractField, 14, 2,  // Inst{15-14} ...
/* 3104 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 3119
/* 3109 */    MCD_OPC_CheckPredicate, 112, 201, 0, 0, // Skip to: 3315
/* 3114 */    MCD_OPC_Decode, 176, 8, 215, 3, // Opcode: BNEC_NM
/* 3119 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 3134
/* 3124 */    MCD_OPC_CheckPredicate, 112, 186, 0, 0, // Skip to: 3315
/* 3129 */    MCD_OPC_Decode, 146, 8, 215, 3, // Opcode: BLTC_NM
/* 3134 */    MCD_OPC_FilterValue, 3, 176, 0, 0, // Skip to: 3315
/* 3139 */    MCD_OPC_CheckPredicate, 112, 171, 0, 0, // Skip to: 3315
/* 3144 */    MCD_OPC_Decode, 152, 8, 215, 3, // Opcode: BLTUC_NM
/* 3149 */    MCD_OPC_FilterValue, 50, 123, 0, 0, // Skip to: 3277
/* 3154 */    MCD_OPC_ExtractField, 18, 3,  // Inst{20-18} ...
/* 3157 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 3172
/* 3162 */    MCD_OPC_CheckPredicate, 112, 148, 0, 0, // Skip to: 3315
/* 3167 */    MCD_OPC_Decode, 196, 7, 224, 3, // Opcode: BEQIC_NM
/* 3172 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 3187
/* 3177 */    MCD_OPC_CheckPredicate, 112, 133, 0, 0, // Skip to: 3315
/* 3182 */    MCD_OPC_Decode, 155, 7, 225, 3, // Opcode: BBEQZC_NM
/* 3187 */    MCD_OPC_FilterValue, 2, 10, 0, 0, // Skip to: 3202
/* 3192 */    MCD_OPC_CheckPredicate, 112, 118, 0, 0, // Skip to: 3315
/* 3197 */    MCD_OPC_Decode, 213, 7, 224, 3, // Opcode: BGEIC_NM
/* 3202 */    MCD_OPC_FilterValue, 3, 10, 0, 0, // Skip to: 3217
/* 3207 */    MCD_OPC_CheckPredicate, 112, 103, 0, 0, // Skip to: 3315
/* 3212 */    MCD_OPC_Decode, 214, 7, 224, 3, // Opcode: BGEIUC_NM
/* 3217 */    MCD_OPC_FilterValue, 4, 10, 0, 0, // Skip to: 3232
/* 3222 */    MCD_OPC_CheckPredicate, 112, 88, 0, 0, // Skip to: 3315
/* 3227 */    MCD_OPC_Decode, 186, 8, 224, 3, // Opcode: BNEIC_NM
/* 3232 */    MCD_OPC_FilterValue, 5, 10, 0, 0, // Skip to: 3247
/* 3237 */    MCD_OPC_CheckPredicate, 112, 73, 0, 0, // Skip to: 3315
/* 3242 */    MCD_OPC_Decode, 160, 7, 225, 3, // Opcode: BBNEZC_NM
/* 3247 */    MCD_OPC_FilterValue, 6, 10, 0, 0, // Skip to: 3262
/* 3252 */    MCD_OPC_CheckPredicate, 112, 58, 0, 0, // Skip to: 3315
/* 3257 */    MCD_OPC_Decode, 147, 8, 224, 3, // Opcode: BLTIC_NM
/* 3262 */    MCD_OPC_FilterValue, 7, 48, 0, 0, // Skip to: 3315
/* 3267 */    MCD_OPC_CheckPredicate, 112, 43, 0, 0, // Skip to: 3315
/* 3272 */    MCD_OPC_Decode, 148, 8, 224, 3, // Opcode: BLTIUC_NM
/* 3277 */    MCD_OPC_FilterValue, 56, 33, 0, 0, // Skip to: 3315
/* 3282 */    MCD_OPC_ExtractField, 1, 1,  // Inst{1} ...
/* 3285 */    MCD_OPC_FilterValue, 0, 10, 0, 0, // Skip to: 3300
/* 3290 */    MCD_OPC_CheckPredicate, 112, 20, 0, 0, // Skip to: 3315
/* 3295 */    MCD_OPC_Decode, 252, 15, 226, 3, // Opcode: LUI_NM
/* 3300 */    MCD_OPC_FilterValue, 1, 10, 0, 0, // Skip to: 3315
/* 3305 */    MCD_OPC_CheckPredicate, 112, 5, 0, 0, // Skip to: 3315
/* 3310 */    MCD_OPC_Decode, 215, 6, 226, 3, // Opcode: ALUIPC_NM
/* 3315 */    MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableNanoMips48[] = {
/* 0 */       MCD_OPC_ExtractField, 32, 5,  // Inst{36-32} ...
/* 3 */       MCD_OPC_FilterValue, 0, 17, 0, 0, // Skip to: 25
/* 8 */       MCD_OPC_CheckPredicate, 112, 122, 0, 0, // Skip to: 135
/* 13 */      MCD_OPC_CheckField, 42, 6, 24, 115, 0, 0, // Skip to: 135
/* 20 */      MCD_OPC_Decode, 234, 15, 227, 3, // Opcode: LI48_NM
/* 25 */      MCD_OPC_FilterValue, 1, 17, 0, 0, // Skip to: 47
/* 30 */      MCD_OPC_CheckPredicate, 112, 100, 0, 0, // Skip to: 135
/* 35 */      MCD_OPC_CheckField, 42, 6, 24, 93, 0, 0, // Skip to: 135
/* 42 */      MCD_OPC_Decode, 252, 5, 228, 3, // Opcode: ADDIU48_NM
/* 47 */      MCD_OPC_FilterValue, 2, 17, 0, 0, // Skip to: 69
/* 52 */      MCD_OPC_CheckPredicate, 112, 78, 0, 0, // Skip to: 135
/* 57 */      MCD_OPC_CheckField, 42, 6, 24, 71, 0, 0, // Skip to: 135
/* 64 */      MCD_OPC_Decode, 253, 5, 229, 3, // Opcode: ADDIUGP48_NM
/* 69 */      MCD_OPC_FilterValue, 3, 17, 0, 0, // Skip to: 91
/* 74 */      MCD_OPC_CheckPredicate, 112, 56, 0, 0, // Skip to: 135
/* 79 */      MCD_OPC_CheckField, 42, 6, 24, 49, 0, 0, // Skip to: 135
/* 86 */      MCD_OPC_Decode, 153, 15, 230, 3, // Opcode: LAPC48_NM
/* 91 */      MCD_OPC_FilterValue, 11, 17, 0, 0, // Skip to: 113
/* 96 */      MCD_OPC_CheckPredicate, 112, 34, 0, 0, // Skip to: 135
/* 101 */     MCD_OPC_CheckField, 42, 6, 24, 27, 0, 0, // Skip to: 135
/* 108 */     MCD_OPC_Decode, 160, 16, 230, 3, // Opcode: LWPC_NM
/* 113 */     MCD_OPC_FilterValue, 15, 17, 0, 0, // Skip to: 135
/* 118 */     MCD_OPC_CheckPredicate, 112, 12, 0, 0, // Skip to: 135
/* 123 */     MCD_OPC_CheckField, 42, 6, 24, 5, 0, 0, // Skip to: 135
/* 130 */     MCD_OPC_Decode, 155, 23, 230, 3, // Opcode: SWPC_NM
/* 135 */     MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableNanoMips_Conflict_Space16[] = {
/* 0 */       MCD_OPC_CheckPredicate, 112, 12, 0, 0, // Skip to: 17
/* 5 */       MCD_OPC_CheckField, 10, 6, 54, 5, 0, 0, // Skip to: 17
/* 12 */      MCD_OPC_Decode, 173, 8, 173, 3, // Opcode: BNEC16_NM
/* 17 */      MCD_OPC_Fail,
  0
};

static bool checkDecoderPredicate(MCInst *Inst, unsigned Idx) {
  switch (Idx) {
  default: CS_ASSERT_RET_VAL(0 && "Invalid index!", false);
  case 0:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16));
  case 1:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureCnMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips));
  case 2:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureCnMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips));
  case 3:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureCnMips));
  case 4:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureCnMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 5:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureCnMipsP));
  case 6:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6));
  case 7:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 8:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureDSP));
  case 9:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureDSPR2));
  case 10:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r5) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureVirt));
  case 11:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureDSPR3));
  case 12:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureDSP));
  case 13:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat));
  case 14:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNoMadd4));
  case 15:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat));
  case 16:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNoMadd4));
  case 17:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat));
  case 18:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat));
  case 19:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat));
  case 20:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat));
  case 21:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureEVA));
  case 22:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureEVA));
  case 23:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat));
  case 24:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6));
  case 25:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureGINV));
  case 26:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat));
  case 27:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips));
  case 28:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips));
  case 29:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips4_32) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 30:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMSA));
  case 31:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips));
  case 32:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6));
  case 33:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureUseIndirectJumpsHazard) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips));
  case 34:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32));
  case 35:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips4_32) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 36:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips));
  case 37:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureDSP));
  case 38:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMSA) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64));
  case 39:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips));
  case 40:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureDSP) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 41:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r5) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureVirt) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips));
  case 42:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMT) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips));
  case 43:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips3_32) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips));
  case 44:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r2) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureEVA) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 45:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r5) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips));
  case 46:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips));
  case 47:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 48:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips3) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 49:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 50:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 51:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 52:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 53:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat));
  case 54:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips4_32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 55:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 56:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips3_32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 57:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 58:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips4_32) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 59:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips4_32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 60:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 61:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips4_32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat));
  case 62:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips4_32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 63:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips5_32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 64:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips4_32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNoMadd4));
  case 65:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips4_32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNoMadd4));
  case 66:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips4_32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNoMadd4) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 67:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips4_32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNoMadd4) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 68:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips));
  case 69:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureDSPR2));
  case 70:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureEVA) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 71:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips3_32) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips));
  case 72:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeaturePTR64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips));
  case 73:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeaturePTR64Bit) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 74:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeaturePTR64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 75:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6));
  case 76:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 77:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 78:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureGP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 79:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 80:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureCRC) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 81:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureCRC) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 82:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeaturePTR64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 83:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureGINV) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 84:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6));
  case 85:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureGP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6));
  case 86:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureGP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6));
  case 87:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeaturePTR64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 88:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 89:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeaturePTR64Bit));
  case 90:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 91:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips3) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 92:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips3) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 93:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureGP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips3));
  case 94:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r5) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureVirt));
  case 95:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips3) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6));
  case 96:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureGP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 97:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureDSP));
  case 98:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 99:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 100:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 101:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 102:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips3_32) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 103:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips4_32) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 104:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips4_32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 105:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips3D));
  case 106:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips3_32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 107:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 108:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips4_32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat));
  case 109:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips5_32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 110:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips4_32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNoMadd4));
  case 111:
    return (!Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips16) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureFP64Bit) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips4_32r2) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips32r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMips64r6) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureSoftFloat) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNoMadd4) && !Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMicroMips));
  case 112:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips));
  case 113:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureMT));
  case 114:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureCRC));
  case 115:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureTLB));
  case 116:
    return (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureNanoMips) && Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureGINV));
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
    tmp = fieldname(insn, 0, 11); \
    if (!Check(&S, DecodeBranchTarget(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 1: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 8); \
    if (!Check(&S, DecodeBranchTarget(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 2: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 8); \
    if (!Check(&S, DecodeSImmWithOffsetAndScale_16_0_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 3: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 8); \
    if (!Check(&S, DecodeSImmWithOffsetAndScale_16_0_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 4: \
    tmp = fieldname(insn, 0, 8); \
    if (!Check(&S, DecodeSImmWithOffsetAndScale_16_0_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 5: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 3, 2) << 3; \
    tmp |= fieldname(insn, 5, 3) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 6: \
    tmp = fieldname(insn, 4, 4); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 4); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 7: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 8: \
    tmp = fieldname(insn, 2, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 9: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 10: \
    return S; \
  case 11: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 12: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 13: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 14: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 5) << 0; \
    tmp |= fieldname(insn, 16, 5) << 11; \
    tmp |= fieldname(insn, 21, 6) << 5; \
    if (!Check(&S, DecodeSImmWithOffsetAndScale_16_0_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 15: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 5) << 0; \
    tmp |= fieldname(insn, 16, 5) << 11; \
    tmp |= fieldname(insn, 21, 6) << 5; \
    if (!Check(&S, DecodeBranchTarget(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 16: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 5) << 0; \
    tmp |= fieldname(insn, 16, 5) << 11; \
    tmp |= fieldname(insn, 21, 6) << 5; \
    if (!Check(&S, DecodeBranchTarget(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 17: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 21, 1) << 5; \
    tmp |= fieldname(insn, 22, 5) << 0; \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 18: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 5) << 0; \
    tmp |= fieldname(insn, 16, 5) << 11; \
    tmp |= fieldname(insn, 21, 6) << 5; \
    if (!Check(&S, DecodeSImmWithOffsetAndScale_16_0_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 19: \
    if (!Check(&S, DecodeFIXMEInstruction(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 20: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 5) << 0; \
    tmp |= fieldname(insn, 16, 5) << 11; \
    tmp |= fieldname(insn, 21, 6) << 5; \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 21: \
    if (!Check(&S, DecodeFMem3(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 22: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 23: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 24: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 25: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 26: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 27: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 10); \
    if (!Check(&S, DecodeSImmWithOffsetAndScale_10_0_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 28: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 29: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeBranchTarget(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 30: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 31: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 1, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 32: \
    if (!Check(&S, DecodeMemMMImm4(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 33: \
    tmp = fieldname(insn, 5, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 34: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 1, 3); \
    if (!Check(&S, DecodePOOL16BEncodedField(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 35: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 4); \
    if (!Check(&S, DecodeANDI16Imm(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 36: \
    tmp = fieldname(insn, 3, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 37: \
    tmp = fieldname(insn, 3, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 3, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 38: \
    if (!Check(&S, DecodeMemMMReglistImm4Lsl2(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 39: \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 40: \
    tmp = fieldname(insn, 0, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 41: \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeUImmWithOffsetAndScale_5_0_4(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 42: \
    if (!Check(&S, DecodeMemMMSPImm5Lsl2(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 43: \
    tmp = fieldname(insn, 5, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 1, 4); \
    if (!Check(&S, DecodeSImmWithOffsetAndScale_4_0_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 44: \
    tmp = fieldname(insn, 1, 9); \
    if (!Check(&S, DecodeSimm9SP(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 45: \
    if (!Check(&S, DecodeMemMMGPImm7Lsl2(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 46: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 1, 3); \
    if (!Check(&S, DecodeAddiur2Simm7(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 47: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 1, 6); \
    if (!Check(&S, DecodeUImmWithOffsetAndScale_6_0_4(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 48: \
    if (!Check(&S, DecodeMovePOperands(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 49: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 7); \
    if (!Check(&S, DecodeBranchTarget7MM(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 50: \
    tmp = fieldname(insn, 0, 10); \
    if (!Check(&S, DecodeBranchTarget10MM(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 51: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 7); \
    if (!Check(&S, DecodeLi16Imm(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 52: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 53: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 54: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 55: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 56: \
    tmp = fieldname(insn, 16, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 6, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 57: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeInsSize(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 58: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 59: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 60: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 61: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 62: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 63: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 64: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 65: \
    tmp = fieldname(insn, 14, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 6); \
    if (!Check(&S, DecodeSImmWithOffsetAndScale_6_0_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 66: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeUImmWithOffset_5_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 67: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 68: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeCOP0RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 69: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeCOP0RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 70: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 12, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 71: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 12, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 72: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 73: \
    tmp = fieldname(insn, 14, 2); \
    if (!Check(&S, DecodeHI32DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 74: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 13, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 75: \
    tmp = fieldname(insn, 14, 2); \
    if (!Check(&S, DecodeLO32DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 76: \
    tmp = fieldname(insn, 14, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 77: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 78: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 79: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 80: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 81: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 82: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 83: \
    tmp = fieldname(insn, 14, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 84: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 85: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeHWRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 86: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 87: \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 88: \
    tmp = fieldname(insn, 16, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 89: \
    tmp = fieldname(insn, 14, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 90: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeCOP2RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 91: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeCOP2RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 92: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 93: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 13, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 94: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 7); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 95: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 14, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 96: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 10); \
    if (!Check(&S, DecodeSImmWithOffsetAndScale_10_0_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 97: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeSImmWithOffsetAndScale_16_0_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 98: \
    if (!Check(&S, DecodeMemMMImm16(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 99: \
    if (!Check(&S, DecodeMemMMImm12(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 100: \
    if (!Check(&S, DecodeCacheOpMM(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 101: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeBranchTargetMM(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 102: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeSImmWithOffsetAndScale_16_0_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 103: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 104: \
    if (!Check(&S, DecodeSyncI_MM(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 105: \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeBranchTarget1SImm16(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 106: \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeBranchTargetMM(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 107: \
    tmp = fieldname(insn, 18, 3); \
    if (!Check(&S, DecodeFCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeBranchTargetMM(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 108: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 109: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 110: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 111: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 112: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 113: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 13, 3); \
    if (!Check(&S, DecodeFCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 114: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 115: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 13, 3); \
    if (!Check(&S, DecodeFCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 116: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 117: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 118: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 119: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 120: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 121: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 122: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 123: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 13, 3); \
    if (!Check(&S, DecodeFCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 124: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 125: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 126: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 127: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeCCRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 128: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 129: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 130: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeCCRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 131: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 132: \
    tmp = fieldname(insn, 13, 3); \
    if (!Check(&S, DecodeFCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 133: \
    tmp = fieldname(insn, 13, 3); \
    if (!Check(&S, DecodeFCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 134: \
    if (!Check(&S, DecodeMemMMImm9(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 135: \
    if (!Check(&S, DecodePrefeOpMM(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 136: \
    if (!Check(&S, DecodeJumpTargetMM(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 137: \
    tmp = fieldname(insn, 23, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 23); \
    if (!Check(&S, DecodeSimm23Lsl2(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 138: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeBranchTargetMM(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 139: \
    if (!Check(&S, DecodeFMemMMR2(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 140: \
    if (!Check(&S, DecodeJumpTargetXMM(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 141: \
    if (!Check(&S, DecodeMem(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 142: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 143: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 144: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 145: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 146: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 147: \
    tmp = fieldname(insn, 1, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 148: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 149: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRMM16RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 150: \
    tmp = fieldname(insn, 5, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 151: \
    tmp = fieldname(insn, 5, 5); \
    if (!Check(&S, DecodeUImmWithOffsetAndScale_5_0_4(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 152: \
    tmp = fieldname(insn, 6, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 153: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeHWRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 154: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 9, 2); \
    if (!Check(&S, DecodeUImmWithOffset_2_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 155: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 9, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 156: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 9, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 157: \
    tmp = fieldname(insn, 6, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 158: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 159: \
    if (!Check(&S, DecodeLoadByte15(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 160: \
    if (!Check(&S, DecodeFMemCop2MMR6(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 161: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeBranchTargetMM(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 162: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeCOP2RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeBranchTargetMM(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 163: \
    if (!Check(&S, DecodeSynciR6(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 164: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 165: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGRCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 166: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGRCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 167: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 168: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 169: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGRCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 170: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 171: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 172: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 173: \
    if (!Check(&S, DecodePOP35GroupBranchMMR6(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 174: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 19); \
    if (!Check(&S, DecodeSimm19Lsl2(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 175: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeSImmWithOffsetAndScale_16_0_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 176: \
    if (!Check(&S, DecodePOP37GroupBranchMMR6(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 177: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 21); \
    if (!Check(&S, DecodeBranchTarget21MM(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 178: \
    tmp = fieldname(insn, 0, 26); \
    if (!Check(&S, DecodeBranchTarget26MM(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 179: \
    if (!Check(&S, DecodeBlezGroupBranchMMR6(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 180: \
    if (!Check(&S, DecodePOP65GroupBranchMMR6(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 181: \
    if (!Check(&S, DecodeBgtzGroupBranchMMR6(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 182: \
    if (!Check(&S, DecodePOP75GroupBranchMMR6(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 183: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 184: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 18, 3); \
    if (!Check(&S, DecodeFCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 185: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 2); \
    if (!Check(&S, DecodeUImmWithOffset_2_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 186: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 187: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 188: \
    tmp = fieldname(insn, 6, 20); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 189: \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 190: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 191: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 192: \
    tmp = fieldname(insn, 11, 2); \
    if (!Check(&S, DecodeHI32DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 193: \
    tmp = fieldname(insn, 11, 2); \
    if (!Check(&S, DecodeLO32DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 194: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 2); \
    if (!Check(&S, DecodeUImmWithOffset_2_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 195: \
    tmp = fieldname(insn, 11, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 196: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 197: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeBranchTarget(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 198: \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeBranchTarget(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 199: \
    if (!Check(&S, DecodeSyncI(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 200: \
    if (!Check(&S, DecodeJumpTarget(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 201: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeBranchTarget(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 202: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeSImmWithOffsetAndScale_16_0_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 203: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 204: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeCOP0RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 205: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeCOP0RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 206: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 4, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 207: \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 208: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 209: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 210: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeCCRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 211: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 212: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 213: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 214: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeCCRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 215: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 216: \
    tmp = fieldname(insn, 18, 3); \
    if (!Check(&S, DecodeFCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeBranchTarget(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 217: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeBranchTarget(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 218: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 219: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 220: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 18, 3); \
    if (!Check(&S, DecodeFCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 221: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 222: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 223: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 224: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeFCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 225: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 226: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 227: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 228: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 18, 3); \
    if (!Check(&S, DecodeFCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 229: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 230: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 231: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeFCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 232: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeBranchTarget(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 233: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeBranchTarget(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 234: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeBranchTarget(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 235: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeCOP2RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 236: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeCOP2RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 237: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 238: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 239: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 240: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 241: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 242: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 243: \
    tmp = fieldname(insn, 11, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 244: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 11, 5) << 0; \
    tmp |= fieldname(insn, 16, 5) << 0; \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 245: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 246: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 247: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 248: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 249: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 250: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 251: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 252: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 253: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 254: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 255: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 256: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 257: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 6); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 258: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 259: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 260: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 6); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 261: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 262: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 263: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 264: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 265: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 266: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 267: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 268: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 269: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 270: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 271: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 272: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 273: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 274: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 275: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 276: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 277: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 278: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 279: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 280: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 281: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 282: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 283: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 284: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 285: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 286: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 287: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 288: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 289: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 290: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSACtrlRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 291: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 292: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 293: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 294: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 295: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSACtrlRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 296: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 297: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 298: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 299: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 300: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 301: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 302: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 303: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 304: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 305: \
    if (!Check(&S, DecodeINSVE_DF(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 306: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 307: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 308: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 309: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 310: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 311: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 312: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 313: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 314: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 315: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 316: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 317: \
    if (!Check(&S, DecodeMSA128Mem(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 318: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeUImmWithOffset_5_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 319: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeInsSize(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 320: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 321: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 322: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 323: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 324: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 325: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 326: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 327: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 328: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 329: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 330: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 331: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 332: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 333: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 334: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeDSPRRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 335: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 336: \
    if (!Check(&S, DecodeMemEVA(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 337: \
    if (!Check(&S, DecodeCacheeOp_CacheOpR6(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 338: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 339: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 340: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 341: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 342: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 343: \
    tmp = fieldname(insn, 11, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 6); \
    if (!Check(&S, DecodeSImmWithOffsetAndScale_6_0_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 344: \
    tmp = fieldname(insn, 11, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 2); \
    if (!Check(&S, DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 345: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeHWRegsRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 346: \
    if (!Check(&S, DecodeCacheOp(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 347: \
    if (!Check(&S, DecodeFMem(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 348: \
    if (!Check(&S, DecodeFMem2(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 349: \
    if (!Check(&S, DecodeDAHIDATI(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 350: \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 351: \
    if (!Check(&S, DecodeBlezGroupBranch(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 352: \
    if (!Check(&S, DecodeBgtzGroupBranch(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 353: \
    if (!Check(&S, DecodeAddiGroupBranch(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 354: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeBranchTarget(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 355: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGRCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 356: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 357: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 358: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 359: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGRCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 360: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGRCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 361: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeCOP2RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeBranchTarget(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 362: \
    if (!Check(&S, DecodeFMemCop2R6(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 363: \
    if (!Check(&S, DecodeBlezlGroupBranch(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 364: \
    if (!Check(&S, DecodeBgtzlGroupBranch(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 365: \
    if (!Check(&S, DecodeDaddiGroupBranch(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 366: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 367: \
    if (!Check(&S, DecodeCRC(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 368: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 369: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 370: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 371: \
    if (!Check(&S, DecodeSpecial3LlSc(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 372: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 8, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 373: \
    tmp = fieldname(insn, 0, 26); \
    if (!Check(&S, DecodeBranchTarget26(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 374: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 21); \
    if (!Check(&S, DecodeBranchTarget21(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 375: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 18); \
    if (!Check(&S, DecodeSimm18Lsl3(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 376: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 21); \
    if (!Check(&S, DecodeBranchTarget21(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 377: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 378: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 379: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 380: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeCOP0RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 381: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeCOP0RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 382: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeCOP2RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 383: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeCOP2RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 384: \
    tmp = fieldname(insn, 13, 3); \
    if (!Check(&S, DecodeFCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 385: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    if (!Check(&S, DecodeSImmWithOffsetAndScale_16_0_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 386: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 11, 5) << 0; \
    tmp |= fieldname(insn, 16, 5) << 0; \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 387: \
    if (!Check(&S, DecodeDEXT(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 388: \
    if (!Check(&S, DecodeDINS(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 389: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 390: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 391: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 392: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 393: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 18, 3); \
    if (!Check(&S, DecodeFCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 394: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 395: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 396: \
    tmp = fieldname(insn, 8, 3); \
    if (!Check(&S, DecodeFCCRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 397: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 398: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodePtrRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 399: \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeFGR64RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 400: \
    tmp = fieldname(insn, 0, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 401: \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 402: \
    tmp = fieldname(insn, 5, 5); \
    if (!Check(&S, DecodeGPRNM32NZRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 403: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 7) << 2; \
    if (!Check(&S, DecodeMemNM_6_0_Mips_GPRNM3RegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 404: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 1) << 10; \
    tmp |= fieldname(insn, 1, 9) << 1; \
    if (!Check(&S, DecodeBranchTargetNM_10(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 405: \
    tmp = fieldname(insn, 4, 4) << 4; \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 4) << 0; \
    tmp |= fieldname(insn, 9, 1) << 4; \
    if (!Check(&S, DecodeNMRegList16Operand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 406: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 3); \
    if (!Check(&S, DecodeUImm3Shift(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 407: \
    tmp = fieldname(insn, 5, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5) << 2; \
    if (!Check(&S, DecodeMemNM_7_0_Mips_GPRNMSPRegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 408: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 5, 3) << 0; \
    tmp |= fieldname(insn, 9, 1) << 4; \
    if (!Check(&S, DecodeGPRNM4RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 3) << 0; \
    tmp |= fieldname(insn, 4, 1) << 4; \
    if (!Check(&S, DecodeGPRNM4RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 409: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 410: \
    tmp = fieldname(insn, 4, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 411: \
    tmp = fieldname(insn, 1, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 4, 3) << 0; \
    tmp |= fieldname(insn, 7, 3) << 5; \
    if (!Check(&S, DecodeMemNMRX_Mips_GPRNM3RegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 412: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 7) << 2; \
    if (!Check(&S, DecodeMemNM_9_0_Mips_GPRNMGPRegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 413: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 2) << 0; \
    tmp |= fieldname(insn, 4, 3) << 2; \
    if (!Check(&S, DecodeMemNM_2_0_Mips_GPRNM3RegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 414: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRNM3ZRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 2) << 0; \
    tmp |= fieldname(insn, 4, 3) << 2; \
    if (!Check(&S, DecodeMemNM_2_0_Mips_GPRNM3RegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 415: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 6) << 2; \
    if (!Check(&S, DecodeUImmWithReg_8_0_1_Mips_SP_NM(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 416: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 5, 3) << 0; \
    tmp |= fieldname(insn, 9, 1) << 4; \
    if (!Check(&S, DecodeGPRNM4RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 3) << 4; \
    tmp |= fieldname(insn, 3, 1) << 3; \
    tmp |= fieldname(insn, 4, 1) << 8; \
    tmp |= fieldname(insn, 8, 1) << 2; \
    if (!Check(&S, DecodeMemNM4x4(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 417: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 1, 2) << 1; \
    tmp |= fieldname(insn, 4, 3) << 3; \
    if (!Check(&S, DecodeMemNM_3_0_Mips_GPRNM3RegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 418: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRNM3ZRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 1, 2) << 1; \
    tmp |= fieldname(insn, 4, 3) << 3; \
    if (!Check(&S, DecodeMemNM_3_0_Mips_GPRNM3RegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 419: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 3) << 2; \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 420: \
    tmp = fieldname(insn, 5, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 3) << 0; \
    tmp |= fieldname(insn, 4, 1) << 3; \
    if (!Check(&S, DecodeSImmWithOffsetAndScale_4_0_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 421: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRNM3ZRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 7) << 2; \
    if (!Check(&S, DecodeMemNM_6_0_Mips_GPRNM3RegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 422: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 1) << 7; \
    tmp |= fieldname(insn, 1, 6) << 1; \
    if (!Check(&S, DecodeBranchTargetNM_7(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 423: \
    tmp = fieldname(insn, 1, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 424: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 3, 1) << 1; \
    tmp |= fieldname(insn, 8, 1) << 0; \
    if (!Check(&S, DecodeGPRNM2R1RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 3) << 0; \
    tmp |= fieldname(insn, 4, 1) << 4; \
    if (!Check(&S, DecodeGPRNM4ZRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 5, 3) << 0; \
    tmp |= fieldname(insn, 9, 1) << 4; \
    if (!Check(&S, DecodeGPRNM4ZRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 425: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 7); \
    if (!Check(&S, DecodeImmM1To126(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 426: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRNM3ZRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 7) << 2; \
    if (!Check(&S, DecodeMemNM_9_0_Mips_GPRNMGPRegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 427: \
    tmp = fieldname(insn, 5, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 428: \
    tmp = fieldname(insn, 4, 1); \
    if (!Check(&S, DecodeGPRNMRARegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 5, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 429: \
    if (!Check(&S, DecodeBranchConflictNM(MI, insn, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 430: \
    tmp = fieldname(insn, 7, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 4, 3); \
    if (!Check(&S, DecodeGPRNM3RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 4); \
    if (!Check(&S, DecodeUImm4Mask(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 431: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 5, 3) << 0; \
    tmp |= fieldname(insn, 9, 1) << 4; \
    if (!Check(&S, DecodeGPRNM4ZRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 3) << 4; \
    tmp |= fieldname(insn, 3, 1) << 3; \
    tmp |= fieldname(insn, 4, 1) << 8; \
    tmp |= fieldname(insn, 8, 1) << 2; \
    if (!Check(&S, DecodeMemNM4x4(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 432: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 3) << 0; \
    tmp |= fieldname(insn, 4, 1) << 4; \
    if (!Check(&S, DecodeGPRNM4RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 5, 3) << 0; \
    tmp |= fieldname(insn, 9, 1) << 4; \
    if (!Check(&S, DecodeGPRNM4RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 3, 1) << 1; \
    tmp |= fieldname(insn, 8, 1) << 0; \
    if (!Check(&S, DecodeGPRNM2R1RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 433: \
    tmp = fieldname(insn, 0, 18); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 434: \
    tmp = fieldname(insn, 0, 19); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 435: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 436: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 1) << 21; \
    tmp |= fieldname(insn, 1, 20) << 1; \
    if (!Check(&S, DecodeAddressPCRelNM_22(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 437: \
    tmp = fieldname(insn, 24, 1); \
    if (!Check(&S, DecodeGPRNM1R1RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 21, 3) << 0; \
    tmp |= fieldname(insn, 25, 1) << 4; \
    if (!Check(&S, DecodeGPRNM4ZRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 1) << 21; \
    tmp |= fieldname(insn, 1, 20) << 1; \
    if (!Check(&S, DecodeBranchTargetNM_21(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 438: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 439: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeCOP0RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 440: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 10); \
    if (!Check(&S, DecodeMemNMRX_Mips_GPRNM32RegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 441: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 442: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 9, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 443: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 444: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 445: \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 446: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 447: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 448: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 10); \
    if (!Check(&S, DecodeCOP0SelRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 449: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeCOP0RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 10, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 3, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 450: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeCOP0RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 10, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 3, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 451: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 452: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 453: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 454: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 1) << 25; \
    tmp |= fieldname(insn, 1, 24) << 1; \
    if (!Check(&S, DecodeBranchTargetNM_25(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 455: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 2, 19) << 2; \
    if (!Check(&S, DecodeUImmWithReg_21_0_1_Mips_GP_NM(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 456: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 2, 19) << 2; \
    if (!Check(&S, DecodeMemNM_21_0_Mips_GPRNMGPRegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 457: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 18); \
    if (!Check(&S, DecodeMemNM_18_0_Mips_GPRNMGPRegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 458: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 18); \
    if (!Check(&S, DecodeUImmWithReg_18_0_1_Mips_GP_NM(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 459: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 1, 17) << 1; \
    if (!Check(&S, DecodeMemNM_18_0_Mips_GPRNMGPRegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 460: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32NZRegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 461: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 12); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 462: \
    tmp = fieldname(insn, 3, 9) << 3; \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = 0x0; \
    tmp |= fieldname(insn, 2, 1) << 0; \
    tmp |= fieldname(insn, 16, 4) << 1; \
    tmp |= fieldname(insn, 21, 5) << 5; \
    if (!Check(&S, DecodeNMRegListOperand(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 463: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 12); \
    if (!Check(&S, DecodeNegImm12(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 464: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 465: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 7, 4) << 1; \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 6, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 466: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeInsSize(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 467: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 0, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 6, 5); \
    if (!Check(&S, DecodeUImmWithOffset_5_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 468: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 12) << 0; \
    tmp |= fieldname(insn, 16, 5) << 12; \
    if (!Check(&S, DecodeMemNM_12_0_Mips_GPRNM32RegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 469: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 12) << 0; \
    tmp |= fieldname(insn, 16, 5) << 12; \
    if (!Check(&S, DecodeMemNM_12_0_Mips_GPRNM32RegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 470: \
    tmp = fieldname(insn, 21, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 12) << 0; \
    tmp |= fieldname(insn, 16, 5) << 12; \
    if (!Check(&S, DecodeMemNM_12_0_Mips_GPRNM32RegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 471: \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 1) << 14; \
    tmp |= fieldname(insn, 1, 13) << 1; \
    if (!Check(&S, DecodeBranchTargetNM_14(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 472: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 8) << 0; \
    tmp |= fieldname(insn, 15, 6) << 8; \
    if (!Check(&S, DecodeMemNM_9_1_Mips_GPRNM32RegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 473: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 2, 6) << 2; \
    tmp |= fieldname(insn, 15, 6) << 8; \
    if (!Check(&S, DecodeMemNM_9_1_Mips_GPRNM32RegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 474: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 3, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMemZeroNM(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 475: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 8) << 0; \
    tmp |= fieldname(insn, 15, 6) << 8; \
    if (!Check(&S, DecodeMemNM_9_1_Mips_GPRNM32RegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 12, 3); \
    if (!Check(&S, DecodeUImm3Shift(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 476: \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 8) << 0; \
    tmp |= fieldname(insn, 15, 6) << 8; \
    if (!Check(&S, DecodeMemNM_9_1_Mips_GPRNM32RegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 477: \
    tmp = fieldname(insn, 21, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 8) << 0; \
    tmp |= fieldname(insn, 15, 6) << 8; \
    if (!Check(&S, DecodeMemNM_9_1_Mips_GPRNM32RegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 478: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 2, 6) << 2; \
    tmp |= fieldname(insn, 15, 6) << 8; \
    if (!Check(&S, DecodeMemNM_9_1_Mips_GPRNM32RegClassID(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 479: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 3, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 16, 5); \
    if (!Check(&S, DecodeMemZeroNM(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 480: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 7); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 1) << 11; \
    tmp |= fieldname(insn, 1, 10) << 1; \
    if (!Check(&S, DecodeBranchTargetNM_11(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 481: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 11, 6); \
    if (!Check(&S, DecodeSImmWithOffsetAndScale_32_0_1(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 1) << 11; \
    tmp |= fieldname(insn, 1, 10) << 1; \
    if (!Check(&S, DecodeBranchTargetNM_11(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 482: \
    tmp = fieldname(insn, 21, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 1) << 19; \
    tmp |= fieldname(insn, 2, 10) << 9; \
    tmp |= fieldname(insn, 12, 9) << 0; \
    if (!Check(&S, DecodeSImm32s12(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 483: \
    tmp = fieldname(insn, 37, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 16) << 16; \
    tmp |= fieldname(insn, 16, 16) << 0; \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 484: \
    tmp = fieldname(insn, 37, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 37, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 16) << 16; \
    tmp |= fieldname(insn, 16, 16) << 0; \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 485: \
    tmp = fieldname(insn, 37, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 16) << 16; \
    tmp |= fieldname(insn, 16, 16) << 0; \
    if (!Check(&S, DecodeSImmWithReg_32_0_1_Mips_GP_NM(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    return S; \
  case 486: \
    tmp = fieldname(insn, 37, 5); \
    if (!Check(&S, DecodeGPRNM32RegisterClass(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
    tmp = 0x0; \
    tmp |= fieldname(insn, 0, 16) << 16; \
    tmp |= fieldname(insn, 16, 16) << 0; \
    if (!Check(&S, DecodeAddressPCRelNM_32(MI, tmp, Address, Decoder))) { return MCDisassembler_Fail; } \
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
FieldFromInstruction(fieldFromInstruction_2, uint32_t)
FieldFromInstruction(fieldFromInstruction_8, uint64_t)
DecodeToMCInst(decodeToMCInst_4, fieldFromInstruction_4, uint32_t)
DecodeToMCInst(decodeToMCInst_2, fieldFromInstruction_2, uint32_t)
DecodeToMCInst(decodeToMCInst_8, fieldFromInstruction_8, uint64_t)
DecodeInstruction(decodeInstruction_4, fieldFromInstruction_4, decodeToMCInst_4, uint32_t)
DecodeInstruction(decodeInstruction_2, fieldFromInstruction_2, decodeToMCInst_2, uint32_t)
DecodeInstruction(decodeInstruction_8, fieldFromInstruction_8, decodeToMCInst_8, uint64_t)
