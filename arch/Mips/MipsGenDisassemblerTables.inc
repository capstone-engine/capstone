/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* * Mips Disassembler                                                        *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

/* Capstone Disassembly Engine, http://www.capstone-engine.org */
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

#if 0
// TODO: properly handle this in the future with MIPS1/2 modes
static const uint8_t DecoderTableCOP3_32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 51, 8, 0, // Skip to: 15
/* 7 */       MCD_OPC_CheckPredicate, 1, 40, 0, // Skip to: 51
/* 11 */      MCD_OPC_Decode, 189, 7, 10, // Opcode: LWC3
/* 15 */      MCD_OPC_FilterValue, 55, 8, 0, // Skip to: 27
/* 19 */      MCD_OPC_CheckPredicate, 2, 28, 0, // Skip to: 51
/* 23 */      MCD_OPC_Decode, 139, 7, 10, // Opcode: LDC3
/* 27 */      MCD_OPC_FilterValue, 59, 8, 0, // Skip to: 39
/* 31 */      MCD_OPC_CheckPredicate, 1, 16, 0, // Skip to: 51
/* 35 */      MCD_OPC_Decode, 174, 12, 10, // Opcode: SWC3
/* 39 */      MCD_OPC_FilterValue, 63, 8, 0, // Skip to: 51
/* 43 */      MCD_OPC_CheckPredicate, 2, 4, 0, // Skip to: 51
/* 47 */      MCD_OPC_Decode, 227, 10, 10, // Opcode: SDC3
/* 51 */      MCD_OPC_Fail,
  0
};
#endif

static const uint8_t DecoderTableMicroMips32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 114, 3, // Skip to: 889
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 0, 51, 0, // Skip to: 65
/* 14 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 17 */      MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 29
/* 21 */      MCD_OPC_CheckPredicate, 3, 156, 5, // Skip to: 1461
/* 25 */      MCD_OPC_Decode, 174, 11, 14, // Opcode: SLL_MM
/* 29 */      MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 41
/* 33 */      MCD_OPC_CheckPredicate, 3, 144, 5, // Skip to: 1461
/* 37 */      MCD_OPC_Decode, 241, 11, 14, // Opcode: SRL_MM
/* 41 */      MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 53
/* 45 */      MCD_OPC_CheckPredicate, 3, 132, 5, // Skip to: 1461
/* 49 */      MCD_OPC_Decode, 221, 11, 14, // Opcode: SRA_MM
/* 53 */      MCD_OPC_FilterValue, 3, 124, 5, // Skip to: 1461
/* 57 */      MCD_OPC_CheckPredicate, 3, 120, 5, // Skip to: 1461
/* 61 */      MCD_OPC_Decode, 191, 10, 14, // Opcode: ROTR_MM
/* 65 */      MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 77
/* 69 */      MCD_OPC_CheckPredicate, 3, 108, 5, // Skip to: 1461
/* 73 */      MCD_OPC_Decode, 155, 2, 15, // Opcode: BREAK_MM
/* 77 */      MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 89
/* 81 */      MCD_OPC_CheckPredicate, 3, 96, 5, // Skip to: 1461
/* 85 */      MCD_OPC_Decode, 225, 6, 16, // Opcode: INS_MM
/* 89 */      MCD_OPC_FilterValue, 16, 180, 0, // Skip to: 273
/* 93 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 96 */      MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 108
/* 100 */     MCD_OPC_CheckPredicate, 3, 77, 5, // Skip to: 1461
/* 104 */     MCD_OPC_Decode, 170, 11, 17, // Opcode: SLLV_MM
/* 108 */     MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 120
/* 112 */     MCD_OPC_CheckPredicate, 3, 65, 5, // Skip to: 1461
/* 116 */     MCD_OPC_Decode, 237, 11, 17, // Opcode: SRLV_MM
/* 120 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 132
/* 124 */     MCD_OPC_CheckPredicate, 3, 53, 5, // Skip to: 1461
/* 128 */     MCD_OPC_Decode, 217, 11, 17, // Opcode: SRAV_MM
/* 132 */     MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 144
/* 136 */     MCD_OPC_CheckPredicate, 3, 41, 5, // Skip to: 1461
/* 140 */     MCD_OPC_Decode, 190, 10, 17, // Opcode: ROTRV_MM
/* 144 */     MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 155
/* 148 */     MCD_OPC_CheckPredicate, 3, 29, 5, // Skip to: 1461
/* 152 */     MCD_OPC_Decode, 64, 18, // Opcode: ADD_MM
/* 155 */     MCD_OPC_FilterValue, 5, 7, 0, // Skip to: 166
/* 159 */     MCD_OPC_CheckPredicate, 3, 18, 5, // Skip to: 1461
/* 163 */     MCD_OPC_Decode, 70, 18, // Opcode: ADDu_MM
/* 166 */     MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 178
/* 170 */     MCD_OPC_CheckPredicate, 3, 7, 5, // Skip to: 1461
/* 174 */     MCD_OPC_Decode, 162, 12, 18, // Opcode: SUB_MM
/* 178 */     MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 190
/* 182 */     MCD_OPC_CheckPredicate, 3, 251, 4, // Skip to: 1461
/* 186 */     MCD_OPC_Decode, 164, 12, 18, // Opcode: SUBu_MM
/* 190 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 202
/* 194 */     MCD_OPC_CheckPredicate, 3, 239, 4, // Skip to: 1461
/* 198 */     MCD_OPC_Decode, 178, 9, 18, // Opcode: MUL_MM
/* 202 */     MCD_OPC_FilterValue, 9, 7, 0, // Skip to: 213
/* 206 */     MCD_OPC_CheckPredicate, 3, 227, 4, // Skip to: 1461
/* 210 */     MCD_OPC_Decode, 78, 18, // Opcode: AND_MM
/* 213 */     MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 225
/* 217 */     MCD_OPC_CheckPredicate, 3, 216, 4, // Skip to: 1461
/* 221 */     MCD_OPC_Decode, 224, 9, 18, // Opcode: OR_MM
/* 225 */     MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 237
/* 229 */     MCD_OPC_CheckPredicate, 3, 204, 4, // Skip to: 1461
/* 233 */     MCD_OPC_Decode, 214, 9, 18, // Opcode: NOR_MM
/* 237 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 249
/* 241 */     MCD_OPC_CheckPredicate, 3, 192, 4, // Skip to: 1461
/* 245 */     MCD_OPC_Decode, 165, 13, 18, // Opcode: XOR_MM
/* 249 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 261
/* 253 */     MCD_OPC_CheckPredicate, 3, 180, 4, // Skip to: 1461
/* 257 */     MCD_OPC_Decode, 178, 11, 18, // Opcode: SLT_MM
/* 261 */     MCD_OPC_FilterValue, 14, 172, 4, // Skip to: 1461
/* 265 */     MCD_OPC_CheckPredicate, 3, 168, 4, // Skip to: 1461
/* 269 */     MCD_OPC_Decode, 187, 11, 18, // Opcode: SLTu_MM
/* 273 */     MCD_OPC_FilterValue, 24, 27, 0, // Skip to: 304
/* 277 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 280 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 292
/* 284 */     MCD_OPC_CheckPredicate, 3, 149, 4, // Skip to: 1461
/* 288 */     MCD_OPC_Decode, 214, 8, 19, // Opcode: MOVN_I_MM
/* 292 */     MCD_OPC_FilterValue, 1, 141, 4, // Skip to: 1461
/* 296 */     MCD_OPC_CheckPredicate, 3, 137, 4, // Skip to: 1461
/* 300 */     MCD_OPC_Decode, 234, 8, 19, // Opcode: MOVZ_I_MM
/* 304 */     MCD_OPC_FilterValue, 44, 8, 0, // Skip to: 316
/* 308 */     MCD_OPC_CheckPredicate, 3, 125, 4, // Skip to: 1461
/* 312 */     MCD_OPC_Decode, 139, 5, 20, // Opcode: EXT_MM
/* 316 */     MCD_OPC_FilterValue, 60, 117, 4, // Skip to: 1461
/* 320 */     MCD_OPC_ExtractField, 6, 6,  // Inst{11-6} ...
/* 323 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 335
/* 327 */     MCD_OPC_CheckPredicate, 3, 106, 4, // Skip to: 1461
/* 331 */     MCD_OPC_Decode, 239, 12, 21, // Opcode: TEQ_MM
/* 335 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 347
/* 339 */     MCD_OPC_CheckPredicate, 3, 94, 4, // Skip to: 1461
/* 343 */     MCD_OPC_Decode, 247, 12, 21, // Opcode: TGE_MM
/* 347 */     MCD_OPC_FilterValue, 13, 123, 0, // Skip to: 474
/* 351 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 354 */     MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 372
/* 358 */     MCD_OPC_CheckPredicate, 3, 75, 4, // Skip to: 1461
/* 362 */     MCD_OPC_CheckField, 16, 10, 0, 69, 4, // Skip to: 1461
/* 368 */     MCD_OPC_Decode, 249, 12, 0, // Opcode: TLBP_MM
/* 372 */     MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 390
/* 376 */     MCD_OPC_CheckPredicate, 3, 57, 4, // Skip to: 1461
/* 380 */     MCD_OPC_CheckField, 16, 10, 0, 51, 4, // Skip to: 1461
/* 386 */     MCD_OPC_Decode, 251, 12, 0, // Opcode: TLBR_MM
/* 390 */     MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 408
/* 394 */     MCD_OPC_CheckPredicate, 3, 39, 4, // Skip to: 1461
/* 398 */     MCD_OPC_CheckField, 16, 10, 0, 33, 4, // Skip to: 1461
/* 404 */     MCD_OPC_Decode, 253, 12, 0, // Opcode: TLBWI_MM
/* 408 */     MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 426
/* 412 */     MCD_OPC_CheckPredicate, 3, 21, 4, // Skip to: 1461
/* 416 */     MCD_OPC_CheckField, 16, 10, 0, 15, 4, // Skip to: 1461
/* 422 */     MCD_OPC_Decode, 255, 12, 0, // Opcode: TLBWR_MM
/* 426 */     MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 438
/* 430 */     MCD_OPC_CheckPredicate, 3, 3, 4, // Skip to: 1461
/* 434 */     MCD_OPC_Decode, 158, 13, 22, // Opcode: WAIT_MM
/* 438 */     MCD_OPC_FilterValue, 14, 14, 0, // Skip to: 456
/* 442 */     MCD_OPC_CheckPredicate, 3, 247, 3, // Skip to: 1461
/* 446 */     MCD_OPC_CheckField, 16, 10, 0, 241, 3, // Skip to: 1461
/* 452 */     MCD_OPC_Decode, 155, 4, 0, // Opcode: DERET_MM
/* 456 */     MCD_OPC_FilterValue, 15, 233, 3, // Skip to: 1461
/* 460 */     MCD_OPC_CheckPredicate, 3, 229, 3, // Skip to: 1461
/* 464 */     MCD_OPC_CheckField, 16, 10, 0, 223, 3, // Skip to: 1461
/* 470 */     MCD_OPC_Decode, 251, 4, 0, // Opcode: ERET_MM
/* 474 */     MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 486
/* 478 */     MCD_OPC_CheckPredicate, 3, 211, 3, // Skip to: 1461
/* 482 */     MCD_OPC_Decode, 246, 12, 21, // Opcode: TGEU_MM
/* 486 */     MCD_OPC_FilterValue, 29, 39, 0, // Skip to: 529
/* 490 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 493 */     MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 511
/* 497 */     MCD_OPC_CheckPredicate, 3, 192, 3, // Skip to: 1461
/* 501 */     MCD_OPC_CheckField, 21, 5, 0, 186, 3, // Skip to: 1461
/* 507 */     MCD_OPC_Decode, 173, 4, 23, // Opcode: DI_MM
/* 511 */     MCD_OPC_FilterValue, 5, 178, 3, // Skip to: 1461
/* 515 */     MCD_OPC_CheckPredicate, 3, 174, 3, // Skip to: 1461
/* 519 */     MCD_OPC_CheckField, 21, 5, 0, 168, 3, // Skip to: 1461
/* 525 */     MCD_OPC_Decode, 249, 4, 23, // Opcode: EI_MM
/* 529 */     MCD_OPC_FilterValue, 32, 8, 0, // Skip to: 541
/* 533 */     MCD_OPC_CheckPredicate, 3, 156, 3, // Skip to: 1461
/* 537 */     MCD_OPC_Decode, 134, 13, 21, // Opcode: TLT_MM
/* 541 */     MCD_OPC_FilterValue, 40, 8, 0, // Skip to: 553
/* 545 */     MCD_OPC_CheckPredicate, 3, 144, 3, // Skip to: 1461
/* 549 */     MCD_OPC_Decode, 133, 13, 21, // Opcode: TLTU_MM
/* 553 */     MCD_OPC_FilterValue, 44, 159, 0, // Skip to: 716
/* 557 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 560 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 572
/* 564 */     MCD_OPC_CheckPredicate, 3, 125, 3, // Skip to: 1461
/* 568 */     MCD_OPC_Decode, 236, 10, 24, // Opcode: SEB_MM
/* 572 */     MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 584
/* 576 */     MCD_OPC_CheckPredicate, 3, 113, 3, // Skip to: 1461
/* 580 */     MCD_OPC_Decode, 239, 10, 24, // Opcode: SEH_MM
/* 584 */     MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 596
/* 588 */     MCD_OPC_CheckPredicate, 3, 101, 3, // Skip to: 1461
/* 592 */     MCD_OPC_Decode, 242, 2, 24, // Opcode: CLO_MM
/* 596 */     MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 608
/* 600 */     MCD_OPC_CheckPredicate, 3, 89, 3, // Skip to: 1461
/* 604 */     MCD_OPC_Decode, 133, 3, 24, // Opcode: CLZ_MM
/* 608 */     MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 620
/* 612 */     MCD_OPC_CheckPredicate, 3, 77, 3, // Skip to: 1461
/* 616 */     MCD_OPC_Decode, 161, 13, 24, // Opcode: WSBH_MM
/* 620 */     MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 632
/* 624 */     MCD_OPC_CheckPredicate, 3, 65, 3, // Skip to: 1461
/* 628 */     MCD_OPC_Decode, 170, 9, 25, // Opcode: MULT_MM
/* 632 */     MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 644
/* 636 */     MCD_OPC_CheckPredicate, 3, 53, 3, // Skip to: 1461
/* 640 */     MCD_OPC_Decode, 172, 9, 25, // Opcode: MULTu_MM
/* 644 */     MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 656
/* 648 */     MCD_OPC_CheckPredicate, 3, 41, 3, // Skip to: 1461
/* 652 */     MCD_OPC_Decode, 229, 10, 25, // Opcode: SDIV_MM
/* 656 */     MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 668
/* 660 */     MCD_OPC_CheckPredicate, 3, 29, 3, // Skip to: 1461
/* 664 */     MCD_OPC_Decode, 149, 13, 25, // Opcode: UDIV_MM
/* 668 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 680
/* 672 */     MCD_OPC_CheckPredicate, 3, 17, 3, // Skip to: 1461
/* 676 */     MCD_OPC_Decode, 236, 7, 25, // Opcode: MADD_MM
/* 680 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 692
/* 684 */     MCD_OPC_CheckPredicate, 3, 5, 3, // Skip to: 1461
/* 688 */     MCD_OPC_Decode, 227, 7, 25, // Opcode: MADDU_MM
/* 692 */     MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 704
/* 696 */     MCD_OPC_CheckPredicate, 3, 249, 2, // Skip to: 1461
/* 700 */     MCD_OPC_Decode, 253, 8, 25, // Opcode: MSUB_MM
/* 704 */     MCD_OPC_FilterValue, 15, 241, 2, // Skip to: 1461
/* 708 */     MCD_OPC_CheckPredicate, 3, 237, 2, // Skip to: 1461
/* 712 */     MCD_OPC_Decode, 244, 8, 25, // Opcode: MSUBU_MM
/* 716 */     MCD_OPC_FilterValue, 45, 33, 0, // Skip to: 753
/* 720 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 723 */     MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 741
/* 727 */     MCD_OPC_CheckPredicate, 3, 218, 2, // Skip to: 1461
/* 731 */     MCD_OPC_CheckField, 21, 5, 0, 212, 2, // Skip to: 1461
/* 737 */     MCD_OPC_Decode, 185, 12, 26, // Opcode: SYNC_MM
/* 741 */     MCD_OPC_FilterValue, 8, 204, 2, // Skip to: 1461
/* 745 */     MCD_OPC_CheckPredicate, 3, 200, 2, // Skip to: 1461
/* 749 */     MCD_OPC_Decode, 187, 12, 22, // Opcode: SYSCALL_MM
/* 753 */     MCD_OPC_FilterValue, 48, 8, 0, // Skip to: 765
/* 757 */     MCD_OPC_CheckPredicate, 3, 188, 2, // Skip to: 1461
/* 761 */     MCD_OPC_Decode, 138, 13, 21, // Opcode: TNE_MM
/* 765 */     MCD_OPC_FilterValue, 53, 75, 0, // Skip to: 844
/* 769 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 772 */     MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 790
/* 776 */     MCD_OPC_CheckPredicate, 3, 169, 2, // Skip to: 1461
/* 780 */     MCD_OPC_CheckField, 21, 5, 0, 163, 2, // Skip to: 1461
/* 786 */     MCD_OPC_Decode, 152, 8, 23, // Opcode: MFHI_MM
/* 790 */     MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 808
/* 794 */     MCD_OPC_CheckPredicate, 3, 151, 2, // Skip to: 1461
/* 798 */     MCD_OPC_CheckField, 21, 5, 0, 145, 2, // Skip to: 1461
/* 804 */     MCD_OPC_Decode, 157, 8, 23, // Opcode: MFLO_MM
/* 808 */     MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 826
/* 812 */     MCD_OPC_CheckPredicate, 3, 133, 2, // Skip to: 1461
/* 816 */     MCD_OPC_CheckField, 21, 5, 0, 127, 2, // Skip to: 1461
/* 822 */     MCD_OPC_Decode, 140, 9, 23, // Opcode: MTHI_MM
/* 826 */     MCD_OPC_FilterValue, 3, 119, 2, // Skip to: 1461
/* 830 */     MCD_OPC_CheckPredicate, 3, 115, 2, // Skip to: 1461
/* 834 */     MCD_OPC_CheckField, 21, 5, 0, 109, 2, // Skip to: 1461
/* 840 */     MCD_OPC_Decode, 145, 9, 23, // Opcode: MTLO_MM
/* 844 */     MCD_OPC_FilterValue, 60, 101, 2, // Skip to: 1461
/* 848 */     MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 851 */     MCD_OPC_FilterValue, 0, 22, 0, // Skip to: 877
/* 855 */     MCD_OPC_CheckPredicate, 3, 10, 0, // Skip to: 869
/* 859 */     MCD_OPC_CheckField, 21, 5, 0, 4, 0, // Skip to: 869
/* 865 */     MCD_OPC_Decode, 246, 6, 23, // Opcode: JR_MM
/* 869 */     MCD_OPC_CheckPredicate, 3, 76, 2, // Skip to: 1461
/* 873 */     MCD_OPC_Decode, 235, 6, 24, // Opcode: JALR_MM
/* 877 */     MCD_OPC_FilterValue, 4, 68, 2, // Skip to: 1461
/* 881 */     MCD_OPC_CheckPredicate, 3, 64, 2, // Skip to: 1461
/* 885 */     MCD_OPC_Decode, 233, 6, 24, // Opcode: JALRS_MM
/* 889 */     MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 900
/* 893 */     MCD_OPC_CheckPredicate, 3, 52, 2, // Skip to: 1461
/* 897 */     MCD_OPC_Decode, 66, 27, // Opcode: ADDi_MM
/* 900 */     MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 912
/* 904 */     MCD_OPC_CheckPredicate, 3, 41, 2, // Skip to: 1461
/* 908 */     MCD_OPC_Decode, 132, 7, 28, // Opcode: LBu_MM
/* 912 */     MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 924
/* 916 */     MCD_OPC_CheckPredicate, 3, 29, 2, // Skip to: 1461
/* 920 */     MCD_OPC_Decode, 213, 10, 28, // Opcode: SB_MM
/* 924 */     MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 936
/* 928 */     MCD_OPC_CheckPredicate, 3, 17, 2, // Skip to: 1461
/* 932 */     MCD_OPC_Decode, 129, 7, 28, // Opcode: LB_MM
/* 936 */     MCD_OPC_FilterValue, 12, 7, 0, // Skip to: 947
/* 940 */     MCD_OPC_CheckPredicate, 3, 5, 2, // Skip to: 1461
/* 944 */     MCD_OPC_Decode, 68, 27, // Opcode: ADDiu_MM
/* 947 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 959
/* 951 */     MCD_OPC_CheckPredicate, 3, 250, 1, // Skip to: 1461
/* 955 */     MCD_OPC_Decode, 162, 7, 28, // Opcode: LHu_MM
/* 959 */     MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 971
/* 963 */     MCD_OPC_CheckPredicate, 3, 238, 1, // Skip to: 1461
/* 967 */     MCD_OPC_Decode, 153, 11, 28, // Opcode: SH_MM
/* 971 */     MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 983
/* 975 */     MCD_OPC_CheckPredicate, 3, 226, 1, // Skip to: 1461
/* 979 */     MCD_OPC_Decode, 159, 7, 28, // Opcode: LH_MM
/* 983 */     MCD_OPC_FilterValue, 16, 207, 0, // Skip to: 1194
/* 987 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 990 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1002
/* 994 */     MCD_OPC_CheckPredicate, 3, 207, 1, // Skip to: 1461
/* 998 */     MCD_OPC_Decode, 252, 1, 29, // Opcode: BLTZ_MM
/* 1002 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 1014
/* 1006 */    MCD_OPC_CheckPredicate, 3, 195, 1, // Skip to: 1461
/* 1010 */    MCD_OPC_Decode, 249, 1, 29, // Opcode: BLTZAL_MM
/* 1014 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 1026
/* 1018 */    MCD_OPC_CheckPredicate, 3, 183, 1, // Skip to: 1461
/* 1022 */    MCD_OPC_Decode, 210, 1, 29, // Opcode: BGEZ_MM
/* 1026 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1038
/* 1030 */    MCD_OPC_CheckPredicate, 3, 171, 1, // Skip to: 1461
/* 1034 */    MCD_OPC_Decode, 207, 1, 29, // Opcode: BGEZAL_MM
/* 1038 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 1050
/* 1042 */    MCD_OPC_CheckPredicate, 3, 159, 1, // Skip to: 1461
/* 1046 */    MCD_OPC_Decode, 240, 1, 29, // Opcode: BLEZ_MM
/* 1050 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 1062
/* 1054 */    MCD_OPC_CheckPredicate, 3, 147, 1, // Skip to: 1461
/* 1058 */    MCD_OPC_Decode, 143, 2, 29, // Opcode: BNEZC_MM
/* 1062 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 1074
/* 1066 */    MCD_OPC_CheckPredicate, 3, 135, 1, // Skip to: 1461
/* 1070 */    MCD_OPC_Decode, 216, 1, 29, // Opcode: BGTZ_MM
/* 1074 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 1086
/* 1078 */    MCD_OPC_CheckPredicate, 3, 123, 1, // Skip to: 1461
/* 1082 */    MCD_OPC_Decode, 197, 1, 29, // Opcode: BEQZC_MM
/* 1086 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 1098
/* 1090 */    MCD_OPC_CheckPredicate, 3, 111, 1, // Skip to: 1461
/* 1094 */    MCD_OPC_Decode, 131, 13, 30, // Opcode: TLTI_MM
/* 1098 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 1110
/* 1102 */    MCD_OPC_CheckPredicate, 3, 99, 1, // Skip to: 1461
/* 1106 */    MCD_OPC_Decode, 244, 12, 30, // Opcode: TGEI_MM
/* 1110 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 1122
/* 1114 */    MCD_OPC_CheckPredicate, 3, 87, 1, // Skip to: 1461
/* 1118 */    MCD_OPC_Decode, 130, 13, 30, // Opcode: TLTIU_MM
/* 1122 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1134
/* 1126 */    MCD_OPC_CheckPredicate, 3, 75, 1, // Skip to: 1461
/* 1130 */    MCD_OPC_Decode, 243, 12, 30, // Opcode: TGEIU_MM
/* 1134 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 1146
/* 1138 */    MCD_OPC_CheckPredicate, 3, 63, 1, // Skip to: 1461
/* 1142 */    MCD_OPC_Decode, 137, 13, 30, // Opcode: TNEI_MM
/* 1146 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 1158
/* 1150 */    MCD_OPC_CheckPredicate, 3, 51, 1, // Skip to: 1461
/* 1154 */    MCD_OPC_Decode, 182, 7, 30, // Opcode: LUi_MM
/* 1158 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 1170
/* 1162 */    MCD_OPC_CheckPredicate, 3, 39, 1, // Skip to: 1461
/* 1166 */    MCD_OPC_Decode, 238, 12, 30, // Opcode: TEQI_MM
/* 1170 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 1182
/* 1174 */    MCD_OPC_CheckPredicate, 3, 27, 1, // Skip to: 1461
/* 1178 */    MCD_OPC_Decode, 248, 1, 29, // Opcode: BLTZALS_MM
/* 1182 */    MCD_OPC_FilterValue, 19, 19, 1, // Skip to: 1461
/* 1186 */    MCD_OPC_CheckPredicate, 3, 15, 1, // Skip to: 1461
/* 1190 */    MCD_OPC_Decode, 206, 1, 29, // Opcode: BGEZALS_MM
/* 1194 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 1206
/* 1198 */    MCD_OPC_CheckPredicate, 3, 3, 1, // Skip to: 1461
/* 1202 */    MCD_OPC_Decode, 231, 9, 31, // Opcode: ORi_MM
/* 1206 */    MCD_OPC_FilterValue, 21, 29, 0, // Skip to: 1239
/* 1210 */    MCD_OPC_ExtractField, 0, 13,  // Inst{12-0} ...
/* 1213 */    MCD_OPC_FilterValue, 251, 2, 8, 0, // Skip to: 1226
/* 1218 */    MCD_OPC_CheckPredicate, 3, 239, 0, // Skip to: 1461
/* 1222 */    MCD_OPC_Decode, 202, 8, 32, // Opcode: MOVF_I_MM
/* 1226 */    MCD_OPC_FilterValue, 251, 18, 230, 0, // Skip to: 1461
/* 1231 */    MCD_OPC_CheckPredicate, 3, 226, 0, // Skip to: 1461
/* 1235 */    MCD_OPC_Decode, 222, 8, 32, // Opcode: MOVT_I_MM
/* 1239 */    MCD_OPC_FilterValue, 24, 87, 0, // Skip to: 1330
/* 1243 */    MCD_OPC_ExtractField, 12, 4,  // Inst{15-12} ...
/* 1246 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1258
/* 1250 */    MCD_OPC_CheckPredicate, 3, 207, 0, // Skip to: 1461
/* 1254 */    MCD_OPC_Decode, 192, 7, 33, // Opcode: LWL_MM
/* 1258 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 1270
/* 1262 */    MCD_OPC_CheckPredicate, 3, 195, 0, // Skip to: 1461
/* 1266 */    MCD_OPC_Decode, 196, 7, 33, // Opcode: LWR_MM
/* 1270 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1282
/* 1274 */    MCD_OPC_CheckPredicate, 3, 183, 0, // Skip to: 1461
/* 1278 */    MCD_OPC_Decode, 166, 7, 33, // Opcode: LL_MM
/* 1282 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 1294
/* 1286 */    MCD_OPC_CheckPredicate, 3, 171, 0, // Skip to: 1461
/* 1290 */    MCD_OPC_Decode, 177, 12, 33, // Opcode: SWL_MM
/* 1294 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 1306
/* 1298 */    MCD_OPC_CheckPredicate, 3, 159, 0, // Skip to: 1461
/* 1302 */    MCD_OPC_Decode, 180, 12, 33, // Opcode: SWR_MM
/* 1306 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1318
/* 1310 */    MCD_OPC_CheckPredicate, 3, 147, 0, // Skip to: 1461
/* 1314 */    MCD_OPC_Decode, 217, 10, 33, // Opcode: SC_MM
/* 1318 */    MCD_OPC_FilterValue, 14, 139, 0, // Skip to: 1461
/* 1322 */    MCD_OPC_CheckPredicate, 3, 135, 0, // Skip to: 1461
/* 1326 */    MCD_OPC_Decode, 198, 7, 33, // Opcode: LWU_MM
/* 1330 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 1342
/* 1334 */    MCD_OPC_CheckPredicate, 3, 123, 0, // Skip to: 1461
/* 1338 */    MCD_OPC_Decode, 172, 13, 31, // Opcode: XORi_MM
/* 1342 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 1354
/* 1346 */    MCD_OPC_CheckPredicate, 3, 111, 0, // Skip to: 1461
/* 1350 */    MCD_OPC_Decode, 236, 6, 34, // Opcode: JALS_MM
/* 1354 */    MCD_OPC_FilterValue, 36, 8, 0, // Skip to: 1366
/* 1358 */    MCD_OPC_CheckPredicate, 3, 99, 0, // Skip to: 1461
/* 1362 */    MCD_OPC_Decode, 181, 11, 27, // Opcode: SLTi_MM
/* 1366 */    MCD_OPC_FilterValue, 37, 8, 0, // Skip to: 1378
/* 1370 */    MCD_OPC_CheckPredicate, 3, 87, 0, // Skip to: 1461
/* 1374 */    MCD_OPC_Decode, 198, 1, 35, // Opcode: BEQ_MM
/* 1378 */    MCD_OPC_FilterValue, 44, 8, 0, // Skip to: 1390
/* 1382 */    MCD_OPC_CheckPredicate, 3, 75, 0, // Skip to: 1461
/* 1386 */    MCD_OPC_Decode, 184, 11, 27, // Opcode: SLTiu_MM
/* 1390 */    MCD_OPC_FilterValue, 45, 8, 0, // Skip to: 1402
/* 1394 */    MCD_OPC_CheckPredicate, 3, 63, 0, // Skip to: 1461
/* 1398 */    MCD_OPC_Decode, 144, 2, 35, // Opcode: BNE_MM
/* 1402 */    MCD_OPC_FilterValue, 52, 7, 0, // Skip to: 1413
/* 1406 */    MCD_OPC_CheckPredicate, 3, 51, 0, // Skip to: 1461
/* 1410 */    MCD_OPC_Decode, 85, 31, // Opcode: ANDi_MM
/* 1413 */    MCD_OPC_FilterValue, 53, 8, 0, // Skip to: 1425
/* 1417 */    MCD_OPC_CheckPredicate, 3, 40, 0, // Skip to: 1461
/* 1421 */    MCD_OPC_Decode, 247, 6, 34, // Opcode: J_MM
/* 1425 */    MCD_OPC_FilterValue, 61, 8, 0, // Skip to: 1437
/* 1429 */    MCD_OPC_CheckPredicate, 3, 28, 0, // Skip to: 1461
/* 1433 */    MCD_OPC_Decode, 238, 6, 34, // Opcode: JAL_MM
/* 1437 */    MCD_OPC_FilterValue, 62, 8, 0, // Skip to: 1449
/* 1441 */    MCD_OPC_CheckPredicate, 3, 16, 0, // Skip to: 1461
/* 1445 */    MCD_OPC_Decode, 183, 12, 28, // Opcode: SW_MM
/* 1449 */    MCD_OPC_FilterValue, 63, 8, 0, // Skip to: 1461
/* 1453 */    MCD_OPC_CheckPredicate, 3, 4, 0, // Skip to: 1461
/* 1457 */    MCD_OPC_Decode, 202, 7, 28, // Opcode: LW_MM
/* 1461 */    MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMips32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 173, 3, // Skip to: 948
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 0, 54, 0, // Skip to: 68
/* 14 */      MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 17 */      MCD_OPC_FilterValue, 0, 22, 52, // Skip to: 13355
/* 21 */      MCD_OPC_ExtractField, 6, 15,  // Inst{20-6} ...
/* 24 */      MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 36
/* 28 */      MCD_OPC_CheckPredicate, 1, 28, 0, // Skip to: 60
/* 32 */      MCD_OPC_Decode, 243, 11, 0, // Opcode: SSNOP
/* 36 */      MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 48
/* 40 */      MCD_OPC_CheckPredicate, 1, 16, 0, // Skip to: 60
/* 44 */      MCD_OPC_Decode, 247, 4, 0, // Opcode: EHB
/* 48 */      MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 60
/* 52 */      MCD_OPC_CheckPredicate, 4, 4, 0, // Skip to: 60
/* 56 */      MCD_OPC_Decode, 234, 9, 0, // Opcode: PAUSE
/* 60 */      MCD_OPC_CheckPredicate, 1, 235, 51, // Skip to: 13355
/* 64 */      MCD_OPC_Decode, 162, 11, 36, // Opcode: SLL
/* 68 */      MCD_OPC_FilterValue, 1, 39, 0, // Skip to: 111
/* 72 */      MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 75 */      MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 93
/* 79 */      MCD_OPC_CheckPredicate, 5, 216, 51, // Skip to: 13355
/* 83 */      MCD_OPC_CheckField, 6, 5, 0, 210, 51, // Skip to: 13355
/* 89 */      MCD_OPC_Decode, 200, 8, 37, // Opcode: MOVF_I
/* 93 */      MCD_OPC_FilterValue, 1, 202, 51, // Skip to: 13355
/* 97 */      MCD_OPC_CheckPredicate, 5, 198, 51, // Skip to: 13355
/* 101 */     MCD_OPC_CheckField, 6, 5, 0, 192, 51, // Skip to: 13355
/* 107 */     MCD_OPC_Decode, 220, 8, 37, // Opcode: MOVT_I
/* 111 */     MCD_OPC_FilterValue, 2, 27, 0, // Skip to: 142
/* 115 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 118 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 130
/* 122 */     MCD_OPC_CheckPredicate, 1, 173, 51, // Skip to: 13355
/* 126 */     MCD_OPC_Decode, 223, 11, 36, // Opcode: SRL
/* 130 */     MCD_OPC_FilterValue, 1, 165, 51, // Skip to: 13355
/* 134 */     MCD_OPC_CheckPredicate, 4, 161, 51, // Skip to: 13355
/* 138 */     MCD_OPC_Decode, 188, 10, 36, // Opcode: ROTR
/* 142 */     MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 160
/* 146 */     MCD_OPC_CheckPredicate, 1, 149, 51, // Skip to: 13355
/* 150 */     MCD_OPC_CheckField, 21, 5, 0, 143, 51, // Skip to: 13355
/* 156 */     MCD_OPC_Decode, 203, 11, 36, // Opcode: SRA
/* 160 */     MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 178
/* 164 */     MCD_OPC_CheckPredicate, 1, 131, 51, // Skip to: 13355
/* 168 */     MCD_OPC_CheckField, 6, 5, 0, 125, 51, // Skip to: 13355
/* 174 */     MCD_OPC_Decode, 169, 11, 18, // Opcode: SLLV
/* 178 */     MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 196
/* 182 */     MCD_OPC_CheckPredicate, 6, 113, 51, // Skip to: 13355
/* 186 */     MCD_OPC_CheckField, 8, 3, 0, 107, 51, // Skip to: 13355
/* 192 */     MCD_OPC_Decode, 175, 7, 38, // Opcode: LSA
/* 196 */     MCD_OPC_FilterValue, 6, 27, 0, // Skip to: 227
/* 200 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 203 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 215
/* 207 */     MCD_OPC_CheckPredicate, 1, 88, 51, // Skip to: 13355
/* 211 */     MCD_OPC_Decode, 236, 11, 18, // Opcode: SRLV
/* 215 */     MCD_OPC_FilterValue, 1, 80, 51, // Skip to: 13355
/* 219 */     MCD_OPC_CheckPredicate, 4, 76, 51, // Skip to: 13355
/* 223 */     MCD_OPC_Decode, 189, 10, 18, // Opcode: ROTRV
/* 227 */     MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 245
/* 231 */     MCD_OPC_CheckPredicate, 1, 64, 51, // Skip to: 13355
/* 235 */     MCD_OPC_CheckField, 6, 5, 0, 58, 51, // Skip to: 13355
/* 241 */     MCD_OPC_Decode, 216, 11, 18, // Opcode: SRAV
/* 245 */     MCD_OPC_FilterValue, 8, 27, 0, // Skip to: 276
/* 249 */     MCD_OPC_ExtractField, 6, 15,  // Inst{20-6} ...
/* 252 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 264
/* 256 */     MCD_OPC_CheckPredicate, 1, 39, 51, // Skip to: 13355
/* 260 */     MCD_OPC_Decode, 241, 6, 39, // Opcode: JR
/* 264 */     MCD_OPC_FilterValue, 16, 31, 51, // Skip to: 13355
/* 268 */     MCD_OPC_CheckPredicate, 7, 27, 51, // Skip to: 13355
/* 272 */     MCD_OPC_Decode, 244, 6, 39, // Opcode: JR_HB
/* 276 */     MCD_OPC_FilterValue, 9, 39, 0, // Skip to: 319
/* 280 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 283 */     MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 301
/* 287 */     MCD_OPC_CheckPredicate, 8, 8, 51, // Skip to: 13355
/* 291 */     MCD_OPC_CheckField, 16, 5, 0, 2, 51, // Skip to: 13355
/* 297 */     MCD_OPC_Decode, 228, 6, 40, // Opcode: JALR
/* 301 */     MCD_OPC_FilterValue, 16, 250, 50, // Skip to: 13355
/* 305 */     MCD_OPC_CheckPredicate, 9, 246, 50, // Skip to: 13355
/* 309 */     MCD_OPC_CheckField, 16, 5, 0, 240, 50, // Skip to: 13355
/* 315 */     MCD_OPC_Decode, 234, 6, 40, // Opcode: JALR_HB
/* 319 */     MCD_OPC_FilterValue, 10, 14, 0, // Skip to: 337
/* 323 */     MCD_OPC_CheckPredicate, 5, 228, 50, // Skip to: 13355
/* 327 */     MCD_OPC_CheckField, 6, 5, 0, 222, 50, // Skip to: 13355
/* 333 */     MCD_OPC_Decode, 232, 8, 41, // Opcode: MOVZ_I_I
/* 337 */     MCD_OPC_FilterValue, 11, 14, 0, // Skip to: 355
/* 341 */     MCD_OPC_CheckPredicate, 5, 210, 50, // Skip to: 13355
/* 345 */     MCD_OPC_CheckField, 6, 5, 0, 204, 50, // Skip to: 13355
/* 351 */     MCD_OPC_Decode, 212, 8, 41, // Opcode: MOVN_I_I
/* 355 */     MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 367
/* 359 */     MCD_OPC_CheckPredicate, 1, 192, 50, // Skip to: 13355
/* 363 */     MCD_OPC_Decode, 186, 12, 42, // Opcode: SYSCALL
/* 367 */     MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 379
/* 371 */     MCD_OPC_CheckPredicate, 1, 180, 50, // Skip to: 13355
/* 375 */     MCD_OPC_Decode, 154, 2, 15, // Opcode: BREAK
/* 379 */     MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 391
/* 383 */     MCD_OPC_CheckPredicate, 9, 168, 50, // Skip to: 13355
/* 387 */     MCD_OPC_Decode, 184, 12, 43, // Opcode: SYNC
/* 391 */     MCD_OPC_FilterValue, 16, 43, 0, // Skip to: 438
/* 395 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 398 */     MCD_OPC_FilterValue, 0, 153, 50, // Skip to: 13355
/* 402 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 405 */     MCD_OPC_FilterValue, 0, 146, 50, // Skip to: 13355
/* 409 */     MCD_OPC_ExtractField, 23, 3,  // Inst{25-23} ...
/* 412 */     MCD_OPC_FilterValue, 0, 139, 50, // Skip to: 13355
/* 416 */     MCD_OPC_CheckPredicate, 10, 10, 0, // Skip to: 430
/* 420 */     MCD_OPC_CheckField, 21, 2, 0, 4, 0, // Skip to: 430
/* 426 */     MCD_OPC_Decode, 148, 8, 44, // Opcode: MFHI
/* 430 */     MCD_OPC_CheckPredicate, 11, 121, 50, // Skip to: 13355
/* 434 */     MCD_OPC_Decode, 151, 8, 45, // Opcode: MFHI_DSP
/* 438 */     MCD_OPC_FilterValue, 17, 36, 0, // Skip to: 478
/* 442 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 445 */     MCD_OPC_FilterValue, 0, 106, 50, // Skip to: 13355
/* 449 */     MCD_OPC_ExtractField, 13, 8,  // Inst{20-13} ...
/* 452 */     MCD_OPC_FilterValue, 0, 99, 50, // Skip to: 13355
/* 456 */     MCD_OPC_CheckPredicate, 12, 10, 0, // Skip to: 470
/* 460 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 470
/* 466 */     MCD_OPC_Decode, 137, 9, 39, // Opcode: MTHI
/* 470 */     MCD_OPC_CheckPredicate, 11, 81, 50, // Skip to: 13355
/* 474 */     MCD_OPC_Decode, 139, 9, 46, // Opcode: MTHI_DSP
/* 478 */     MCD_OPC_FilterValue, 18, 43, 0, // Skip to: 525
/* 482 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 485 */     MCD_OPC_FilterValue, 0, 66, 50, // Skip to: 13355
/* 489 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 492 */     MCD_OPC_FilterValue, 0, 59, 50, // Skip to: 13355
/* 496 */     MCD_OPC_ExtractField, 23, 3,  // Inst{25-23} ...
/* 499 */     MCD_OPC_FilterValue, 0, 52, 50, // Skip to: 13355
/* 503 */     MCD_OPC_CheckPredicate, 10, 10, 0, // Skip to: 517
/* 507 */     MCD_OPC_CheckField, 21, 2, 0, 4, 0, // Skip to: 517
/* 513 */     MCD_OPC_Decode, 153, 8, 44, // Opcode: MFLO
/* 517 */     MCD_OPC_CheckPredicate, 11, 34, 50, // Skip to: 13355
/* 521 */     MCD_OPC_Decode, 156, 8, 45, // Opcode: MFLO_DSP
/* 525 */     MCD_OPC_FilterValue, 19, 36, 0, // Skip to: 565
/* 529 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 532 */     MCD_OPC_FilterValue, 0, 19, 50, // Skip to: 13355
/* 536 */     MCD_OPC_ExtractField, 13, 8,  // Inst{20-13} ...
/* 539 */     MCD_OPC_FilterValue, 0, 12, 50, // Skip to: 13355
/* 543 */     MCD_OPC_CheckPredicate, 12, 10, 0, // Skip to: 557
/* 547 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 557
/* 553 */     MCD_OPC_Decode, 142, 9, 39, // Opcode: MTLO
/* 557 */     MCD_OPC_CheckPredicate, 11, 250, 49, // Skip to: 13355
/* 561 */     MCD_OPC_Decode, 144, 9, 47, // Opcode: MTLO_DSP
/* 565 */     MCD_OPC_FilterValue, 21, 14, 0, // Skip to: 583
/* 569 */     MCD_OPC_CheckPredicate, 13, 238, 49, // Skip to: 13355
/* 573 */     MCD_OPC_CheckField, 8, 3, 0, 232, 49, // Skip to: 13355
/* 579 */     MCD_OPC_Decode, 174, 4, 48, // Opcode: DLSA
/* 583 */     MCD_OPC_FilterValue, 24, 36, 0, // Skip to: 623
/* 587 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 590 */     MCD_OPC_FilterValue, 0, 217, 49, // Skip to: 13355
/* 594 */     MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 597 */     MCD_OPC_FilterValue, 0, 210, 49, // Skip to: 13355
/* 601 */     MCD_OPC_CheckPredicate, 12, 10, 0, // Skip to: 615
/* 605 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 615
/* 611 */     MCD_OPC_Decode, 167, 9, 24, // Opcode: MULT
/* 615 */     MCD_OPC_CheckPredicate, 11, 192, 49, // Skip to: 13355
/* 619 */     MCD_OPC_Decode, 169, 9, 49, // Opcode: MULT_DSP
/* 623 */     MCD_OPC_FilterValue, 25, 36, 0, // Skip to: 663
/* 627 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 630 */     MCD_OPC_FilterValue, 0, 177, 49, // Skip to: 13355
/* 634 */     MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 637 */     MCD_OPC_FilterValue, 0, 170, 49, // Skip to: 13355
/* 641 */     MCD_OPC_CheckPredicate, 12, 10, 0, // Skip to: 655
/* 645 */     MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 655
/* 651 */     MCD_OPC_Decode, 171, 9, 24, // Opcode: MULTu
/* 655 */     MCD_OPC_CheckPredicate, 11, 152, 49, // Skip to: 13355
/* 659 */     MCD_OPC_Decode, 168, 9, 49, // Opcode: MULTU_DSP
/* 663 */     MCD_OPC_FilterValue, 26, 14, 0, // Skip to: 681
/* 667 */     MCD_OPC_CheckPredicate, 12, 140, 49, // Skip to: 13355
/* 671 */     MCD_OPC_CheckField, 6, 10, 0, 134, 49, // Skip to: 13355
/* 677 */     MCD_OPC_Decode, 228, 10, 24, // Opcode: SDIV
/* 681 */     MCD_OPC_FilterValue, 27, 14, 0, // Skip to: 699
/* 685 */     MCD_OPC_CheckPredicate, 12, 122, 49, // Skip to: 13355
/* 689 */     MCD_OPC_CheckField, 6, 10, 0, 116, 49, // Skip to: 13355
/* 695 */     MCD_OPC_Decode, 148, 13, 24, // Opcode: UDIV
/* 699 */     MCD_OPC_FilterValue, 32, 13, 0, // Skip to: 716
/* 703 */     MCD_OPC_CheckPredicate, 1, 104, 49, // Skip to: 13355
/* 707 */     MCD_OPC_CheckField, 6, 5, 0, 98, 49, // Skip to: 13355
/* 713 */     MCD_OPC_Decode, 23, 17, // Opcode: ADD
/* 716 */     MCD_OPC_FilterValue, 33, 13, 0, // Skip to: 733
/* 720 */     MCD_OPC_CheckPredicate, 1, 87, 49, // Skip to: 13355
/* 724 */     MCD_OPC_CheckField, 6, 5, 0, 81, 49, // Skip to: 13355
/* 730 */     MCD_OPC_Decode, 69, 17, // Opcode: ADDu
/* 733 */     MCD_OPC_FilterValue, 34, 14, 0, // Skip to: 751
/* 737 */     MCD_OPC_CheckPredicate, 1, 70, 49, // Skip to: 13355
/* 741 */     MCD_OPC_CheckField, 6, 5, 0, 64, 49, // Skip to: 13355
/* 747 */     MCD_OPC_Decode, 252, 11, 17, // Opcode: SUB
/* 751 */     MCD_OPC_FilterValue, 35, 14, 0, // Skip to: 769
/* 755 */     MCD_OPC_CheckPredicate, 1, 52, 49, // Skip to: 13355
/* 759 */     MCD_OPC_CheckField, 6, 5, 0, 46, 49, // Skip to: 13355
/* 765 */     MCD_OPC_Decode, 163, 12, 17, // Opcode: SUBu
/* 769 */     MCD_OPC_FilterValue, 36, 13, 0, // Skip to: 786
/* 773 */     MCD_OPC_CheckPredicate, 1, 34, 49, // Skip to: 13355
/* 777 */     MCD_OPC_CheckField, 6, 5, 0, 28, 49, // Skip to: 13355
/* 783 */     MCD_OPC_Decode, 75, 17, // Opcode: AND
/* 786 */     MCD_OPC_FilterValue, 37, 14, 0, // Skip to: 804
/* 790 */     MCD_OPC_CheckPredicate, 1, 17, 49, // Skip to: 13355
/* 794 */     MCD_OPC_CheckField, 6, 5, 0, 11, 49, // Skip to: 13355
/* 800 */     MCD_OPC_Decode, 221, 9, 17, // Opcode: OR
/* 804 */     MCD_OPC_FilterValue, 38, 14, 0, // Skip to: 822
/* 808 */     MCD_OPC_CheckPredicate, 1, 255, 48, // Skip to: 13355
/* 812 */     MCD_OPC_CheckField, 6, 5, 0, 249, 48, // Skip to: 13355
/* 818 */     MCD_OPC_Decode, 162, 13, 17, // Opcode: XOR
/* 822 */     MCD_OPC_FilterValue, 39, 14, 0, // Skip to: 840
/* 826 */     MCD_OPC_CheckPredicate, 1, 237, 48, // Skip to: 13355
/* 830 */     MCD_OPC_CheckField, 6, 5, 0, 231, 48, // Skip to: 13355
/* 836 */     MCD_OPC_Decode, 211, 9, 17, // Opcode: NOR
/* 840 */     MCD_OPC_FilterValue, 42, 14, 0, // Skip to: 858
/* 844 */     MCD_OPC_CheckPredicate, 1, 219, 48, // Skip to: 13355
/* 848 */     MCD_OPC_CheckField, 6, 5, 0, 213, 48, // Skip to: 13355
/* 854 */     MCD_OPC_Decode, 176, 11, 17, // Opcode: SLT
/* 858 */     MCD_OPC_FilterValue, 43, 14, 0, // Skip to: 876
/* 862 */     MCD_OPC_CheckPredicate, 1, 201, 48, // Skip to: 13355
/* 866 */     MCD_OPC_CheckField, 6, 5, 0, 195, 48, // Skip to: 13355
/* 872 */     MCD_OPC_Decode, 185, 11, 17, // Opcode: SLTu
/* 876 */     MCD_OPC_FilterValue, 48, 8, 0, // Skip to: 888
/* 880 */     MCD_OPC_CheckPredicate, 2, 183, 48, // Skip to: 13355
/* 884 */     MCD_OPC_Decode, 240, 12, 50, // Opcode: TGE
/* 888 */     MCD_OPC_FilterValue, 49, 8, 0, // Skip to: 900
/* 892 */     MCD_OPC_CheckPredicate, 2, 171, 48, // Skip to: 13355
/* 896 */     MCD_OPC_Decode, 245, 12, 50, // Opcode: TGEU
/* 900 */     MCD_OPC_FilterValue, 50, 8, 0, // Skip to: 912
/* 904 */     MCD_OPC_CheckPredicate, 2, 159, 48, // Skip to: 13355
/* 908 */     MCD_OPC_Decode, 128, 13, 50, // Opcode: TLT
/* 912 */     MCD_OPC_FilterValue, 51, 8, 0, // Skip to: 924
/* 916 */     MCD_OPC_CheckPredicate, 2, 147, 48, // Skip to: 13355
/* 920 */     MCD_OPC_Decode, 132, 13, 50, // Opcode: TLTU
/* 924 */     MCD_OPC_FilterValue, 52, 8, 0, // Skip to: 936
/* 928 */     MCD_OPC_CheckPredicate, 2, 135, 48, // Skip to: 13355
/* 932 */     MCD_OPC_Decode, 236, 12, 50, // Opcode: TEQ
/* 936 */     MCD_OPC_FilterValue, 54, 127, 48, // Skip to: 13355
/* 940 */     MCD_OPC_CheckPredicate, 2, 123, 48, // Skip to: 13355
/* 944 */     MCD_OPC_Decode, 135, 13, 50, // Opcode: TNE
/* 948 */     MCD_OPC_FilterValue, 1, 189, 0, // Skip to: 1141
/* 952 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 955 */     MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 967
/* 959 */     MCD_OPC_CheckPredicate, 1, 104, 48, // Skip to: 13355
/* 963 */     MCD_OPC_Decode, 243, 1, 51, // Opcode: BLTZ
/* 967 */     MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 979
/* 971 */     MCD_OPC_CheckPredicate, 1, 92, 48, // Skip to: 13355
/* 975 */     MCD_OPC_Decode, 201, 1, 51, // Opcode: BGEZ
/* 979 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 991
/* 983 */     MCD_OPC_CheckPredicate, 1, 80, 48, // Skip to: 13355
/* 987 */     MCD_OPC_Decode, 251, 1, 51, // Opcode: BLTZL
/* 991 */     MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1003
/* 995 */     MCD_OPC_CheckPredicate, 1, 68, 48, // Skip to: 13355
/* 999 */     MCD_OPC_Decode, 209, 1, 51, // Opcode: BGEZL
/* 1003 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 1015
/* 1007 */    MCD_OPC_CheckPredicate, 14, 56, 48, // Skip to: 13355
/* 1011 */    MCD_OPC_Decode, 241, 12, 52, // Opcode: TGEI
/* 1015 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 1027
/* 1019 */    MCD_OPC_CheckPredicate, 14, 44, 48, // Skip to: 13355
/* 1023 */    MCD_OPC_Decode, 242, 12, 52, // Opcode: TGEIU
/* 1027 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 1039
/* 1031 */    MCD_OPC_CheckPredicate, 14, 32, 48, // Skip to: 13355
/* 1035 */    MCD_OPC_Decode, 129, 13, 52, // Opcode: TLTI
/* 1039 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1051
/* 1043 */    MCD_OPC_CheckPredicate, 14, 20, 48, // Skip to: 13355
/* 1047 */    MCD_OPC_Decode, 147, 13, 52, // Opcode: TTLTIU
/* 1051 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 1063
/* 1055 */    MCD_OPC_CheckPredicate, 14, 8, 48, // Skip to: 13355
/* 1059 */    MCD_OPC_Decode, 237, 12, 52, // Opcode: TEQI
/* 1063 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 1075
/* 1067 */    MCD_OPC_CheckPredicate, 14, 252, 47, // Skip to: 13355
/* 1071 */    MCD_OPC_Decode, 136, 13, 52, // Opcode: TNEI
/* 1075 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 1087
/* 1079 */    MCD_OPC_CheckPredicate, 12, 240, 47, // Skip to: 13355
/* 1083 */    MCD_OPC_Decode, 245, 1, 51, // Opcode: BLTZAL
/* 1087 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 1099
/* 1091 */    MCD_OPC_CheckPredicate, 12, 228, 47, // Skip to: 13355
/* 1095 */    MCD_OPC_Decode, 203, 1, 51, // Opcode: BGEZAL
/* 1099 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 1111
/* 1103 */    MCD_OPC_CheckPredicate, 1, 216, 47, // Skip to: 13355
/* 1107 */    MCD_OPC_Decode, 247, 1, 51, // Opcode: BLTZALL
/* 1111 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 1123
/* 1115 */    MCD_OPC_CheckPredicate, 1, 204, 47, // Skip to: 13355
/* 1119 */    MCD_OPC_Decode, 205, 1, 51, // Opcode: BGEZALL
/* 1123 */    MCD_OPC_FilterValue, 28, 196, 47, // Skip to: 13355
/* 1127 */    MCD_OPC_CheckPredicate, 11, 192, 47, // Skip to: 13355
/* 1131 */    MCD_OPC_CheckField, 21, 5, 0, 186, 47, // Skip to: 13355
/* 1137 */    MCD_OPC_Decode, 152, 2, 53, // Opcode: BPOSGE32
/* 1141 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 1153
/* 1145 */    MCD_OPC_CheckPredicate, 9, 174, 47, // Skip to: 13355
/* 1149 */    MCD_OPC_Decode, 226, 6, 54, // Opcode: J
/* 1153 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1165
/* 1157 */    MCD_OPC_CheckPredicate, 1, 162, 47, // Skip to: 13355
/* 1161 */    MCD_OPC_Decode, 227, 6, 54, // Opcode: JAL
/* 1165 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 1177
/* 1169 */    MCD_OPC_CheckPredicate, 1, 150, 47, // Skip to: 13355
/* 1173 */    MCD_OPC_Decode, 191, 1, 55, // Opcode: BEQ
/* 1177 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 1189
/* 1181 */    MCD_OPC_CheckPredicate, 1, 138, 47, // Skip to: 13355
/* 1185 */    MCD_OPC_Decode, 129, 2, 55, // Opcode: BNE
/* 1189 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 1207
/* 1193 */    MCD_OPC_CheckPredicate, 1, 126, 47, // Skip to: 13355
/* 1197 */    MCD_OPC_CheckField, 16, 5, 0, 120, 47, // Skip to: 13355
/* 1203 */    MCD_OPC_Decode, 235, 1, 51, // Opcode: BLEZ
/* 1207 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 1225
/* 1211 */    MCD_OPC_CheckPredicate, 1, 108, 47, // Skip to: 13355
/* 1215 */    MCD_OPC_CheckField, 16, 5, 0, 102, 47, // Skip to: 13355
/* 1221 */    MCD_OPC_Decode, 211, 1, 51, // Opcode: BGTZ
/* 1225 */    MCD_OPC_FilterValue, 8, 7, 0, // Skip to: 1236
/* 1229 */    MCD_OPC_CheckPredicate, 12, 90, 47, // Skip to: 13355
/* 1233 */    MCD_OPC_Decode, 65, 56, // Opcode: ADDi
/* 1236 */    MCD_OPC_FilterValue, 9, 7, 0, // Skip to: 1247
/* 1240 */    MCD_OPC_CheckPredicate, 1, 79, 47, // Skip to: 13355
/* 1244 */    MCD_OPC_Decode, 67, 56, // Opcode: ADDiu
/* 1247 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 1259
/* 1251 */    MCD_OPC_CheckPredicate, 1, 68, 47, // Skip to: 13355
/* 1255 */    MCD_OPC_Decode, 179, 11, 56, // Opcode: SLTi
/* 1259 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1271
/* 1263 */    MCD_OPC_CheckPredicate, 1, 56, 47, // Skip to: 13355
/* 1267 */    MCD_OPC_Decode, 182, 11, 56, // Opcode: SLTiu
/* 1271 */    MCD_OPC_FilterValue, 12, 7, 0, // Skip to: 1282
/* 1275 */    MCD_OPC_CheckPredicate, 1, 44, 47, // Skip to: 13355
/* 1279 */    MCD_OPC_Decode, 83, 57, // Opcode: ANDi
/* 1282 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 1294
/* 1286 */    MCD_OPC_CheckPredicate, 1, 33, 47, // Skip to: 13355
/* 1290 */    MCD_OPC_Decode, 229, 9, 57, // Opcode: ORi
/* 1294 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 1306
/* 1298 */    MCD_OPC_CheckPredicate, 1, 21, 47, // Skip to: 13355
/* 1302 */    MCD_OPC_Decode, 170, 13, 57, // Opcode: XORi
/* 1306 */    MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 1324
/* 1310 */    MCD_OPC_CheckPredicate, 1, 9, 47, // Skip to: 13355
/* 1314 */    MCD_OPC_CheckField, 21, 5, 0, 3, 47, // Skip to: 13355
/* 1320 */    MCD_OPC_Decode, 180, 7, 30, // Opcode: LUi
/* 1324 */    MCD_OPC_FilterValue, 16, 220, 0, // Skip to: 1548
/* 1328 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1331 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 1349
/* 1335 */    MCD_OPC_CheckPredicate, 9, 240, 46, // Skip to: 13355
/* 1339 */    MCD_OPC_CheckField, 3, 8, 0, 234, 46, // Skip to: 13355
/* 1345 */    MCD_OPC_Decode, 141, 8, 58, // Opcode: MFC0
/* 1349 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 1367
/* 1353 */    MCD_OPC_CheckPredicate, 9, 222, 46, // Skip to: 13355
/* 1357 */    MCD_OPC_CheckField, 3, 8, 0, 216, 46, // Skip to: 13355
/* 1363 */    MCD_OPC_Decode, 130, 9, 58, // Opcode: MTC0
/* 1367 */    MCD_OPC_FilterValue, 8, 51, 0, // Skip to: 1422
/* 1371 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1374 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1386
/* 1378 */    MCD_OPC_CheckPredicate, 12, 197, 46, // Skip to: 13355
/* 1382 */    MCD_OPC_Decode, 161, 1, 59, // Opcode: BC0F
/* 1386 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 1398
/* 1390 */    MCD_OPC_CheckPredicate, 12, 185, 46, // Skip to: 13355
/* 1394 */    MCD_OPC_Decode, 163, 1, 59, // Opcode: BC0T
/* 1398 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 1410
/* 1402 */    MCD_OPC_CheckPredicate, 12, 173, 46, // Skip to: 13355
/* 1406 */    MCD_OPC_Decode, 162, 1, 59, // Opcode: BC0FL
/* 1410 */    MCD_OPC_FilterValue, 3, 165, 46, // Skip to: 13355
/* 1414 */    MCD_OPC_CheckPredicate, 12, 161, 46, // Skip to: 13355
/* 1418 */    MCD_OPC_Decode, 164, 1, 59, // Opcode: BC0TL
/* 1422 */    MCD_OPC_FilterValue, 11, 31, 0, // Skip to: 1457
/* 1426 */    MCD_OPC_ExtractField, 0, 16,  // Inst{15-0} ...
/* 1429 */    MCD_OPC_FilterValue, 128, 192, 1, 8, 0, // Skip to: 1443
/* 1435 */    MCD_OPC_CheckPredicate, 4, 140, 46, // Skip to: 13355
/* 1439 */    MCD_OPC_Decode, 159, 4, 23, // Opcode: DI
/* 1443 */    MCD_OPC_FilterValue, 160, 192, 1, 130, 46, // Skip to: 13355
/* 1449 */    MCD_OPC_CheckPredicate, 4, 126, 46, // Skip to: 13355
/* 1453 */    MCD_OPC_Decode, 248, 4, 23, // Opcode: EI
/* 1457 */    MCD_OPC_FilterValue, 16, 118, 46, // Skip to: 13355
/* 1461 */    MCD_OPC_ExtractField, 0, 21,  // Inst{20-0} ...
/* 1464 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 1476
/* 1468 */    MCD_OPC_CheckPredicate, 1, 107, 46, // Skip to: 13355
/* 1472 */    MCD_OPC_Decode, 250, 12, 0, // Opcode: TLBR
/* 1476 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 1488
/* 1480 */    MCD_OPC_CheckPredicate, 1, 95, 46, // Skip to: 13355
/* 1484 */    MCD_OPC_Decode, 252, 12, 0, // Opcode: TLBWI
/* 1488 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 1500
/* 1492 */    MCD_OPC_CheckPredicate, 1, 83, 46, // Skip to: 13355
/* 1496 */    MCD_OPC_Decode, 254, 12, 0, // Opcode: TLBWR
/* 1500 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 1512
/* 1504 */    MCD_OPC_CheckPredicate, 1, 71, 46, // Skip to: 13355
/* 1508 */    MCD_OPC_Decode, 248, 12, 0, // Opcode: TLBP
/* 1512 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 1524
/* 1516 */    MCD_OPC_CheckPredicate, 15, 59, 46, // Skip to: 13355
/* 1520 */    MCD_OPC_Decode, 250, 4, 0, // Opcode: ERET
/* 1524 */    MCD_OPC_FilterValue, 31, 8, 0, // Skip to: 1536
/* 1528 */    MCD_OPC_CheckPredicate, 9, 47, 46, // Skip to: 13355
/* 1532 */    MCD_OPC_Decode, 154, 4, 0, // Opcode: DERET
/* 1536 */    MCD_OPC_FilterValue, 32, 39, 46, // Skip to: 13355
/* 1540 */    MCD_OPC_CheckPredicate, 16, 35, 46, // Skip to: 13355
/* 1544 */    MCD_OPC_Decode, 157, 13, 0, // Opcode: WAIT
/* 1548 */    MCD_OPC_FilterValue, 17, 21, 6, // Skip to: 3109
/* 1552 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1555 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 1573
/* 1559 */    MCD_OPC_CheckPredicate, 1, 16, 46, // Skip to: 13355
/* 1563 */    MCD_OPC_CheckField, 0, 11, 0, 10, 46, // Skip to: 13355
/* 1569 */    MCD_OPC_Decode, 142, 8, 60, // Opcode: MFC1
/* 1573 */    MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 1591
/* 1577 */    MCD_OPC_CheckPredicate, 17, 254, 45, // Skip to: 13355
/* 1581 */    MCD_OPC_CheckField, 0, 11, 0, 248, 45, // Skip to: 13355
/* 1587 */    MCD_OPC_Decode, 177, 4, 61, // Opcode: DMFC1
/* 1591 */    MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 1609
/* 1595 */    MCD_OPC_CheckPredicate, 1, 236, 45, // Skip to: 13355
/* 1599 */    MCD_OPC_CheckField, 0, 11, 0, 230, 45, // Skip to: 13355
/* 1605 */    MCD_OPC_Decode, 218, 2, 62, // Opcode: CFC1
/* 1609 */    MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 1627
/* 1613 */    MCD_OPC_CheckPredicate, 18, 218, 45, // Skip to: 13355
/* 1617 */    MCD_OPC_CheckField, 0, 11, 0, 212, 45, // Skip to: 13355
/* 1623 */    MCD_OPC_Decode, 145, 8, 63, // Opcode: MFHC1_D32
/* 1627 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 1645
/* 1631 */    MCD_OPC_CheckPredicate, 1, 200, 45, // Skip to: 13355
/* 1635 */    MCD_OPC_CheckField, 0, 11, 0, 194, 45, // Skip to: 13355
/* 1641 */    MCD_OPC_Decode, 131, 9, 64, // Opcode: MTC1
/* 1645 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 1663
/* 1649 */    MCD_OPC_CheckPredicate, 17, 182, 45, // Skip to: 13355
/* 1653 */    MCD_OPC_CheckField, 0, 11, 0, 176, 45, // Skip to: 13355
/* 1659 */    MCD_OPC_Decode, 182, 4, 65, // Opcode: DMTC1
/* 1663 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 1681
/* 1667 */    MCD_OPC_CheckPredicate, 1, 164, 45, // Skip to: 13355
/* 1671 */    MCD_OPC_CheckField, 0, 11, 0, 158, 45, // Skip to: 13355
/* 1677 */    MCD_OPC_Decode, 190, 3, 66, // Opcode: CTC1
/* 1681 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 1699
/* 1685 */    MCD_OPC_CheckPredicate, 18, 146, 45, // Skip to: 13355
/* 1689 */    MCD_OPC_CheckField, 0, 11, 0, 140, 45, // Skip to: 13355
/* 1695 */    MCD_OPC_Decode, 134, 9, 67, // Opcode: MTHC1_D32
/* 1699 */    MCD_OPC_FilterValue, 8, 51, 0, // Skip to: 1754
/* 1703 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1706 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1718
/* 1710 */    MCD_OPC_CheckPredicate, 12, 121, 45, // Skip to: 13355
/* 1714 */    MCD_OPC_Decode, 166, 1, 68, // Opcode: BC1F
/* 1718 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 1730
/* 1722 */    MCD_OPC_CheckPredicate, 12, 109, 45, // Skip to: 13355
/* 1726 */    MCD_OPC_Decode, 170, 1, 68, // Opcode: BC1T
/* 1730 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 1742
/* 1734 */    MCD_OPC_CheckPredicate, 12, 97, 45, // Skip to: 13355
/* 1738 */    MCD_OPC_Decode, 167, 1, 68, // Opcode: BC1FL
/* 1742 */    MCD_OPC_FilterValue, 3, 89, 45, // Skip to: 13355
/* 1746 */    MCD_OPC_CheckPredicate, 12, 85, 45, // Skip to: 13355
/* 1750 */    MCD_OPC_Decode, 171, 1, 68, // Opcode: BC1TL
/* 1754 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 1766
/* 1758 */    MCD_OPC_CheckPredicate, 6, 73, 45, // Skip to: 13355
/* 1762 */    MCD_OPC_Decode, 174, 2, 69, // Opcode: BZ_V
/* 1766 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 1778
/* 1770 */    MCD_OPC_CheckPredicate, 6, 61, 45, // Skip to: 13355
/* 1774 */    MCD_OPC_Decode, 149, 2, 69, // Opcode: BNZ_V
/* 1778 */    MCD_OPC_FilterValue, 16, 80, 2, // Skip to: 2374
/* 1782 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1785 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1797
/* 1789 */    MCD_OPC_CheckPredicate, 1, 42, 45, // Skip to: 13355
/* 1793 */    MCD_OPC_Decode, 153, 5, 70, // Opcode: FADD_S
/* 1797 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 1809
/* 1801 */    MCD_OPC_CheckPredicate, 1, 30, 45, // Skip to: 13355
/* 1805 */    MCD_OPC_Decode, 155, 6, 70, // Opcode: FSUB_S
/* 1809 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 1821
/* 1813 */    MCD_OPC_CheckPredicate, 1, 18, 45, // Skip to: 13355
/* 1817 */    MCD_OPC_Decode, 246, 5, 70, // Opcode: FMUL_S
/* 1821 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 1833
/* 1825 */    MCD_OPC_CheckPredicate, 1, 6, 45, // Skip to: 13355
/* 1829 */    MCD_OPC_Decode, 189, 5, 70, // Opcode: FDIV_S
/* 1833 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 1851
/* 1837 */    MCD_OPC_CheckPredicate, 2, 250, 44, // Skip to: 13355
/* 1841 */    MCD_OPC_CheckField, 16, 5, 0, 244, 44, // Skip to: 13355
/* 1847 */    MCD_OPC_Decode, 148, 6, 71, // Opcode: FSQRT_S
/* 1851 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 1869
/* 1855 */    MCD_OPC_CheckPredicate, 1, 232, 44, // Skip to: 13355
/* 1859 */    MCD_OPC_CheckField, 16, 5, 0, 226, 44, // Skip to: 13355
/* 1865 */    MCD_OPC_Decode, 146, 5, 71, // Opcode: FABS_S
/* 1869 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 1887
/* 1873 */    MCD_OPC_CheckPredicate, 1, 214, 44, // Skip to: 13355
/* 1877 */    MCD_OPC_CheckField, 16, 5, 0, 208, 44, // Skip to: 13355
/* 1883 */    MCD_OPC_Decode, 238, 5, 71, // Opcode: FMOV_S
/* 1887 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 1905
/* 1891 */    MCD_OPC_CheckPredicate, 1, 196, 44, // Skip to: 13355
/* 1895 */    MCD_OPC_CheckField, 16, 5, 0, 190, 44, // Skip to: 13355
/* 1901 */    MCD_OPC_Decode, 252, 5, 71, // Opcode: FNEG_S
/* 1905 */    MCD_OPC_FilterValue, 12, 14, 0, // Skip to: 1923
/* 1909 */    MCD_OPC_CheckPredicate, 2, 178, 44, // Skip to: 13355
/* 1913 */    MCD_OPC_CheckField, 16, 5, 0, 172, 44, // Skip to: 13355
/* 1919 */    MCD_OPC_Decode, 197, 10, 71, // Opcode: ROUND_W_S
/* 1923 */    MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 1941
/* 1927 */    MCD_OPC_CheckPredicate, 2, 160, 44, // Skip to: 13355
/* 1931 */    MCD_OPC_CheckField, 16, 5, 0, 154, 44, // Skip to: 13355
/* 1937 */    MCD_OPC_Decode, 145, 13, 71, // Opcode: TRUNC_W_S
/* 1941 */    MCD_OPC_FilterValue, 14, 14, 0, // Skip to: 1959
/* 1945 */    MCD_OPC_CheckPredicate, 2, 142, 44, // Skip to: 13355
/* 1949 */    MCD_OPC_CheckField, 16, 5, 0, 136, 44, // Skip to: 13355
/* 1955 */    MCD_OPC_Decode, 208, 2, 71, // Opcode: CEIL_W_S
/* 1959 */    MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 1977
/* 1963 */    MCD_OPC_CheckPredicate, 2, 124, 44, // Skip to: 13355
/* 1967 */    MCD_OPC_CheckField, 16, 5, 0, 118, 44, // Skip to: 13355
/* 1973 */    MCD_OPC_Decode, 223, 5, 71, // Opcode: FLOOR_W_S
/* 1977 */    MCD_OPC_FilterValue, 17, 27, 0, // Skip to: 2008
/* 1981 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1984 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1996
/* 1988 */    MCD_OPC_CheckPredicate, 5, 99, 44, // Skip to: 13355
/* 1992 */    MCD_OPC_Decode, 203, 8, 72, // Opcode: MOVF_S
/* 1996 */    MCD_OPC_FilterValue, 1, 91, 44, // Skip to: 13355
/* 2000 */    MCD_OPC_CheckPredicate, 5, 87, 44, // Skip to: 13355
/* 2004 */    MCD_OPC_Decode, 223, 8, 72, // Opcode: MOVT_S
/* 2008 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 2020
/* 2012 */    MCD_OPC_CheckPredicate, 5, 75, 44, // Skip to: 13355
/* 2016 */    MCD_OPC_Decode, 235, 8, 73, // Opcode: MOVZ_I_S
/* 2020 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 2032
/* 2024 */    MCD_OPC_CheckPredicate, 5, 63, 44, // Skip to: 13355
/* 2028 */    MCD_OPC_Decode, 215, 8, 73, // Opcode: MOVN_I_S
/* 2032 */    MCD_OPC_FilterValue, 33, 14, 0, // Skip to: 2050
/* 2036 */    MCD_OPC_CheckPredicate, 19, 51, 44, // Skip to: 13355
/* 2040 */    MCD_OPC_CheckField, 16, 5, 0, 45, 44, // Skip to: 13355
/* 2046 */    MCD_OPC_Decode, 193, 3, 74, // Opcode: CVT_D32_S
/* 2050 */    MCD_OPC_FilterValue, 36, 14, 0, // Skip to: 2068
/* 2054 */    MCD_OPC_CheckPredicate, 1, 33, 44, // Skip to: 13355
/* 2058 */    MCD_OPC_CheckField, 16, 5, 0, 27, 44, // Skip to: 13355
/* 2064 */    MCD_OPC_Decode, 213, 3, 71, // Opcode: CVT_W_S
/* 2068 */    MCD_OPC_FilterValue, 37, 14, 0, // Skip to: 2086
/* 2072 */    MCD_OPC_CheckPredicate, 20, 15, 44, // Skip to: 13355
/* 2076 */    MCD_OPC_CheckField, 16, 5, 0, 9, 44, // Skip to: 13355
/* 2082 */    MCD_OPC_Decode, 202, 3, 75, // Opcode: CVT_L_S
/* 2086 */    MCD_OPC_FilterValue, 48, 14, 0, // Skip to: 2104
/* 2090 */    MCD_OPC_CheckPredicate, 12, 253, 43, // Skip to: 13355
/* 2094 */    MCD_OPC_CheckField, 6, 5, 0, 247, 43, // Skip to: 13355
/* 2100 */    MCD_OPC_Decode, 220, 3, 76, // Opcode: C_F_S
/* 2104 */    MCD_OPC_FilterValue, 49, 14, 0, // Skip to: 2122
/* 2108 */    MCD_OPC_CheckPredicate, 12, 235, 43, // Skip to: 13355
/* 2112 */    MCD_OPC_CheckField, 6, 5, 0, 229, 43, // Skip to: 13355
/* 2118 */    MCD_OPC_Decode, 134, 4, 76, // Opcode: C_UN_S
/* 2122 */    MCD_OPC_FilterValue, 50, 14, 0, // Skip to: 2140
/* 2126 */    MCD_OPC_CheckPredicate, 12, 217, 43, // Skip to: 13355
/* 2130 */    MCD_OPC_CheckField, 6, 5, 0, 211, 43, // Skip to: 13355
/* 2136 */    MCD_OPC_Decode, 217, 3, 76, // Opcode: C_EQ_S
/* 2140 */    MCD_OPC_FilterValue, 51, 14, 0, // Skip to: 2158
/* 2144 */    MCD_OPC_CheckPredicate, 12, 199, 43, // Skip to: 13355
/* 2148 */    MCD_OPC_CheckField, 6, 5, 0, 193, 43, // Skip to: 13355
/* 2154 */    MCD_OPC_Decode, 253, 3, 76, // Opcode: C_UEQ_S
/* 2158 */    MCD_OPC_FilterValue, 52, 14, 0, // Skip to: 2176
/* 2162 */    MCD_OPC_CheckPredicate, 12, 181, 43, // Skip to: 13355
/* 2166 */    MCD_OPC_CheckField, 6, 5, 0, 175, 43, // Skip to: 13355
/* 2172 */    MCD_OPC_Decode, 244, 3, 76, // Opcode: C_OLT_S
/* 2176 */    MCD_OPC_FilterValue, 53, 14, 0, // Skip to: 2194
/* 2180 */    MCD_OPC_CheckPredicate, 12, 163, 43, // Skip to: 13355
/* 2184 */    MCD_OPC_CheckField, 6, 5, 0, 157, 43, // Skip to: 13355
/* 2190 */    MCD_OPC_Decode, 131, 4, 76, // Opcode: C_ULT_S
/* 2194 */    MCD_OPC_FilterValue, 54, 14, 0, // Skip to: 2212
/* 2198 */    MCD_OPC_CheckPredicate, 12, 145, 43, // Skip to: 13355
/* 2202 */    MCD_OPC_CheckField, 6, 5, 0, 139, 43, // Skip to: 13355
/* 2208 */    MCD_OPC_Decode, 241, 3, 76, // Opcode: C_OLE_S
/* 2212 */    MCD_OPC_FilterValue, 55, 14, 0, // Skip to: 2230
/* 2216 */    MCD_OPC_CheckPredicate, 12, 127, 43, // Skip to: 13355
/* 2220 */    MCD_OPC_CheckField, 6, 5, 0, 121, 43, // Skip to: 13355
/* 2226 */    MCD_OPC_Decode, 128, 4, 76, // Opcode: C_ULE_S
/* 2230 */    MCD_OPC_FilterValue, 56, 14, 0, // Skip to: 2248
/* 2234 */    MCD_OPC_CheckPredicate, 12, 109, 43, // Skip to: 13355
/* 2238 */    MCD_OPC_CheckField, 6, 5, 0, 103, 43, // Skip to: 13355
/* 2244 */    MCD_OPC_Decode, 250, 3, 76, // Opcode: C_SF_S
/* 2248 */    MCD_OPC_FilterValue, 57, 14, 0, // Skip to: 2266
/* 2252 */    MCD_OPC_CheckPredicate, 12, 91, 43, // Skip to: 13355
/* 2256 */    MCD_OPC_CheckField, 6, 5, 0, 85, 43, // Skip to: 13355
/* 2262 */    MCD_OPC_Decode, 232, 3, 76, // Opcode: C_NGLE_S
/* 2266 */    MCD_OPC_FilterValue, 58, 14, 0, // Skip to: 2284
/* 2270 */    MCD_OPC_CheckPredicate, 12, 73, 43, // Skip to: 13355
/* 2274 */    MCD_OPC_CheckField, 6, 5, 0, 67, 43, // Skip to: 13355
/* 2280 */    MCD_OPC_Decode, 247, 3, 76, // Opcode: C_SEQ_S
/* 2284 */    MCD_OPC_FilterValue, 59, 14, 0, // Skip to: 2302
/* 2288 */    MCD_OPC_CheckPredicate, 12, 55, 43, // Skip to: 13355
/* 2292 */    MCD_OPC_CheckField, 6, 5, 0, 49, 43, // Skip to: 13355
/* 2298 */    MCD_OPC_Decode, 235, 3, 76, // Opcode: C_NGL_S
/* 2302 */    MCD_OPC_FilterValue, 60, 14, 0, // Skip to: 2320
/* 2306 */    MCD_OPC_CheckPredicate, 12, 37, 43, // Skip to: 13355
/* 2310 */    MCD_OPC_CheckField, 6, 5, 0, 31, 43, // Skip to: 13355
/* 2316 */    MCD_OPC_Decode, 226, 3, 76, // Opcode: C_LT_S
/* 2320 */    MCD_OPC_FilterValue, 61, 14, 0, // Skip to: 2338
/* 2324 */    MCD_OPC_CheckPredicate, 12, 19, 43, // Skip to: 13355
/* 2328 */    MCD_OPC_CheckField, 6, 5, 0, 13, 43, // Skip to: 13355
/* 2334 */    MCD_OPC_Decode, 229, 3, 76, // Opcode: C_NGE_S
/* 2338 */    MCD_OPC_FilterValue, 62, 14, 0, // Skip to: 2356
/* 2342 */    MCD_OPC_CheckPredicate, 12, 1, 43, // Skip to: 13355
/* 2346 */    MCD_OPC_CheckField, 6, 5, 0, 251, 42, // Skip to: 13355
/* 2352 */    MCD_OPC_Decode, 223, 3, 76, // Opcode: C_LE_S
/* 2356 */    MCD_OPC_FilterValue, 63, 243, 42, // Skip to: 13355
/* 2360 */    MCD_OPC_CheckPredicate, 12, 239, 42, // Skip to: 13355
/* 2364 */    MCD_OPC_CheckField, 6, 5, 0, 233, 42, // Skip to: 13355
/* 2370 */    MCD_OPC_Decode, 238, 3, 76, // Opcode: C_NGT_S
/* 2374 */    MCD_OPC_FilterValue, 17, 80, 2, // Skip to: 2970
/* 2378 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2381 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 2393
/* 2385 */    MCD_OPC_CheckPredicate, 19, 214, 42, // Skip to: 13355
/* 2389 */    MCD_OPC_Decode, 150, 5, 77, // Opcode: FADD_D32
/* 2393 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 2405
/* 2397 */    MCD_OPC_CheckPredicate, 19, 202, 42, // Skip to: 13355
/* 2401 */    MCD_OPC_Decode, 152, 6, 77, // Opcode: FSUB_D32
/* 2405 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 2417
/* 2409 */    MCD_OPC_CheckPredicate, 19, 190, 42, // Skip to: 13355
/* 2413 */    MCD_OPC_Decode, 243, 5, 77, // Opcode: FMUL_D32
/* 2417 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 2429
/* 2421 */    MCD_OPC_CheckPredicate, 19, 178, 42, // Skip to: 13355
/* 2425 */    MCD_OPC_Decode, 186, 5, 77, // Opcode: FDIV_D32
/* 2429 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 2447
/* 2433 */    MCD_OPC_CheckPredicate, 21, 166, 42, // Skip to: 13355
/* 2437 */    MCD_OPC_CheckField, 16, 5, 0, 160, 42, // Skip to: 13355
/* 2443 */    MCD_OPC_Decode, 145, 6, 78, // Opcode: FSQRT_D32
/* 2447 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 2465
/* 2451 */    MCD_OPC_CheckPredicate, 19, 148, 42, // Skip to: 13355
/* 2455 */    MCD_OPC_CheckField, 16, 5, 0, 142, 42, // Skip to: 13355
/* 2461 */    MCD_OPC_Decode, 143, 5, 78, // Opcode: FABS_D32
/* 2465 */    MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 2483
/* 2469 */    MCD_OPC_CheckPredicate, 19, 130, 42, // Skip to: 13355
/* 2473 */    MCD_OPC_CheckField, 16, 5, 0, 124, 42, // Skip to: 13355
/* 2479 */    MCD_OPC_Decode, 235, 5, 78, // Opcode: FMOV_D32
/* 2483 */    MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 2501
/* 2487 */    MCD_OPC_CheckPredicate, 19, 112, 42, // Skip to: 13355
/* 2491 */    MCD_OPC_CheckField, 16, 5, 0, 106, 42, // Skip to: 13355
/* 2497 */    MCD_OPC_Decode, 249, 5, 78, // Opcode: FNEG_D32
/* 2501 */    MCD_OPC_FilterValue, 12, 14, 0, // Skip to: 2519
/* 2505 */    MCD_OPC_CheckPredicate, 21, 94, 42, // Skip to: 13355
/* 2509 */    MCD_OPC_CheckField, 16, 5, 0, 88, 42, // Skip to: 13355
/* 2515 */    MCD_OPC_Decode, 194, 10, 79, // Opcode: ROUND_W_D32
/* 2519 */    MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 2537
/* 2523 */    MCD_OPC_CheckPredicate, 21, 76, 42, // Skip to: 13355
/* 2527 */    MCD_OPC_CheckField, 16, 5, 0, 70, 42, // Skip to: 13355
/* 2533 */    MCD_OPC_Decode, 142, 13, 79, // Opcode: TRUNC_W_D32
/* 2537 */    MCD_OPC_FilterValue, 14, 14, 0, // Skip to: 2555
/* 2541 */    MCD_OPC_CheckPredicate, 21, 58, 42, // Skip to: 13355
/* 2545 */    MCD_OPC_CheckField, 16, 5, 0, 52, 42, // Skip to: 13355
/* 2551 */    MCD_OPC_Decode, 205, 2, 79, // Opcode: CEIL_W_D32
/* 2555 */    MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 2573
/* 2559 */    MCD_OPC_CheckPredicate, 21, 40, 42, // Skip to: 13355
/* 2563 */    MCD_OPC_CheckField, 16, 5, 0, 34, 42, // Skip to: 13355
/* 2569 */    MCD_OPC_Decode, 220, 5, 79, // Opcode: FLOOR_W_D32
/* 2573 */    MCD_OPC_FilterValue, 17, 27, 0, // Skip to: 2604
/* 2577 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 2580 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 2592
/* 2584 */    MCD_OPC_CheckPredicate, 22, 15, 42, // Skip to: 13355
/* 2588 */    MCD_OPC_Decode, 197, 8, 80, // Opcode: MOVF_D32
/* 2592 */    MCD_OPC_FilterValue, 1, 7, 42, // Skip to: 13355
/* 2596 */    MCD_OPC_CheckPredicate, 22, 3, 42, // Skip to: 13355
/* 2600 */    MCD_OPC_Decode, 217, 8, 80, // Opcode: MOVT_D32
/* 2604 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 2616
/* 2608 */    MCD_OPC_CheckPredicate, 22, 247, 41, // Skip to: 13355
/* 2612 */    MCD_OPC_Decode, 229, 8, 81, // Opcode: MOVZ_I_D32
/* 2616 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 2628
/* 2620 */    MCD_OPC_CheckPredicate, 22, 235, 41, // Skip to: 13355
/* 2624 */    MCD_OPC_Decode, 209, 8, 81, // Opcode: MOVN_I_D32
/* 2628 */    MCD_OPC_FilterValue, 32, 14, 0, // Skip to: 2646
/* 2632 */    MCD_OPC_CheckPredicate, 19, 223, 41, // Skip to: 13355
/* 2636 */    MCD_OPC_CheckField, 16, 5, 0, 217, 41, // Skip to: 13355
/* 2642 */    MCD_OPC_Decode, 204, 3, 79, // Opcode: CVT_S_D32
/* 2646 */    MCD_OPC_FilterValue, 36, 14, 0, // Skip to: 2664
/* 2650 */    MCD_OPC_CheckPredicate, 19, 205, 41, // Skip to: 13355
/* 2654 */    MCD_OPC_CheckField, 16, 5, 0, 199, 41, // Skip to: 13355
/* 2660 */    MCD_OPC_Decode, 210, 3, 79, // Opcode: CVT_W_D32
/* 2664 */    MCD_OPC_FilterValue, 37, 14, 0, // Skip to: 2682
/* 2668 */    MCD_OPC_CheckPredicate, 20, 187, 41, // Skip to: 13355
/* 2672 */    MCD_OPC_CheckField, 16, 5, 0, 181, 41, // Skip to: 13355
/* 2678 */    MCD_OPC_Decode, 200, 3, 82, // Opcode: CVT_L_D64
/* 2682 */    MCD_OPC_FilterValue, 48, 14, 0, // Skip to: 2700
/* 2686 */    MCD_OPC_CheckPredicate, 23, 169, 41, // Skip to: 13355
/* 2690 */    MCD_OPC_CheckField, 6, 5, 0, 163, 41, // Skip to: 13355
/* 2696 */    MCD_OPC_Decode, 218, 3, 83, // Opcode: C_F_D32
/* 2700 */    MCD_OPC_FilterValue, 49, 14, 0, // Skip to: 2718
/* 2704 */    MCD_OPC_CheckPredicate, 23, 151, 41, // Skip to: 13355
/* 2708 */    MCD_OPC_CheckField, 6, 5, 0, 145, 41, // Skip to: 13355
/* 2714 */    MCD_OPC_Decode, 132, 4, 83, // Opcode: C_UN_D32
/* 2718 */    MCD_OPC_FilterValue, 50, 14, 0, // Skip to: 2736
/* 2722 */    MCD_OPC_CheckPredicate, 23, 133, 41, // Skip to: 13355
/* 2726 */    MCD_OPC_CheckField, 6, 5, 0, 127, 41, // Skip to: 13355
/* 2732 */    MCD_OPC_Decode, 215, 3, 83, // Opcode: C_EQ_D32
/* 2736 */    MCD_OPC_FilterValue, 51, 14, 0, // Skip to: 2754
/* 2740 */    MCD_OPC_CheckPredicate, 23, 115, 41, // Skip to: 13355
/* 2744 */    MCD_OPC_CheckField, 6, 5, 0, 109, 41, // Skip to: 13355
/* 2750 */    MCD_OPC_Decode, 251, 3, 83, // Opcode: C_UEQ_D32
/* 2754 */    MCD_OPC_FilterValue, 52, 14, 0, // Skip to: 2772
/* 2758 */    MCD_OPC_CheckPredicate, 23, 97, 41, // Skip to: 13355
/* 2762 */    MCD_OPC_CheckField, 6, 5, 0, 91, 41, // Skip to: 13355
/* 2768 */    MCD_OPC_Decode, 242, 3, 83, // Opcode: C_OLT_D32
/* 2772 */    MCD_OPC_FilterValue, 53, 14, 0, // Skip to: 2790
/* 2776 */    MCD_OPC_CheckPredicate, 23, 79, 41, // Skip to: 13355
/* 2780 */    MCD_OPC_CheckField, 6, 5, 0, 73, 41, // Skip to: 13355
/* 2786 */    MCD_OPC_Decode, 129, 4, 83, // Opcode: C_ULT_D32
/* 2790 */    MCD_OPC_FilterValue, 54, 14, 0, // Skip to: 2808
/* 2794 */    MCD_OPC_CheckPredicate, 23, 61, 41, // Skip to: 13355
/* 2798 */    MCD_OPC_CheckField, 6, 5, 0, 55, 41, // Skip to: 13355
/* 2804 */    MCD_OPC_Decode, 239, 3, 83, // Opcode: C_OLE_D32
/* 2808 */    MCD_OPC_FilterValue, 55, 14, 0, // Skip to: 2826
/* 2812 */    MCD_OPC_CheckPredicate, 23, 43, 41, // Skip to: 13355
/* 2816 */    MCD_OPC_CheckField, 6, 5, 0, 37, 41, // Skip to: 13355
/* 2822 */    MCD_OPC_Decode, 254, 3, 83, // Opcode: C_ULE_D32
/* 2826 */    MCD_OPC_FilterValue, 56, 14, 0, // Skip to: 2844
/* 2830 */    MCD_OPC_CheckPredicate, 23, 25, 41, // Skip to: 13355
/* 2834 */    MCD_OPC_CheckField, 6, 5, 0, 19, 41, // Skip to: 13355
/* 2840 */    MCD_OPC_Decode, 248, 3, 83, // Opcode: C_SF_D32
/* 2844 */    MCD_OPC_FilterValue, 57, 14, 0, // Skip to: 2862
/* 2848 */    MCD_OPC_CheckPredicate, 23, 7, 41, // Skip to: 13355
/* 2852 */    MCD_OPC_CheckField, 6, 5, 0, 1, 41, // Skip to: 13355
/* 2858 */    MCD_OPC_Decode, 230, 3, 83, // Opcode: C_NGLE_D32
/* 2862 */    MCD_OPC_FilterValue, 58, 14, 0, // Skip to: 2880
/* 2866 */    MCD_OPC_CheckPredicate, 23, 245, 40, // Skip to: 13355
/* 2870 */    MCD_OPC_CheckField, 6, 5, 0, 239, 40, // Skip to: 13355
/* 2876 */    MCD_OPC_Decode, 245, 3, 83, // Opcode: C_SEQ_D32
/* 2880 */    MCD_OPC_FilterValue, 59, 14, 0, // Skip to: 2898
/* 2884 */    MCD_OPC_CheckPredicate, 23, 227, 40, // Skip to: 13355
/* 2888 */    MCD_OPC_CheckField, 6, 5, 0, 221, 40, // Skip to: 13355
/* 2894 */    MCD_OPC_Decode, 233, 3, 83, // Opcode: C_NGL_D32
/* 2898 */    MCD_OPC_FilterValue, 60, 14, 0, // Skip to: 2916
/* 2902 */    MCD_OPC_CheckPredicate, 23, 209, 40, // Skip to: 13355
/* 2906 */    MCD_OPC_CheckField, 6, 5, 0, 203, 40, // Skip to: 13355
/* 2912 */    MCD_OPC_Decode, 224, 3, 83, // Opcode: C_LT_D32
/* 2916 */    MCD_OPC_FilterValue, 61, 14, 0, // Skip to: 2934
/* 2920 */    MCD_OPC_CheckPredicate, 23, 191, 40, // Skip to: 13355
/* 2924 */    MCD_OPC_CheckField, 6, 5, 0, 185, 40, // Skip to: 13355
/* 2930 */    MCD_OPC_Decode, 227, 3, 83, // Opcode: C_NGE_D32
/* 2934 */    MCD_OPC_FilterValue, 62, 14, 0, // Skip to: 2952
/* 2938 */    MCD_OPC_CheckPredicate, 23, 173, 40, // Skip to: 13355
/* 2942 */    MCD_OPC_CheckField, 6, 5, 0, 167, 40, // Skip to: 13355
/* 2948 */    MCD_OPC_Decode, 221, 3, 83, // Opcode: C_LE_D32
/* 2952 */    MCD_OPC_FilterValue, 63, 159, 40, // Skip to: 13355
/* 2956 */    MCD_OPC_CheckPredicate, 23, 155, 40, // Skip to: 13355
/* 2960 */    MCD_OPC_CheckField, 6, 5, 0, 149, 40, // Skip to: 13355
/* 2966 */    MCD_OPC_Decode, 236, 3, 83, // Opcode: C_NGT_D32
/* 2970 */    MCD_OPC_FilterValue, 20, 39, 0, // Skip to: 3013
/* 2974 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2977 */    MCD_OPC_FilterValue, 32, 14, 0, // Skip to: 2995
/* 2981 */    MCD_OPC_CheckPredicate, 1, 130, 40, // Skip to: 13355
/* 2985 */    MCD_OPC_CheckField, 16, 5, 0, 124, 40, // Skip to: 13355
/* 2991 */    MCD_OPC_Decode, 208, 3, 71, // Opcode: CVT_S_W
/* 2995 */    MCD_OPC_FilterValue, 33, 116, 40, // Skip to: 13355
/* 2999 */    MCD_OPC_CheckPredicate, 19, 112, 40, // Skip to: 13355
/* 3003 */    MCD_OPC_CheckField, 16, 5, 0, 106, 40, // Skip to: 13355
/* 3009 */    MCD_OPC_Decode, 194, 3, 74, // Opcode: CVT_D32_W
/* 3013 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 3025
/* 3017 */    MCD_OPC_CheckPredicate, 6, 94, 40, // Skip to: 13355
/* 3021 */    MCD_OPC_Decode, 171, 2, 69, // Opcode: BZ_B
/* 3025 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 3037
/* 3029 */    MCD_OPC_CheckPredicate, 6, 82, 40, // Skip to: 13355
/* 3033 */    MCD_OPC_Decode, 173, 2, 84, // Opcode: BZ_H
/* 3037 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 3049
/* 3041 */    MCD_OPC_CheckPredicate, 6, 70, 40, // Skip to: 13355
/* 3045 */    MCD_OPC_Decode, 175, 2, 85, // Opcode: BZ_W
/* 3049 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 3061
/* 3053 */    MCD_OPC_CheckPredicate, 6, 58, 40, // Skip to: 13355
/* 3057 */    MCD_OPC_Decode, 172, 2, 86, // Opcode: BZ_D
/* 3061 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 3073
/* 3065 */    MCD_OPC_CheckPredicate, 6, 46, 40, // Skip to: 13355
/* 3069 */    MCD_OPC_Decode, 146, 2, 69, // Opcode: BNZ_B
/* 3073 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 3085
/* 3077 */    MCD_OPC_CheckPredicate, 6, 34, 40, // Skip to: 13355
/* 3081 */    MCD_OPC_Decode, 148, 2, 84, // Opcode: BNZ_H
/* 3085 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 3097
/* 3089 */    MCD_OPC_CheckPredicate, 6, 22, 40, // Skip to: 13355
/* 3093 */    MCD_OPC_Decode, 150, 2, 85, // Opcode: BNZ_W
/* 3097 */    MCD_OPC_FilterValue, 31, 14, 40, // Skip to: 13355
/* 3101 */    MCD_OPC_CheckPredicate, 6, 10, 40, // Skip to: 13355
/* 3105 */    MCD_OPC_Decode, 147, 2, 86, // Opcode: BNZ_D
/* 3109 */    MCD_OPC_FilterValue, 18, 94, 0, // Skip to: 3207
/* 3113 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 3116 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 3134
/* 3120 */    MCD_OPC_CheckPredicate, 1, 247, 39, // Skip to: 13355
/* 3124 */    MCD_OPC_CheckField, 3, 8, 0, 241, 39, // Skip to: 13355
/* 3130 */    MCD_OPC_Decode, 144, 8, 58, // Opcode: MFC2
/* 3134 */    MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 3152
/* 3138 */    MCD_OPC_CheckPredicate, 1, 229, 39, // Skip to: 13355
/* 3142 */    MCD_OPC_CheckField, 3, 8, 0, 223, 39, // Skip to: 13355
/* 3148 */    MCD_OPC_Decode, 133, 9, 58, // Opcode: MTC2
/* 3152 */    MCD_OPC_FilterValue, 8, 215, 39, // Skip to: 13355
/* 3156 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 3159 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3171
/* 3163 */    MCD_OPC_CheckPredicate, 12, 204, 39, // Skip to: 13355
/* 3167 */    MCD_OPC_Decode, 174, 1, 59, // Opcode: BC2F
/* 3171 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3183
/* 3175 */    MCD_OPC_CheckPredicate, 12, 192, 39, // Skip to: 13355
/* 3179 */    MCD_OPC_Decode, 177, 1, 59, // Opcode: BC2T
/* 3183 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3195
/* 3187 */    MCD_OPC_CheckPredicate, 12, 180, 39, // Skip to: 13355
/* 3191 */    MCD_OPC_Decode, 175, 1, 59, // Opcode: BC2FL
/* 3195 */    MCD_OPC_FilterValue, 3, 172, 39, // Skip to: 13355
/* 3199 */    MCD_OPC_CheckPredicate, 12, 168, 39, // Skip to: 13355
/* 3203 */    MCD_OPC_Decode, 178, 1, 59, // Opcode: BC2TL
/* 3207 */    MCD_OPC_FilterValue, 19, 9, 1, // Skip to: 3476
/* 3211 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 3214 */    MCD_OPC_FilterValue, 8, 51, 0, // Skip to: 3269
/* 3218 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 3221 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3233
/* 3225 */    MCD_OPC_CheckPredicate, 12, 40, 0, // Skip to: 3269
/* 3229 */    MCD_OPC_Decode, 179, 1, 59, // Opcode: BC3F
/* 3233 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3245
/* 3237 */    MCD_OPC_CheckPredicate, 12, 28, 0, // Skip to: 3269
/* 3241 */    MCD_OPC_Decode, 181, 1, 59, // Opcode: BC3T
/* 3245 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3257
/* 3249 */    MCD_OPC_CheckPredicate, 12, 16, 0, // Skip to: 3269
/* 3253 */    MCD_OPC_Decode, 180, 1, 59, // Opcode: BC3FL
/* 3257 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 3269
/* 3261 */    MCD_OPC_CheckPredicate, 12, 4, 0, // Skip to: 3269
/* 3265 */    MCD_OPC_Decode, 182, 1, 59, // Opcode: BC3TL
/* 3269 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 3272 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 3290
/* 3276 */    MCD_OPC_CheckPredicate, 24, 91, 39, // Skip to: 13355
/* 3280 */    MCD_OPC_CheckField, 11, 5, 0, 85, 39, // Skip to: 13355
/* 3286 */    MCD_OPC_Decode, 200, 7, 87, // Opcode: LWXC1
/* 3290 */    MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 3308
/* 3294 */    MCD_OPC_CheckPredicate, 25, 73, 39, // Skip to: 13355
/* 3298 */    MCD_OPC_CheckField, 11, 5, 0, 67, 39, // Skip to: 13355
/* 3304 */    MCD_OPC_Decode, 147, 7, 88, // Opcode: LDXC1
/* 3308 */    MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 3326
/* 3312 */    MCD_OPC_CheckPredicate, 26, 55, 39, // Skip to: 13355
/* 3316 */    MCD_OPC_CheckField, 11, 5, 0, 49, 39, // Skip to: 13355
/* 3322 */    MCD_OPC_Decode, 177, 7, 88, // Opcode: LUXC1
/* 3326 */    MCD_OPC_FilterValue, 8, 14, 0, // Skip to: 3344
/* 3330 */    MCD_OPC_CheckPredicate, 24, 37, 39, // Skip to: 13355
/* 3334 */    MCD_OPC_CheckField, 6, 5, 0, 31, 39, // Skip to: 13355
/* 3340 */    MCD_OPC_Decode, 181, 12, 89, // Opcode: SWXC1
/* 3344 */    MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 3362
/* 3348 */    MCD_OPC_CheckPredicate, 25, 19, 39, // Skip to: 13355
/* 3352 */    MCD_OPC_CheckField, 6, 5, 0, 13, 39, // Skip to: 13355
/* 3358 */    MCD_OPC_Decode, 232, 10, 90, // Opcode: SDXC1
/* 3362 */    MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 3380
/* 3366 */    MCD_OPC_CheckPredicate, 26, 1, 39, // Skip to: 13355
/* 3370 */    MCD_OPC_CheckField, 6, 5, 0, 251, 38, // Skip to: 13355
/* 3376 */    MCD_OPC_Decode, 165, 12, 90, // Opcode: SUXC1
/* 3380 */    MCD_OPC_FilterValue, 32, 8, 0, // Skip to: 3392
/* 3384 */    MCD_OPC_CheckPredicate, 27, 239, 38, // Skip to: 13355
/* 3388 */    MCD_OPC_Decode, 239, 7, 91, // Opcode: MADD_S
/* 3392 */    MCD_OPC_FilterValue, 33, 8, 0, // Skip to: 3404
/* 3396 */    MCD_OPC_CheckPredicate, 28, 227, 38, // Skip to: 13355
/* 3400 */    MCD_OPC_Decode, 232, 7, 92, // Opcode: MADD_D32
/* 3404 */    MCD_OPC_FilterValue, 40, 8, 0, // Skip to: 3416
/* 3408 */    MCD_OPC_CheckPredicate, 27, 215, 38, // Skip to: 13355
/* 3412 */    MCD_OPC_Decode, 128, 9, 91, // Opcode: MSUB_S
/* 3416 */    MCD_OPC_FilterValue, 41, 8, 0, // Skip to: 3428
/* 3420 */    MCD_OPC_CheckPredicate, 28, 203, 38, // Skip to: 13355
/* 3424 */    MCD_OPC_Decode, 249, 8, 92, // Opcode: MSUB_D32
/* 3428 */    MCD_OPC_FilterValue, 48, 8, 0, // Skip to: 3440
/* 3432 */    MCD_OPC_CheckPredicate, 27, 191, 38, // Skip to: 13355
/* 3436 */    MCD_OPC_Decode, 203, 9, 91, // Opcode: NMADD_S
/* 3440 */    MCD_OPC_FilterValue, 49, 8, 0, // Skip to: 3452
/* 3444 */    MCD_OPC_CheckPredicate, 28, 179, 38, // Skip to: 13355
/* 3448 */    MCD_OPC_Decode, 200, 9, 92, // Opcode: NMADD_D32
/* 3452 */    MCD_OPC_FilterValue, 56, 8, 0, // Skip to: 3464
/* 3456 */    MCD_OPC_CheckPredicate, 27, 167, 38, // Skip to: 13355
/* 3460 */    MCD_OPC_Decode, 208, 9, 91, // Opcode: NMSUB_S
/* 3464 */    MCD_OPC_FilterValue, 57, 159, 38, // Skip to: 13355
/* 3468 */    MCD_OPC_CheckPredicate, 28, 155, 38, // Skip to: 13355
/* 3472 */    MCD_OPC_Decode, 205, 9, 92, // Opcode: NMSUB_D32
/* 3476 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 3488
/* 3480 */    MCD_OPC_CheckPredicate, 1, 143, 38, // Skip to: 13355
/* 3484 */    MCD_OPC_Decode, 194, 1, 55, // Opcode: BEQL
/* 3488 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 3500
/* 3492 */    MCD_OPC_CheckPredicate, 1, 131, 38, // Skip to: 13355
/* 3496 */    MCD_OPC_Decode, 140, 2, 55, // Opcode: BNEL
/* 3500 */    MCD_OPC_FilterValue, 22, 14, 0, // Skip to: 3518
/* 3504 */    MCD_OPC_CheckPredicate, 1, 119, 38, // Skip to: 13355
/* 3508 */    MCD_OPC_CheckField, 16, 5, 0, 113, 38, // Skip to: 13355
/* 3514 */    MCD_OPC_Decode, 239, 1, 51, // Opcode: BLEZL
/* 3518 */    MCD_OPC_FilterValue, 23, 14, 0, // Skip to: 3536
/* 3522 */    MCD_OPC_CheckPredicate, 1, 101, 38, // Skip to: 13355
/* 3526 */    MCD_OPC_CheckField, 16, 5, 0, 95, 38, // Skip to: 13355
/* 3532 */    MCD_OPC_Decode, 215, 1, 51, // Opcode: BGTZL
/* 3536 */    MCD_OPC_FilterValue, 28, 229, 0, // Skip to: 3769
/* 3540 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 3543 */    MCD_OPC_FilterValue, 0, 36, 0, // Skip to: 3583
/* 3547 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 3550 */    MCD_OPC_FilterValue, 0, 73, 38, // Skip to: 13355
/* 3554 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3557 */    MCD_OPC_FilterValue, 0, 66, 38, // Skip to: 13355
/* 3561 */    MCD_OPC_CheckPredicate, 7, 10, 0, // Skip to: 3575
/* 3565 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3575
/* 3571 */    MCD_OPC_Decode, 220, 7, 24, // Opcode: MADD
/* 3575 */    MCD_OPC_CheckPredicate, 11, 48, 38, // Skip to: 13355
/* 3579 */    MCD_OPC_Decode, 235, 7, 93, // Opcode: MADD_DSP
/* 3583 */    MCD_OPC_FilterValue, 1, 36, 0, // Skip to: 3623
/* 3587 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 3590 */    MCD_OPC_FilterValue, 0, 33, 38, // Skip to: 13355
/* 3594 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3597 */    MCD_OPC_FilterValue, 0, 26, 38, // Skip to: 13355
/* 3601 */    MCD_OPC_CheckPredicate, 7, 10, 0, // Skip to: 3615
/* 3605 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3615
/* 3611 */    MCD_OPC_Decode, 225, 7, 24, // Opcode: MADDU
/* 3615 */    MCD_OPC_CheckPredicate, 11, 8, 38, // Skip to: 13355
/* 3619 */    MCD_OPC_Decode, 226, 7, 93, // Opcode: MADDU_DSP
/* 3623 */    MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 3641
/* 3627 */    MCD_OPC_CheckPredicate, 7, 252, 37, // Skip to: 13355
/* 3631 */    MCD_OPC_CheckField, 6, 5, 0, 246, 37, // Skip to: 13355
/* 3637 */    MCD_OPC_Decode, 154, 9, 17, // Opcode: MUL
/* 3641 */    MCD_OPC_FilterValue, 4, 36, 0, // Skip to: 3681
/* 3645 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 3648 */    MCD_OPC_FilterValue, 0, 231, 37, // Skip to: 13355
/* 3652 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3655 */    MCD_OPC_FilterValue, 0, 224, 37, // Skip to: 13355
/* 3659 */    MCD_OPC_CheckPredicate, 7, 10, 0, // Skip to: 3673
/* 3663 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3673
/* 3669 */    MCD_OPC_Decode, 237, 8, 24, // Opcode: MSUB
/* 3673 */    MCD_OPC_CheckPredicate, 11, 206, 37, // Skip to: 13355
/* 3677 */    MCD_OPC_Decode, 252, 8, 93, // Opcode: MSUB_DSP
/* 3681 */    MCD_OPC_FilterValue, 5, 36, 0, // Skip to: 3721
/* 3685 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 3688 */    MCD_OPC_FilterValue, 0, 191, 37, // Skip to: 13355
/* 3692 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 3695 */    MCD_OPC_FilterValue, 0, 184, 37, // Skip to: 13355
/* 3699 */    MCD_OPC_CheckPredicate, 7, 10, 0, // Skip to: 3713
/* 3703 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 3713
/* 3709 */    MCD_OPC_Decode, 242, 8, 24, // Opcode: MSUBU
/* 3713 */    MCD_OPC_CheckPredicate, 11, 166, 37, // Skip to: 13355
/* 3717 */    MCD_OPC_Decode, 243, 8, 93, // Opcode: MSUBU_DSP
/* 3721 */    MCD_OPC_FilterValue, 32, 14, 0, // Skip to: 3739
/* 3725 */    MCD_OPC_CheckPredicate, 7, 154, 37, // Skip to: 13355
/* 3729 */    MCD_OPC_CheckField, 6, 5, 0, 148, 37, // Skip to: 13355
/* 3735 */    MCD_OPC_Decode, 132, 3, 94, // Opcode: CLZ
/* 3739 */    MCD_OPC_FilterValue, 33, 14, 0, // Skip to: 3757
/* 3743 */    MCD_OPC_CheckPredicate, 7, 136, 37, // Skip to: 13355
/* 3747 */    MCD_OPC_CheckField, 6, 5, 0, 130, 37, // Skip to: 13355
/* 3753 */    MCD_OPC_Decode, 241, 2, 94, // Opcode: CLO
/* 3757 */    MCD_OPC_FilterValue, 63, 122, 37, // Skip to: 13355
/* 3761 */    MCD_OPC_CheckPredicate, 7, 118, 37, // Skip to: 13355
/* 3765 */    MCD_OPC_Decode, 220, 10, 42, // Opcode: SDBBP
/* 3769 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 3781
/* 3773 */    MCD_OPC_CheckPredicate, 7, 106, 37, // Skip to: 13355
/* 3777 */    MCD_OPC_Decode, 237, 6, 54, // Opcode: JALX
/* 3781 */    MCD_OPC_FilterValue, 30, 181, 26, // Skip to: 10622
/* 3785 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 3788 */    MCD_OPC_FilterValue, 0, 50, 0, // Skip to: 3842
/* 3792 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 3795 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 3806
/* 3799 */    MCD_OPC_CheckPredicate, 6, 80, 37, // Skip to: 13355
/* 3803 */    MCD_OPC_Decode, 77, 95, // Opcode: ANDI_B
/* 3806 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3818
/* 3810 */    MCD_OPC_CheckPredicate, 6, 69, 37, // Skip to: 13355
/* 3814 */    MCD_OPC_Decode, 223, 9, 95, // Opcode: ORI_B
/* 3818 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 3830
/* 3822 */    MCD_OPC_CheckPredicate, 6, 57, 37, // Skip to: 13355
/* 3826 */    MCD_OPC_Decode, 213, 9, 95, // Opcode: NORI_B
/* 3830 */    MCD_OPC_FilterValue, 3, 49, 37, // Skip to: 13355
/* 3834 */    MCD_OPC_CheckPredicate, 6, 45, 37, // Skip to: 13355
/* 3838 */    MCD_OPC_Decode, 164, 13, 95, // Opcode: XORI_B
/* 3842 */    MCD_OPC_FilterValue, 1, 39, 0, // Skip to: 3885
/* 3846 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 3849 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3861
/* 3853 */    MCD_OPC_CheckPredicate, 6, 26, 37, // Skip to: 13355
/* 3857 */    MCD_OPC_Decode, 253, 1, 96, // Opcode: BMNZI_B
/* 3861 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3873
/* 3865 */    MCD_OPC_CheckPredicate, 6, 14, 37, // Skip to: 13355
/* 3869 */    MCD_OPC_Decode, 255, 1, 96, // Opcode: BMZI_B
/* 3873 */    MCD_OPC_FilterValue, 2, 6, 37, // Skip to: 13355
/* 3877 */    MCD_OPC_CheckPredicate, 6, 2, 37, // Skip to: 13355
/* 3881 */    MCD_OPC_Decode, 156, 2, 96, // Opcode: BSELI_B
/* 3885 */    MCD_OPC_FilterValue, 2, 39, 0, // Skip to: 3928
/* 3889 */    MCD_OPC_ExtractField, 24, 2,  // Inst{25-24} ...
/* 3892 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 3904
/* 3896 */    MCD_OPC_CheckPredicate, 6, 239, 36, // Skip to: 13355
/* 3900 */    MCD_OPC_Decode, 254, 10, 95, // Opcode: SHF_B
/* 3904 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 3916
/* 3908 */    MCD_OPC_CheckPredicate, 6, 227, 36, // Skip to: 13355
/* 3912 */    MCD_OPC_Decode, 255, 10, 97, // Opcode: SHF_H
/* 3916 */    MCD_OPC_FilterValue, 2, 219, 36, // Skip to: 13355
/* 3920 */    MCD_OPC_CheckPredicate, 6, 215, 36, // Skip to: 13355
/* 3924 */    MCD_OPC_Decode, 128, 11, 98, // Opcode: SHF_W
/* 3928 */    MCD_OPC_FilterValue, 6, 31, 1, // Skip to: 4219
/* 3932 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 3935 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 3946
/* 3939 */    MCD_OPC_CheckPredicate, 6, 196, 36, // Skip to: 13355
/* 3943 */    MCD_OPC_Decode, 51, 99, // Opcode: ADDVI_B
/* 3946 */    MCD_OPC_FilterValue, 1, 7, 0, // Skip to: 3957
/* 3950 */    MCD_OPC_CheckPredicate, 6, 185, 36, // Skip to: 13355
/* 3954 */    MCD_OPC_Decode, 53, 100, // Opcode: ADDVI_H
/* 3957 */    MCD_OPC_FilterValue, 2, 7, 0, // Skip to: 3968
/* 3961 */    MCD_OPC_CheckPredicate, 6, 174, 36, // Skip to: 13355
/* 3965 */    MCD_OPC_Decode, 54, 101, // Opcode: ADDVI_W
/* 3968 */    MCD_OPC_FilterValue, 3, 7, 0, // Skip to: 3979
/* 3972 */    MCD_OPC_CheckPredicate, 6, 163, 36, // Skip to: 13355
/* 3976 */    MCD_OPC_Decode, 52, 102, // Opcode: ADDVI_D
/* 3979 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 3991
/* 3983 */    MCD_OPC_CheckPredicate, 6, 152, 36, // Skip to: 13355
/* 3987 */    MCD_OPC_Decode, 154, 12, 99, // Opcode: SUBVI_B
/* 3991 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 4003
/* 3995 */    MCD_OPC_CheckPredicate, 6, 140, 36, // Skip to: 13355
/* 3999 */    MCD_OPC_Decode, 156, 12, 100, // Opcode: SUBVI_H
/* 4003 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 4015
/* 4007 */    MCD_OPC_CheckPredicate, 6, 128, 36, // Skip to: 13355
/* 4011 */    MCD_OPC_Decode, 157, 12, 101, // Opcode: SUBVI_W
/* 4015 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 4027
/* 4019 */    MCD_OPC_CheckPredicate, 6, 116, 36, // Skip to: 13355
/* 4023 */    MCD_OPC_Decode, 155, 12, 102, // Opcode: SUBVI_D
/* 4027 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 4039
/* 4031 */    MCD_OPC_CheckPredicate, 6, 104, 36, // Skip to: 13355
/* 4035 */    MCD_OPC_Decode, 247, 7, 99, // Opcode: MAXI_S_B
/* 4039 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 4051
/* 4043 */    MCD_OPC_CheckPredicate, 6, 92, 36, // Skip to: 13355
/* 4047 */    MCD_OPC_Decode, 249, 7, 100, // Opcode: MAXI_S_H
/* 4051 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 4063
/* 4055 */    MCD_OPC_CheckPredicate, 6, 80, 36, // Skip to: 13355
/* 4059 */    MCD_OPC_Decode, 250, 7, 101, // Opcode: MAXI_S_W
/* 4063 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 4075
/* 4067 */    MCD_OPC_CheckPredicate, 6, 68, 36, // Skip to: 13355
/* 4071 */    MCD_OPC_Decode, 248, 7, 102, // Opcode: MAXI_S_D
/* 4075 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 4087
/* 4079 */    MCD_OPC_CheckPredicate, 6, 56, 36, // Skip to: 13355
/* 4083 */    MCD_OPC_Decode, 251, 7, 99, // Opcode: MAXI_U_B
/* 4087 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 4099
/* 4091 */    MCD_OPC_CheckPredicate, 6, 44, 36, // Skip to: 13355
/* 4095 */    MCD_OPC_Decode, 253, 7, 100, // Opcode: MAXI_U_H
/* 4099 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 4111
/* 4103 */    MCD_OPC_CheckPredicate, 6, 32, 36, // Skip to: 13355
/* 4107 */    MCD_OPC_Decode, 254, 7, 101, // Opcode: MAXI_U_W
/* 4111 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 4123
/* 4115 */    MCD_OPC_CheckPredicate, 6, 20, 36, // Skip to: 13355
/* 4119 */    MCD_OPC_Decode, 252, 7, 102, // Opcode: MAXI_U_D
/* 4123 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 4135
/* 4127 */    MCD_OPC_CheckPredicate, 6, 8, 36, // Skip to: 13355
/* 4131 */    MCD_OPC_Decode, 160, 8, 99, // Opcode: MINI_S_B
/* 4135 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 4147
/* 4139 */    MCD_OPC_CheckPredicate, 6, 252, 35, // Skip to: 13355
/* 4143 */    MCD_OPC_Decode, 162, 8, 100, // Opcode: MINI_S_H
/* 4147 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 4159
/* 4151 */    MCD_OPC_CheckPredicate, 6, 240, 35, // Skip to: 13355
/* 4155 */    MCD_OPC_Decode, 163, 8, 101, // Opcode: MINI_S_W
/* 4159 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 4171
/* 4163 */    MCD_OPC_CheckPredicate, 6, 228, 35, // Skip to: 13355
/* 4167 */    MCD_OPC_Decode, 161, 8, 102, // Opcode: MINI_S_D
/* 4171 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 4183
/* 4175 */    MCD_OPC_CheckPredicate, 6, 216, 35, // Skip to: 13355
/* 4179 */    MCD_OPC_Decode, 164, 8, 99, // Opcode: MINI_U_B
/* 4183 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 4195
/* 4187 */    MCD_OPC_CheckPredicate, 6, 204, 35, // Skip to: 13355
/* 4191 */    MCD_OPC_Decode, 166, 8, 100, // Opcode: MINI_U_H
/* 4195 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 4207
/* 4199 */    MCD_OPC_CheckPredicate, 6, 192, 35, // Skip to: 13355
/* 4203 */    MCD_OPC_Decode, 167, 8, 101, // Opcode: MINI_U_W
/* 4207 */    MCD_OPC_FilterValue, 23, 184, 35, // Skip to: 13355
/* 4211 */    MCD_OPC_CheckPredicate, 6, 180, 35, // Skip to: 13355
/* 4215 */    MCD_OPC_Decode, 165, 8, 102, // Opcode: MINI_U_D
/* 4219 */    MCD_OPC_FilterValue, 7, 35, 1, // Skip to: 4514
/* 4223 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 4226 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4238
/* 4230 */    MCD_OPC_CheckPredicate, 6, 161, 35, // Skip to: 13355
/* 4234 */    MCD_OPC_Decode, 210, 2, 99, // Opcode: CEQI_B
/* 4238 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 4250
/* 4242 */    MCD_OPC_CheckPredicate, 6, 149, 35, // Skip to: 13355
/* 4246 */    MCD_OPC_Decode, 212, 2, 100, // Opcode: CEQI_H
/* 4250 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 4262
/* 4254 */    MCD_OPC_CheckPredicate, 6, 137, 35, // Skip to: 13355
/* 4258 */    MCD_OPC_Decode, 213, 2, 101, // Opcode: CEQI_W
/* 4262 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 4274
/* 4266 */    MCD_OPC_CheckPredicate, 6, 125, 35, // Skip to: 13355
/* 4270 */    MCD_OPC_Decode, 211, 2, 102, // Opcode: CEQI_D
/* 4274 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 4286
/* 4278 */    MCD_OPC_CheckPredicate, 6, 113, 35, // Skip to: 13355
/* 4282 */    MCD_OPC_Decode, 244, 2, 99, // Opcode: CLTI_S_B
/* 4286 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 4298
/* 4290 */    MCD_OPC_CheckPredicate, 6, 101, 35, // Skip to: 13355
/* 4294 */    MCD_OPC_Decode, 246, 2, 100, // Opcode: CLTI_S_H
/* 4298 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 4310
/* 4302 */    MCD_OPC_CheckPredicate, 6, 89, 35, // Skip to: 13355
/* 4306 */    MCD_OPC_Decode, 247, 2, 101, // Opcode: CLTI_S_W
/* 4310 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 4322
/* 4314 */    MCD_OPC_CheckPredicate, 6, 77, 35, // Skip to: 13355
/* 4318 */    MCD_OPC_Decode, 245, 2, 102, // Opcode: CLTI_S_D
/* 4322 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 4334
/* 4326 */    MCD_OPC_CheckPredicate, 6, 65, 35, // Skip to: 13355
/* 4330 */    MCD_OPC_Decode, 248, 2, 99, // Opcode: CLTI_U_B
/* 4334 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 4346
/* 4338 */    MCD_OPC_CheckPredicate, 6, 53, 35, // Skip to: 13355
/* 4342 */    MCD_OPC_Decode, 250, 2, 100, // Opcode: CLTI_U_H
/* 4346 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 4358
/* 4350 */    MCD_OPC_CheckPredicate, 6, 41, 35, // Skip to: 13355
/* 4354 */    MCD_OPC_Decode, 251, 2, 101, // Opcode: CLTI_U_W
/* 4358 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 4370
/* 4362 */    MCD_OPC_CheckPredicate, 6, 29, 35, // Skip to: 13355
/* 4366 */    MCD_OPC_Decode, 249, 2, 102, // Opcode: CLTI_U_D
/* 4370 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 4382
/* 4374 */    MCD_OPC_CheckPredicate, 6, 17, 35, // Skip to: 13355
/* 4378 */    MCD_OPC_Decode, 225, 2, 99, // Opcode: CLEI_S_B
/* 4382 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 4394
/* 4386 */    MCD_OPC_CheckPredicate, 6, 5, 35, // Skip to: 13355
/* 4390 */    MCD_OPC_Decode, 227, 2, 100, // Opcode: CLEI_S_H
/* 4394 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 4406
/* 4398 */    MCD_OPC_CheckPredicate, 6, 249, 34, // Skip to: 13355
/* 4402 */    MCD_OPC_Decode, 228, 2, 101, // Opcode: CLEI_S_W
/* 4406 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 4418
/* 4410 */    MCD_OPC_CheckPredicate, 6, 237, 34, // Skip to: 13355
/* 4414 */    MCD_OPC_Decode, 226, 2, 102, // Opcode: CLEI_S_D
/* 4418 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 4430
/* 4422 */    MCD_OPC_CheckPredicate, 6, 225, 34, // Skip to: 13355
/* 4426 */    MCD_OPC_Decode, 229, 2, 99, // Opcode: CLEI_U_B
/* 4430 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 4442
/* 4434 */    MCD_OPC_CheckPredicate, 6, 213, 34, // Skip to: 13355
/* 4438 */    MCD_OPC_Decode, 231, 2, 100, // Opcode: CLEI_U_H
/* 4442 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 4454
/* 4446 */    MCD_OPC_CheckPredicate, 6, 201, 34, // Skip to: 13355
/* 4450 */    MCD_OPC_Decode, 232, 2, 101, // Opcode: CLEI_U_W
/* 4454 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 4466
/* 4458 */    MCD_OPC_CheckPredicate, 6, 189, 34, // Skip to: 13355
/* 4462 */    MCD_OPC_Decode, 230, 2, 102, // Opcode: CLEI_U_D
/* 4466 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 4478
/* 4470 */    MCD_OPC_CheckPredicate, 6, 177, 34, // Skip to: 13355
/* 4474 */    MCD_OPC_Decode, 140, 7, 103, // Opcode: LDI_B
/* 4478 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 4490
/* 4482 */    MCD_OPC_CheckPredicate, 6, 165, 34, // Skip to: 13355
/* 4486 */    MCD_OPC_Decode, 142, 7, 104, // Opcode: LDI_H
/* 4490 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 4502
/* 4494 */    MCD_OPC_CheckPredicate, 6, 153, 34, // Skip to: 13355
/* 4498 */    MCD_OPC_Decode, 143, 7, 105, // Opcode: LDI_W
/* 4502 */    MCD_OPC_FilterValue, 27, 145, 34, // Skip to: 13355
/* 4506 */    MCD_OPC_CheckPredicate, 6, 141, 34, // Skip to: 13355
/* 4510 */    MCD_OPC_Decode, 141, 7, 106, // Opcode: LDI_D
/* 4514 */    MCD_OPC_FilterValue, 9, 35, 2, // Skip to: 5065
/* 4518 */    MCD_OPC_ExtractField, 22, 4,  // Inst{25-22} ...
/* 4521 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4533
/* 4525 */    MCD_OPC_CheckPredicate, 6, 122, 34, // Skip to: 13355
/* 4529 */    MCD_OPC_Decode, 166, 11, 107, // Opcode: SLLI_D
/* 4533 */    MCD_OPC_FilterValue, 1, 52, 0, // Skip to: 4589
/* 4537 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4540 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4552
/* 4544 */    MCD_OPC_CheckPredicate, 6, 103, 34, // Skip to: 13355
/* 4548 */    MCD_OPC_Decode, 168, 11, 101, // Opcode: SLLI_W
/* 4552 */    MCD_OPC_FilterValue, 1, 95, 34, // Skip to: 13355
/* 4556 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4559 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4571
/* 4563 */    MCD_OPC_CheckPredicate, 6, 84, 34, // Skip to: 13355
/* 4567 */    MCD_OPC_Decode, 167, 11, 108, // Opcode: SLLI_H
/* 4571 */    MCD_OPC_FilterValue, 1, 76, 34, // Skip to: 13355
/* 4575 */    MCD_OPC_CheckPredicate, 6, 72, 34, // Skip to: 13355
/* 4579 */    MCD_OPC_CheckField, 19, 1, 0, 66, 34, // Skip to: 13355
/* 4585 */    MCD_OPC_Decode, 165, 11, 109, // Opcode: SLLI_B
/* 4589 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 4601
/* 4593 */    MCD_OPC_CheckPredicate, 6, 54, 34, // Skip to: 13355
/* 4597 */    MCD_OPC_Decode, 205, 11, 107, // Opcode: SRAI_D
/* 4601 */    MCD_OPC_FilterValue, 3, 52, 0, // Skip to: 4657
/* 4605 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4608 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4620
/* 4612 */    MCD_OPC_CheckPredicate, 6, 35, 34, // Skip to: 13355
/* 4616 */    MCD_OPC_Decode, 207, 11, 101, // Opcode: SRAI_W
/* 4620 */    MCD_OPC_FilterValue, 1, 27, 34, // Skip to: 13355
/* 4624 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4627 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4639
/* 4631 */    MCD_OPC_CheckPredicate, 6, 16, 34, // Skip to: 13355
/* 4635 */    MCD_OPC_Decode, 206, 11, 108, // Opcode: SRAI_H
/* 4639 */    MCD_OPC_FilterValue, 1, 8, 34, // Skip to: 13355
/* 4643 */    MCD_OPC_CheckPredicate, 6, 4, 34, // Skip to: 13355
/* 4647 */    MCD_OPC_CheckField, 19, 1, 0, 254, 33, // Skip to: 13355
/* 4653 */    MCD_OPC_Decode, 204, 11, 109, // Opcode: SRAI_B
/* 4657 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 4669
/* 4661 */    MCD_OPC_CheckPredicate, 6, 242, 33, // Skip to: 13355
/* 4665 */    MCD_OPC_Decode, 225, 11, 107, // Opcode: SRLI_D
/* 4669 */    MCD_OPC_FilterValue, 5, 52, 0, // Skip to: 4725
/* 4673 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4676 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4688
/* 4680 */    MCD_OPC_CheckPredicate, 6, 223, 33, // Skip to: 13355
/* 4684 */    MCD_OPC_Decode, 227, 11, 101, // Opcode: SRLI_W
/* 4688 */    MCD_OPC_FilterValue, 1, 215, 33, // Skip to: 13355
/* 4692 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4695 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4707
/* 4699 */    MCD_OPC_CheckPredicate, 6, 204, 33, // Skip to: 13355
/* 4703 */    MCD_OPC_Decode, 226, 11, 108, // Opcode: SRLI_H
/* 4707 */    MCD_OPC_FilterValue, 1, 196, 33, // Skip to: 13355
/* 4711 */    MCD_OPC_CheckPredicate, 6, 192, 33, // Skip to: 13355
/* 4715 */    MCD_OPC_CheckField, 19, 1, 0, 186, 33, // Skip to: 13355
/* 4721 */    MCD_OPC_Decode, 224, 11, 109, // Opcode: SRLI_B
/* 4725 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 4737
/* 4729 */    MCD_OPC_CheckPredicate, 6, 174, 33, // Skip to: 13355
/* 4733 */    MCD_OPC_Decode, 184, 1, 107, // Opcode: BCLRI_D
/* 4737 */    MCD_OPC_FilterValue, 7, 52, 0, // Skip to: 4793
/* 4741 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4744 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4756
/* 4748 */    MCD_OPC_CheckPredicate, 6, 155, 33, // Skip to: 13355
/* 4752 */    MCD_OPC_Decode, 186, 1, 101, // Opcode: BCLRI_W
/* 4756 */    MCD_OPC_FilterValue, 1, 147, 33, // Skip to: 13355
/* 4760 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4763 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4775
/* 4767 */    MCD_OPC_CheckPredicate, 6, 136, 33, // Skip to: 13355
/* 4771 */    MCD_OPC_Decode, 185, 1, 108, // Opcode: BCLRI_H
/* 4775 */    MCD_OPC_FilterValue, 1, 128, 33, // Skip to: 13355
/* 4779 */    MCD_OPC_CheckPredicate, 6, 124, 33, // Skip to: 13355
/* 4783 */    MCD_OPC_CheckField, 19, 1, 0, 118, 33, // Skip to: 13355
/* 4789 */    MCD_OPC_Decode, 183, 1, 109, // Opcode: BCLRI_B
/* 4793 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 4805
/* 4797 */    MCD_OPC_CheckPredicate, 6, 106, 33, // Skip to: 13355
/* 4801 */    MCD_OPC_Decode, 164, 2, 107, // Opcode: BSETI_D
/* 4805 */    MCD_OPC_FilterValue, 9, 52, 0, // Skip to: 4861
/* 4809 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4812 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4824
/* 4816 */    MCD_OPC_CheckPredicate, 6, 87, 33, // Skip to: 13355
/* 4820 */    MCD_OPC_Decode, 166, 2, 101, // Opcode: BSETI_W
/* 4824 */    MCD_OPC_FilterValue, 1, 79, 33, // Skip to: 13355
/* 4828 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4831 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4843
/* 4835 */    MCD_OPC_CheckPredicate, 6, 68, 33, // Skip to: 13355
/* 4839 */    MCD_OPC_Decode, 165, 2, 108, // Opcode: BSETI_H
/* 4843 */    MCD_OPC_FilterValue, 1, 60, 33, // Skip to: 13355
/* 4847 */    MCD_OPC_CheckPredicate, 6, 56, 33, // Skip to: 13355
/* 4851 */    MCD_OPC_CheckField, 19, 1, 0, 50, 33, // Skip to: 13355
/* 4857 */    MCD_OPC_Decode, 163, 2, 109, // Opcode: BSETI_B
/* 4861 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 4873
/* 4865 */    MCD_OPC_CheckPredicate, 6, 38, 33, // Skip to: 13355
/* 4869 */    MCD_OPC_Decode, 133, 2, 107, // Opcode: BNEGI_D
/* 4873 */    MCD_OPC_FilterValue, 11, 52, 0, // Skip to: 4929
/* 4877 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4880 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4892
/* 4884 */    MCD_OPC_CheckPredicate, 6, 19, 33, // Skip to: 13355
/* 4888 */    MCD_OPC_Decode, 135, 2, 101, // Opcode: BNEGI_W
/* 4892 */    MCD_OPC_FilterValue, 1, 11, 33, // Skip to: 13355
/* 4896 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4899 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4911
/* 4903 */    MCD_OPC_CheckPredicate, 6, 0, 33, // Skip to: 13355
/* 4907 */    MCD_OPC_Decode, 134, 2, 108, // Opcode: BNEGI_H
/* 4911 */    MCD_OPC_FilterValue, 1, 248, 32, // Skip to: 13355
/* 4915 */    MCD_OPC_CheckPredicate, 6, 244, 32, // Skip to: 13355
/* 4919 */    MCD_OPC_CheckField, 19, 1, 0, 238, 32, // Skip to: 13355
/* 4925 */    MCD_OPC_Decode, 132, 2, 109, // Opcode: BNEGI_B
/* 4929 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 4941
/* 4933 */    MCD_OPC_CheckPredicate, 6, 226, 32, // Skip to: 13355
/* 4937 */    MCD_OPC_Decode, 218, 1, 110, // Opcode: BINSLI_D
/* 4941 */    MCD_OPC_FilterValue, 13, 52, 0, // Skip to: 4997
/* 4945 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 4948 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4960
/* 4952 */    MCD_OPC_CheckPredicate, 6, 207, 32, // Skip to: 13355
/* 4956 */    MCD_OPC_Decode, 220, 1, 111, // Opcode: BINSLI_W
/* 4960 */    MCD_OPC_FilterValue, 1, 199, 32, // Skip to: 13355
/* 4964 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 4967 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 4979
/* 4971 */    MCD_OPC_CheckPredicate, 6, 188, 32, // Skip to: 13355
/* 4975 */    MCD_OPC_Decode, 219, 1, 112, // Opcode: BINSLI_H
/* 4979 */    MCD_OPC_FilterValue, 1, 180, 32, // Skip to: 13355
/* 4983 */    MCD_OPC_CheckPredicate, 6, 176, 32, // Skip to: 13355
/* 4987 */    MCD_OPC_CheckField, 19, 1, 0, 170, 32, // Skip to: 13355
/* 4993 */    MCD_OPC_Decode, 217, 1, 113, // Opcode: BINSLI_B
/* 4997 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 5009
/* 5001 */    MCD_OPC_CheckPredicate, 6, 158, 32, // Skip to: 13355
/* 5005 */    MCD_OPC_Decode, 226, 1, 110, // Opcode: BINSRI_D
/* 5009 */    MCD_OPC_FilterValue, 15, 150, 32, // Skip to: 13355
/* 5013 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 5016 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5028
/* 5020 */    MCD_OPC_CheckPredicate, 6, 139, 32, // Skip to: 13355
/* 5024 */    MCD_OPC_Decode, 228, 1, 111, // Opcode: BINSRI_W
/* 5028 */    MCD_OPC_FilterValue, 1, 131, 32, // Skip to: 13355
/* 5032 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 5035 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5047
/* 5039 */    MCD_OPC_CheckPredicate, 6, 120, 32, // Skip to: 13355
/* 5043 */    MCD_OPC_Decode, 227, 1, 112, // Opcode: BINSRI_H
/* 5047 */    MCD_OPC_FilterValue, 1, 112, 32, // Skip to: 13355
/* 5051 */    MCD_OPC_CheckPredicate, 6, 108, 32, // Skip to: 13355
/* 5055 */    MCD_OPC_CheckField, 19, 1, 0, 102, 32, // Skip to: 13355
/* 5061 */    MCD_OPC_Decode, 225, 1, 113, // Opcode: BINSRI_B
/* 5065 */    MCD_OPC_FilterValue, 10, 19, 1, // Skip to: 5344
/* 5069 */    MCD_OPC_ExtractField, 22, 4,  // Inst{25-22} ...
/* 5072 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5084
/* 5076 */    MCD_OPC_CheckPredicate, 6, 83, 32, // Skip to: 13355
/* 5080 */    MCD_OPC_Decode, 204, 10, 107, // Opcode: SAT_S_D
/* 5084 */    MCD_OPC_FilterValue, 1, 52, 0, // Skip to: 5140
/* 5088 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 5091 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5103
/* 5095 */    MCD_OPC_CheckPredicate, 6, 64, 32, // Skip to: 13355
/* 5099 */    MCD_OPC_Decode, 206, 10, 101, // Opcode: SAT_S_W
/* 5103 */    MCD_OPC_FilterValue, 1, 56, 32, // Skip to: 13355
/* 5107 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 5110 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5122
/* 5114 */    MCD_OPC_CheckPredicate, 6, 45, 32, // Skip to: 13355
/* 5118 */    MCD_OPC_Decode, 205, 10, 108, // Opcode: SAT_S_H
/* 5122 */    MCD_OPC_FilterValue, 1, 37, 32, // Skip to: 13355
/* 5126 */    MCD_OPC_CheckPredicate, 6, 33, 32, // Skip to: 13355
/* 5130 */    MCD_OPC_CheckField, 19, 1, 0, 27, 32, // Skip to: 13355
/* 5136 */    MCD_OPC_Decode, 203, 10, 109, // Opcode: SAT_S_B
/* 5140 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 5152
/* 5144 */    MCD_OPC_CheckPredicate, 6, 15, 32, // Skip to: 13355
/* 5148 */    MCD_OPC_Decode, 208, 10, 107, // Opcode: SAT_U_D
/* 5152 */    MCD_OPC_FilterValue, 3, 52, 0, // Skip to: 5208
/* 5156 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 5159 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5171
/* 5163 */    MCD_OPC_CheckPredicate, 6, 252, 31, // Skip to: 13355
/* 5167 */    MCD_OPC_Decode, 210, 10, 101, // Opcode: SAT_U_W
/* 5171 */    MCD_OPC_FilterValue, 1, 244, 31, // Skip to: 13355
/* 5175 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 5178 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5190
/* 5182 */    MCD_OPC_CheckPredicate, 6, 233, 31, // Skip to: 13355
/* 5186 */    MCD_OPC_Decode, 209, 10, 108, // Opcode: SAT_U_H
/* 5190 */    MCD_OPC_FilterValue, 1, 225, 31, // Skip to: 13355
/* 5194 */    MCD_OPC_CheckPredicate, 6, 221, 31, // Skip to: 13355
/* 5198 */    MCD_OPC_CheckField, 19, 1, 0, 215, 31, // Skip to: 13355
/* 5204 */    MCD_OPC_Decode, 207, 10, 109, // Opcode: SAT_U_B
/* 5208 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 5220
/* 5212 */    MCD_OPC_CheckPredicate, 6, 203, 31, // Skip to: 13355
/* 5216 */    MCD_OPC_Decode, 209, 11, 107, // Opcode: SRARI_D
/* 5220 */    MCD_OPC_FilterValue, 5, 52, 0, // Skip to: 5276
/* 5224 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 5227 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5239
/* 5231 */    MCD_OPC_CheckPredicate, 6, 184, 31, // Skip to: 13355
/* 5235 */    MCD_OPC_Decode, 211, 11, 101, // Opcode: SRARI_W
/* 5239 */    MCD_OPC_FilterValue, 1, 176, 31, // Skip to: 13355
/* 5243 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 5246 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5258
/* 5250 */    MCD_OPC_CheckPredicate, 6, 165, 31, // Skip to: 13355
/* 5254 */    MCD_OPC_Decode, 210, 11, 108, // Opcode: SRARI_H
/* 5258 */    MCD_OPC_FilterValue, 1, 157, 31, // Skip to: 13355
/* 5262 */    MCD_OPC_CheckPredicate, 6, 153, 31, // Skip to: 13355
/* 5266 */    MCD_OPC_CheckField, 19, 1, 0, 147, 31, // Skip to: 13355
/* 5272 */    MCD_OPC_Decode, 208, 11, 109, // Opcode: SRARI_B
/* 5276 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 5288
/* 5280 */    MCD_OPC_CheckPredicate, 6, 135, 31, // Skip to: 13355
/* 5284 */    MCD_OPC_Decode, 229, 11, 107, // Opcode: SRLRI_D
/* 5288 */    MCD_OPC_FilterValue, 7, 127, 31, // Skip to: 13355
/* 5292 */    MCD_OPC_ExtractField, 21, 1,  // Inst{21} ...
/* 5295 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5307
/* 5299 */    MCD_OPC_CheckPredicate, 6, 116, 31, // Skip to: 13355
/* 5303 */    MCD_OPC_Decode, 231, 11, 101, // Opcode: SRLRI_W
/* 5307 */    MCD_OPC_FilterValue, 1, 108, 31, // Skip to: 13355
/* 5311 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 5314 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5326
/* 5318 */    MCD_OPC_CheckPredicate, 6, 97, 31, // Skip to: 13355
/* 5322 */    MCD_OPC_Decode, 230, 11, 108, // Opcode: SRLRI_H
/* 5326 */    MCD_OPC_FilterValue, 1, 89, 31, // Skip to: 13355
/* 5330 */    MCD_OPC_CheckPredicate, 6, 85, 31, // Skip to: 13355
/* 5334 */    MCD_OPC_CheckField, 19, 1, 0, 79, 31, // Skip to: 13355
/* 5340 */    MCD_OPC_Decode, 228, 11, 109, // Opcode: SRLRI_B
/* 5344 */    MCD_OPC_FilterValue, 13, 131, 1, // Skip to: 5735
/* 5348 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5351 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 5363
/* 5355 */    MCD_OPC_CheckPredicate, 6, 60, 31, // Skip to: 13355
/* 5359 */    MCD_OPC_Decode, 171, 11, 114, // Opcode: SLL_B
/* 5363 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 5375
/* 5367 */    MCD_OPC_CheckPredicate, 6, 48, 31, // Skip to: 13355
/* 5371 */    MCD_OPC_Decode, 173, 11, 115, // Opcode: SLL_H
/* 5375 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 5387
/* 5379 */    MCD_OPC_CheckPredicate, 6, 36, 31, // Skip to: 13355
/* 5383 */    MCD_OPC_Decode, 175, 11, 116, // Opcode: SLL_W
/* 5387 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 5399
/* 5391 */    MCD_OPC_CheckPredicate, 6, 24, 31, // Skip to: 13355
/* 5395 */    MCD_OPC_Decode, 172, 11, 117, // Opcode: SLL_D
/* 5399 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 5411
/* 5403 */    MCD_OPC_CheckPredicate, 6, 12, 31, // Skip to: 13355
/* 5407 */    MCD_OPC_Decode, 218, 11, 114, // Opcode: SRA_B
/* 5411 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 5423
/* 5415 */    MCD_OPC_CheckPredicate, 6, 0, 31, // Skip to: 13355
/* 5419 */    MCD_OPC_Decode, 220, 11, 115, // Opcode: SRA_H
/* 5423 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 5435
/* 5427 */    MCD_OPC_CheckPredicate, 6, 244, 30, // Skip to: 13355
/* 5431 */    MCD_OPC_Decode, 222, 11, 116, // Opcode: SRA_W
/* 5435 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 5447
/* 5439 */    MCD_OPC_CheckPredicate, 6, 232, 30, // Skip to: 13355
/* 5443 */    MCD_OPC_Decode, 219, 11, 117, // Opcode: SRA_D
/* 5447 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 5459
/* 5451 */    MCD_OPC_CheckPredicate, 6, 220, 30, // Skip to: 13355
/* 5455 */    MCD_OPC_Decode, 238, 11, 114, // Opcode: SRL_B
/* 5459 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 5471
/* 5463 */    MCD_OPC_CheckPredicate, 6, 208, 30, // Skip to: 13355
/* 5467 */    MCD_OPC_Decode, 240, 11, 115, // Opcode: SRL_H
/* 5471 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 5483
/* 5475 */    MCD_OPC_CheckPredicate, 6, 196, 30, // Skip to: 13355
/* 5479 */    MCD_OPC_Decode, 242, 11, 116, // Opcode: SRL_W
/* 5483 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 5495
/* 5487 */    MCD_OPC_CheckPredicate, 6, 184, 30, // Skip to: 13355
/* 5491 */    MCD_OPC_Decode, 239, 11, 117, // Opcode: SRL_D
/* 5495 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 5507
/* 5499 */    MCD_OPC_CheckPredicate, 6, 172, 30, // Skip to: 13355
/* 5503 */    MCD_OPC_Decode, 187, 1, 114, // Opcode: BCLR_B
/* 5507 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 5519
/* 5511 */    MCD_OPC_CheckPredicate, 6, 160, 30, // Skip to: 13355
/* 5515 */    MCD_OPC_Decode, 189, 1, 115, // Opcode: BCLR_H
/* 5519 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 5531
/* 5523 */    MCD_OPC_CheckPredicate, 6, 148, 30, // Skip to: 13355
/* 5527 */    MCD_OPC_Decode, 190, 1, 116, // Opcode: BCLR_W
/* 5531 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 5543
/* 5535 */    MCD_OPC_CheckPredicate, 6, 136, 30, // Skip to: 13355
/* 5539 */    MCD_OPC_Decode, 188, 1, 117, // Opcode: BCLR_D
/* 5543 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 5555
/* 5547 */    MCD_OPC_CheckPredicate, 6, 124, 30, // Skip to: 13355
/* 5551 */    MCD_OPC_Decode, 167, 2, 114, // Opcode: BSET_B
/* 5555 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 5567
/* 5559 */    MCD_OPC_CheckPredicate, 6, 112, 30, // Skip to: 13355
/* 5563 */    MCD_OPC_Decode, 169, 2, 115, // Opcode: BSET_H
/* 5567 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 5579
/* 5571 */    MCD_OPC_CheckPredicate, 6, 100, 30, // Skip to: 13355
/* 5575 */    MCD_OPC_Decode, 170, 2, 116, // Opcode: BSET_W
/* 5579 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 5591
/* 5583 */    MCD_OPC_CheckPredicate, 6, 88, 30, // Skip to: 13355
/* 5587 */    MCD_OPC_Decode, 168, 2, 117, // Opcode: BSET_D
/* 5591 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 5603
/* 5595 */    MCD_OPC_CheckPredicate, 6, 76, 30, // Skip to: 13355
/* 5599 */    MCD_OPC_Decode, 136, 2, 114, // Opcode: BNEG_B
/* 5603 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 5615
/* 5607 */    MCD_OPC_CheckPredicate, 6, 64, 30, // Skip to: 13355
/* 5611 */    MCD_OPC_Decode, 138, 2, 115, // Opcode: BNEG_H
/* 5615 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 5627
/* 5619 */    MCD_OPC_CheckPredicate, 6, 52, 30, // Skip to: 13355
/* 5623 */    MCD_OPC_Decode, 139, 2, 116, // Opcode: BNEG_W
/* 5627 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 5639
/* 5631 */    MCD_OPC_CheckPredicate, 6, 40, 30, // Skip to: 13355
/* 5635 */    MCD_OPC_Decode, 137, 2, 117, // Opcode: BNEG_D
/* 5639 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 5651
/* 5643 */    MCD_OPC_CheckPredicate, 6, 28, 30, // Skip to: 13355
/* 5647 */    MCD_OPC_Decode, 221, 1, 118, // Opcode: BINSL_B
/* 5651 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 5663
/* 5655 */    MCD_OPC_CheckPredicate, 6, 16, 30, // Skip to: 13355
/* 5659 */    MCD_OPC_Decode, 223, 1, 119, // Opcode: BINSL_H
/* 5663 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 5675
/* 5667 */    MCD_OPC_CheckPredicate, 6, 4, 30, // Skip to: 13355
/* 5671 */    MCD_OPC_Decode, 224, 1, 120, // Opcode: BINSL_W
/* 5675 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 5687
/* 5679 */    MCD_OPC_CheckPredicate, 6, 248, 29, // Skip to: 13355
/* 5683 */    MCD_OPC_Decode, 222, 1, 121, // Opcode: BINSL_D
/* 5687 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 5699
/* 5691 */    MCD_OPC_CheckPredicate, 6, 236, 29, // Skip to: 13355
/* 5695 */    MCD_OPC_Decode, 229, 1, 118, // Opcode: BINSR_B
/* 5699 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 5711
/* 5703 */    MCD_OPC_CheckPredicate, 6, 224, 29, // Skip to: 13355
/* 5707 */    MCD_OPC_Decode, 231, 1, 119, // Opcode: BINSR_H
/* 5711 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 5723
/* 5715 */    MCD_OPC_CheckPredicate, 6, 212, 29, // Skip to: 13355
/* 5719 */    MCD_OPC_Decode, 232, 1, 120, // Opcode: BINSR_W
/* 5723 */    MCD_OPC_FilterValue, 31, 204, 29, // Skip to: 13355
/* 5727 */    MCD_OPC_CheckPredicate, 6, 200, 29, // Skip to: 13355
/* 5731 */    MCD_OPC_Decode, 230, 1, 121, // Opcode: BINSR_D
/* 5735 */    MCD_OPC_FilterValue, 14, 127, 1, // Skip to: 6122
/* 5739 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5742 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 5753
/* 5746 */    MCD_OPC_CheckPredicate, 6, 181, 29, // Skip to: 13355
/* 5750 */    MCD_OPC_Decode, 55, 114, // Opcode: ADDV_B
/* 5753 */    MCD_OPC_FilterValue, 1, 7, 0, // Skip to: 5764
/* 5757 */    MCD_OPC_CheckPredicate, 6, 170, 29, // Skip to: 13355
/* 5761 */    MCD_OPC_Decode, 57, 115, // Opcode: ADDV_H
/* 5764 */    MCD_OPC_FilterValue, 2, 7, 0, // Skip to: 5775
/* 5768 */    MCD_OPC_CheckPredicate, 6, 159, 29, // Skip to: 13355
/* 5772 */    MCD_OPC_Decode, 58, 116, // Opcode: ADDV_W
/* 5775 */    MCD_OPC_FilterValue, 3, 7, 0, // Skip to: 5786
/* 5779 */    MCD_OPC_CheckPredicate, 6, 148, 29, // Skip to: 13355
/* 5783 */    MCD_OPC_Decode, 56, 117, // Opcode: ADDV_D
/* 5786 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 5798
/* 5790 */    MCD_OPC_CheckPredicate, 6, 137, 29, // Skip to: 13355
/* 5794 */    MCD_OPC_Decode, 158, 12, 114, // Opcode: SUBV_B
/* 5798 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 5810
/* 5802 */    MCD_OPC_CheckPredicate, 6, 125, 29, // Skip to: 13355
/* 5806 */    MCD_OPC_Decode, 160, 12, 115, // Opcode: SUBV_H
/* 5810 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 5822
/* 5814 */    MCD_OPC_CheckPredicate, 6, 113, 29, // Skip to: 13355
/* 5818 */    MCD_OPC_Decode, 161, 12, 116, // Opcode: SUBV_W
/* 5822 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 5834
/* 5826 */    MCD_OPC_CheckPredicate, 6, 101, 29, // Skip to: 13355
/* 5830 */    MCD_OPC_Decode, 159, 12, 117, // Opcode: SUBV_D
/* 5834 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 5846
/* 5838 */    MCD_OPC_CheckPredicate, 6, 89, 29, // Skip to: 13355
/* 5842 */    MCD_OPC_Decode, 133, 8, 114, // Opcode: MAX_S_B
/* 5846 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 5858
/* 5850 */    MCD_OPC_CheckPredicate, 6, 77, 29, // Skip to: 13355
/* 5854 */    MCD_OPC_Decode, 135, 8, 115, // Opcode: MAX_S_H
/* 5858 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 5870
/* 5862 */    MCD_OPC_CheckPredicate, 6, 65, 29, // Skip to: 13355
/* 5866 */    MCD_OPC_Decode, 136, 8, 116, // Opcode: MAX_S_W
/* 5870 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 5882
/* 5874 */    MCD_OPC_CheckPredicate, 6, 53, 29, // Skip to: 13355
/* 5878 */    MCD_OPC_Decode, 134, 8, 117, // Opcode: MAX_S_D
/* 5882 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 5894
/* 5886 */    MCD_OPC_CheckPredicate, 6, 41, 29, // Skip to: 13355
/* 5890 */    MCD_OPC_Decode, 137, 8, 114, // Opcode: MAX_U_B
/* 5894 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 5906
/* 5898 */    MCD_OPC_CheckPredicate, 6, 29, 29, // Skip to: 13355
/* 5902 */    MCD_OPC_Decode, 139, 8, 115, // Opcode: MAX_U_H
/* 5906 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 5918
/* 5910 */    MCD_OPC_CheckPredicate, 6, 17, 29, // Skip to: 13355
/* 5914 */    MCD_OPC_Decode, 140, 8, 116, // Opcode: MAX_U_W
/* 5918 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 5930
/* 5922 */    MCD_OPC_CheckPredicate, 6, 5, 29, // Skip to: 13355
/* 5926 */    MCD_OPC_Decode, 138, 8, 117, // Opcode: MAX_U_D
/* 5930 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 5942
/* 5934 */    MCD_OPC_CheckPredicate, 6, 249, 28, // Skip to: 13355
/* 5938 */    MCD_OPC_Decode, 174, 8, 114, // Opcode: MIN_S_B
/* 5942 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 5954
/* 5946 */    MCD_OPC_CheckPredicate, 6, 237, 28, // Skip to: 13355
/* 5950 */    MCD_OPC_Decode, 176, 8, 115, // Opcode: MIN_S_H
/* 5954 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 5966
/* 5958 */    MCD_OPC_CheckPredicate, 6, 225, 28, // Skip to: 13355
/* 5962 */    MCD_OPC_Decode, 177, 8, 116, // Opcode: MIN_S_W
/* 5966 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 5978
/* 5970 */    MCD_OPC_CheckPredicate, 6, 213, 28, // Skip to: 13355
/* 5974 */    MCD_OPC_Decode, 175, 8, 117, // Opcode: MIN_S_D
/* 5978 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 5990
/* 5982 */    MCD_OPC_CheckPredicate, 6, 201, 28, // Skip to: 13355
/* 5986 */    MCD_OPC_Decode, 178, 8, 114, // Opcode: MIN_U_B
/* 5990 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 6002
/* 5994 */    MCD_OPC_CheckPredicate, 6, 189, 28, // Skip to: 13355
/* 5998 */    MCD_OPC_Decode, 180, 8, 115, // Opcode: MIN_U_H
/* 6002 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 6014
/* 6006 */    MCD_OPC_CheckPredicate, 6, 177, 28, // Skip to: 13355
/* 6010 */    MCD_OPC_Decode, 181, 8, 116, // Opcode: MIN_U_W
/* 6014 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 6026
/* 6018 */    MCD_OPC_CheckPredicate, 6, 165, 28, // Skip to: 13355
/* 6022 */    MCD_OPC_Decode, 179, 8, 117, // Opcode: MIN_U_D
/* 6026 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 6038
/* 6030 */    MCD_OPC_CheckPredicate, 6, 153, 28, // Skip to: 13355
/* 6034 */    MCD_OPC_Decode, 255, 7, 114, // Opcode: MAX_A_B
/* 6038 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 6050
/* 6042 */    MCD_OPC_CheckPredicate, 6, 141, 28, // Skip to: 13355
/* 6046 */    MCD_OPC_Decode, 129, 8, 115, // Opcode: MAX_A_H
/* 6050 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 6062
/* 6054 */    MCD_OPC_CheckPredicate, 6, 129, 28, // Skip to: 13355
/* 6058 */    MCD_OPC_Decode, 130, 8, 116, // Opcode: MAX_A_W
/* 6062 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 6074
/* 6066 */    MCD_OPC_CheckPredicate, 6, 117, 28, // Skip to: 13355
/* 6070 */    MCD_OPC_Decode, 128, 8, 117, // Opcode: MAX_A_D
/* 6074 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 6086
/* 6078 */    MCD_OPC_CheckPredicate, 6, 105, 28, // Skip to: 13355
/* 6082 */    MCD_OPC_Decode, 168, 8, 114, // Opcode: MIN_A_B
/* 6086 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 6098
/* 6090 */    MCD_OPC_CheckPredicate, 6, 93, 28, // Skip to: 13355
/* 6094 */    MCD_OPC_Decode, 170, 8, 115, // Opcode: MIN_A_H
/* 6098 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 6110
/* 6102 */    MCD_OPC_CheckPredicate, 6, 81, 28, // Skip to: 13355
/* 6106 */    MCD_OPC_Decode, 171, 8, 116, // Opcode: MIN_A_W
/* 6110 */    MCD_OPC_FilterValue, 31, 73, 28, // Skip to: 13355
/* 6114 */    MCD_OPC_CheckPredicate, 6, 69, 28, // Skip to: 13355
/* 6118 */    MCD_OPC_Decode, 169, 8, 117, // Opcode: MIN_A_D
/* 6122 */    MCD_OPC_FilterValue, 15, 243, 0, // Skip to: 6369
/* 6126 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 6129 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 6141
/* 6133 */    MCD_OPC_CheckPredicate, 6, 50, 28, // Skip to: 13355
/* 6137 */    MCD_OPC_Decode, 214, 2, 114, // Opcode: CEQ_B
/* 6141 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 6153
/* 6145 */    MCD_OPC_CheckPredicate, 6, 38, 28, // Skip to: 13355
/* 6149 */    MCD_OPC_Decode, 216, 2, 115, // Opcode: CEQ_H
/* 6153 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 6165
/* 6157 */    MCD_OPC_CheckPredicate, 6, 26, 28, // Skip to: 13355
/* 6161 */    MCD_OPC_Decode, 217, 2, 116, // Opcode: CEQ_W
/* 6165 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 6177
/* 6169 */    MCD_OPC_CheckPredicate, 6, 14, 28, // Skip to: 13355
/* 6173 */    MCD_OPC_Decode, 215, 2, 117, // Opcode: CEQ_D
/* 6177 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 6189
/* 6181 */    MCD_OPC_CheckPredicate, 6, 2, 28, // Skip to: 13355
/* 6185 */    MCD_OPC_Decode, 252, 2, 114, // Opcode: CLT_S_B
/* 6189 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 6201
/* 6193 */    MCD_OPC_CheckPredicate, 6, 246, 27, // Skip to: 13355
/* 6197 */    MCD_OPC_Decode, 254, 2, 115, // Opcode: CLT_S_H
/* 6201 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 6213
/* 6205 */    MCD_OPC_CheckPredicate, 6, 234, 27, // Skip to: 13355
/* 6209 */    MCD_OPC_Decode, 255, 2, 116, // Opcode: CLT_S_W
/* 6213 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 6225
/* 6217 */    MCD_OPC_CheckPredicate, 6, 222, 27, // Skip to: 13355
/* 6221 */    MCD_OPC_Decode, 253, 2, 117, // Opcode: CLT_S_D
/* 6225 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 6237
/* 6229 */    MCD_OPC_CheckPredicate, 6, 210, 27, // Skip to: 13355
/* 6233 */    MCD_OPC_Decode, 128, 3, 114, // Opcode: CLT_U_B
/* 6237 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 6249
/* 6241 */    MCD_OPC_CheckPredicate, 6, 198, 27, // Skip to: 13355
/* 6245 */    MCD_OPC_Decode, 130, 3, 115, // Opcode: CLT_U_H
/* 6249 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 6261
/* 6253 */    MCD_OPC_CheckPredicate, 6, 186, 27, // Skip to: 13355
/* 6257 */    MCD_OPC_Decode, 131, 3, 116, // Opcode: CLT_U_W
/* 6261 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 6273
/* 6265 */    MCD_OPC_CheckPredicate, 6, 174, 27, // Skip to: 13355
/* 6269 */    MCD_OPC_Decode, 129, 3, 117, // Opcode: CLT_U_D
/* 6273 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 6285
/* 6277 */    MCD_OPC_CheckPredicate, 6, 162, 27, // Skip to: 13355
/* 6281 */    MCD_OPC_Decode, 233, 2, 114, // Opcode: CLE_S_B
/* 6285 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 6297
/* 6289 */    MCD_OPC_CheckPredicate, 6, 150, 27, // Skip to: 13355
/* 6293 */    MCD_OPC_Decode, 235, 2, 115, // Opcode: CLE_S_H
/* 6297 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 6309
/* 6301 */    MCD_OPC_CheckPredicate, 6, 138, 27, // Skip to: 13355
/* 6305 */    MCD_OPC_Decode, 236, 2, 116, // Opcode: CLE_S_W
/* 6309 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 6321
/* 6313 */    MCD_OPC_CheckPredicate, 6, 126, 27, // Skip to: 13355
/* 6317 */    MCD_OPC_Decode, 234, 2, 117, // Opcode: CLE_S_D
/* 6321 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 6333
/* 6325 */    MCD_OPC_CheckPredicate, 6, 114, 27, // Skip to: 13355
/* 6329 */    MCD_OPC_Decode, 237, 2, 114, // Opcode: CLE_U_B
/* 6333 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 6345
/* 6337 */    MCD_OPC_CheckPredicate, 6, 102, 27, // Skip to: 13355
/* 6341 */    MCD_OPC_Decode, 239, 2, 115, // Opcode: CLE_U_H
/* 6345 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 6357
/* 6349 */    MCD_OPC_CheckPredicate, 6, 90, 27, // Skip to: 13355
/* 6353 */    MCD_OPC_Decode, 240, 2, 116, // Opcode: CLE_U_W
/* 6357 */    MCD_OPC_FilterValue, 23, 82, 27, // Skip to: 13355
/* 6361 */    MCD_OPC_CheckPredicate, 6, 78, 27, // Skip to: 13355
/* 6365 */    MCD_OPC_Decode, 238, 2, 117, // Opcode: CLE_U_D
/* 6369 */    MCD_OPC_FilterValue, 16, 115, 1, // Skip to: 6744
/* 6373 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 6376 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 6387
/* 6380 */    MCD_OPC_CheckPredicate, 6, 59, 27, // Skip to: 13355
/* 6384 */    MCD_OPC_Decode, 60, 114, // Opcode: ADD_A_B
/* 6387 */    MCD_OPC_FilterValue, 1, 7, 0, // Skip to: 6398
/* 6391 */    MCD_OPC_CheckPredicate, 6, 48, 27, // Skip to: 13355
/* 6395 */    MCD_OPC_Decode, 62, 115, // Opcode: ADD_A_H
/* 6398 */    MCD_OPC_FilterValue, 2, 7, 0, // Skip to: 6409
/* 6402 */    MCD_OPC_CheckPredicate, 6, 37, 27, // Skip to: 13355
/* 6406 */    MCD_OPC_Decode, 63, 116, // Opcode: ADD_A_W
/* 6409 */    MCD_OPC_FilterValue, 3, 7, 0, // Skip to: 6420
/* 6413 */    MCD_OPC_CheckPredicate, 6, 26, 27, // Skip to: 13355
/* 6417 */    MCD_OPC_Decode, 61, 117, // Opcode: ADD_A_D
/* 6420 */    MCD_OPC_FilterValue, 4, 7, 0, // Skip to: 6431
/* 6424 */    MCD_OPC_CheckPredicate, 6, 15, 27, // Skip to: 13355
/* 6428 */    MCD_OPC_Decode, 33, 114, // Opcode: ADDS_A_B
/* 6431 */    MCD_OPC_FilterValue, 5, 7, 0, // Skip to: 6442
/* 6435 */    MCD_OPC_CheckPredicate, 6, 4, 27, // Skip to: 13355
/* 6439 */    MCD_OPC_Decode, 35, 115, // Opcode: ADDS_A_H
/* 6442 */    MCD_OPC_FilterValue, 6, 7, 0, // Skip to: 6453
/* 6446 */    MCD_OPC_CheckPredicate, 6, 249, 26, // Skip to: 13355
/* 6450 */    MCD_OPC_Decode, 36, 116, // Opcode: ADDS_A_W
/* 6453 */    MCD_OPC_FilterValue, 7, 7, 0, // Skip to: 6464
/* 6457 */    MCD_OPC_CheckPredicate, 6, 238, 26, // Skip to: 13355
/* 6461 */    MCD_OPC_Decode, 34, 117, // Opcode: ADDS_A_D
/* 6464 */    MCD_OPC_FilterValue, 8, 7, 0, // Skip to: 6475
/* 6468 */    MCD_OPC_CheckPredicate, 6, 227, 26, // Skip to: 13355
/* 6472 */    MCD_OPC_Decode, 37, 114, // Opcode: ADDS_S_B
/* 6475 */    MCD_OPC_FilterValue, 9, 7, 0, // Skip to: 6486
/* 6479 */    MCD_OPC_CheckPredicate, 6, 216, 26, // Skip to: 13355
/* 6483 */    MCD_OPC_Decode, 39, 115, // Opcode: ADDS_S_H
/* 6486 */    MCD_OPC_FilterValue, 10, 7, 0, // Skip to: 6497
/* 6490 */    MCD_OPC_CheckPredicate, 6, 205, 26, // Skip to: 13355
/* 6494 */    MCD_OPC_Decode, 40, 116, // Opcode: ADDS_S_W
/* 6497 */    MCD_OPC_FilterValue, 11, 7, 0, // Skip to: 6508
/* 6501 */    MCD_OPC_CheckPredicate, 6, 194, 26, // Skip to: 13355
/* 6505 */    MCD_OPC_Decode, 38, 117, // Opcode: ADDS_S_D
/* 6508 */    MCD_OPC_FilterValue, 12, 7, 0, // Skip to: 6519
/* 6512 */    MCD_OPC_CheckPredicate, 6, 183, 26, // Skip to: 13355
/* 6516 */    MCD_OPC_Decode, 41, 114, // Opcode: ADDS_U_B
/* 6519 */    MCD_OPC_FilterValue, 13, 7, 0, // Skip to: 6530
/* 6523 */    MCD_OPC_CheckPredicate, 6, 172, 26, // Skip to: 13355
/* 6527 */    MCD_OPC_Decode, 43, 115, // Opcode: ADDS_U_H
/* 6530 */    MCD_OPC_FilterValue, 14, 7, 0, // Skip to: 6541
/* 6534 */    MCD_OPC_CheckPredicate, 6, 161, 26, // Skip to: 13355
/* 6538 */    MCD_OPC_Decode, 44, 116, // Opcode: ADDS_U_W
/* 6541 */    MCD_OPC_FilterValue, 15, 7, 0, // Skip to: 6552
/* 6545 */    MCD_OPC_CheckPredicate, 6, 150, 26, // Skip to: 13355
/* 6549 */    MCD_OPC_Decode, 42, 117, // Opcode: ADDS_U_D
/* 6552 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 6564
/* 6556 */    MCD_OPC_CheckPredicate, 6, 139, 26, // Skip to: 13355
/* 6560 */    MCD_OPC_Decode, 137, 1, 114, // Opcode: AVE_S_B
/* 6564 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 6576
/* 6568 */    MCD_OPC_CheckPredicate, 6, 127, 26, // Skip to: 13355
/* 6572 */    MCD_OPC_Decode, 139, 1, 115, // Opcode: AVE_S_H
/* 6576 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 6588
/* 6580 */    MCD_OPC_CheckPredicate, 6, 115, 26, // Skip to: 13355
/* 6584 */    MCD_OPC_Decode, 140, 1, 116, // Opcode: AVE_S_W
/* 6588 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 6600
/* 6592 */    MCD_OPC_CheckPredicate, 6, 103, 26, // Skip to: 13355
/* 6596 */    MCD_OPC_Decode, 138, 1, 117, // Opcode: AVE_S_D
/* 6600 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 6612
/* 6604 */    MCD_OPC_CheckPredicate, 6, 91, 26, // Skip to: 13355
/* 6608 */    MCD_OPC_Decode, 141, 1, 114, // Opcode: AVE_U_B
/* 6612 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 6624
/* 6616 */    MCD_OPC_CheckPredicate, 6, 79, 26, // Skip to: 13355
/* 6620 */    MCD_OPC_Decode, 143, 1, 115, // Opcode: AVE_U_H
/* 6624 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 6636
/* 6628 */    MCD_OPC_CheckPredicate, 6, 67, 26, // Skip to: 13355
/* 6632 */    MCD_OPC_Decode, 144, 1, 116, // Opcode: AVE_U_W
/* 6636 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 6648
/* 6640 */    MCD_OPC_CheckPredicate, 6, 55, 26, // Skip to: 13355
/* 6644 */    MCD_OPC_Decode, 142, 1, 117, // Opcode: AVE_U_D
/* 6648 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 6660
/* 6652 */    MCD_OPC_CheckPredicate, 6, 43, 26, // Skip to: 13355
/* 6656 */    MCD_OPC_Decode, 129, 1, 114, // Opcode: AVER_S_B
/* 6660 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 6672
/* 6664 */    MCD_OPC_CheckPredicate, 6, 31, 26, // Skip to: 13355
/* 6668 */    MCD_OPC_Decode, 131, 1, 115, // Opcode: AVER_S_H
/* 6672 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 6684
/* 6676 */    MCD_OPC_CheckPredicate, 6, 19, 26, // Skip to: 13355
/* 6680 */    MCD_OPC_Decode, 132, 1, 116, // Opcode: AVER_S_W
/* 6684 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 6696
/* 6688 */    MCD_OPC_CheckPredicate, 6, 7, 26, // Skip to: 13355
/* 6692 */    MCD_OPC_Decode, 130, 1, 117, // Opcode: AVER_S_D
/* 6696 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 6708
/* 6700 */    MCD_OPC_CheckPredicate, 6, 251, 25, // Skip to: 13355
/* 6704 */    MCD_OPC_Decode, 133, 1, 114, // Opcode: AVER_U_B
/* 6708 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 6720
/* 6712 */    MCD_OPC_CheckPredicate, 6, 239, 25, // Skip to: 13355
/* 6716 */    MCD_OPC_Decode, 135, 1, 115, // Opcode: AVER_U_H
/* 6720 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 6732
/* 6724 */    MCD_OPC_CheckPredicate, 6, 227, 25, // Skip to: 13355
/* 6728 */    MCD_OPC_Decode, 136, 1, 116, // Opcode: AVER_U_W
/* 6732 */    MCD_OPC_FilterValue, 31, 219, 25, // Skip to: 13355
/* 6736 */    MCD_OPC_CheckPredicate, 6, 215, 25, // Skip to: 13355
/* 6740 */    MCD_OPC_Decode, 134, 1, 117, // Opcode: AVER_U_D
/* 6744 */    MCD_OPC_FilterValue, 17, 27, 1, // Skip to: 7031
/* 6748 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 6751 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 6763
/* 6755 */    MCD_OPC_CheckPredicate, 6, 196, 25, // Skip to: 13355
/* 6759 */    MCD_OPC_Decode, 140, 12, 114, // Opcode: SUBS_S_B
/* 6763 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 6775
/* 6767 */    MCD_OPC_CheckPredicate, 6, 184, 25, // Skip to: 13355
/* 6771 */    MCD_OPC_Decode, 142, 12, 115, // Opcode: SUBS_S_H
/* 6775 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 6787
/* 6779 */    MCD_OPC_CheckPredicate, 6, 172, 25, // Skip to: 13355
/* 6783 */    MCD_OPC_Decode, 143, 12, 116, // Opcode: SUBS_S_W
/* 6787 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 6799
/* 6791 */    MCD_OPC_CheckPredicate, 6, 160, 25, // Skip to: 13355
/* 6795 */    MCD_OPC_Decode, 141, 12, 117, // Opcode: SUBS_S_D
/* 6799 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 6811
/* 6803 */    MCD_OPC_CheckPredicate, 6, 148, 25, // Skip to: 13355
/* 6807 */    MCD_OPC_Decode, 144, 12, 114, // Opcode: SUBS_U_B
/* 6811 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 6823
/* 6815 */    MCD_OPC_CheckPredicate, 6, 136, 25, // Skip to: 13355
/* 6819 */    MCD_OPC_Decode, 146, 12, 115, // Opcode: SUBS_U_H
/* 6823 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 6835
/* 6827 */    MCD_OPC_CheckPredicate, 6, 124, 25, // Skip to: 13355
/* 6831 */    MCD_OPC_Decode, 147, 12, 116, // Opcode: SUBS_U_W
/* 6835 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 6847
/* 6839 */    MCD_OPC_CheckPredicate, 6, 112, 25, // Skip to: 13355
/* 6843 */    MCD_OPC_Decode, 145, 12, 117, // Opcode: SUBS_U_D
/* 6847 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 6859
/* 6851 */    MCD_OPC_CheckPredicate, 6, 100, 25, // Skip to: 13355
/* 6855 */    MCD_OPC_Decode, 132, 12, 114, // Opcode: SUBSUS_U_B
/* 6859 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 6871
/* 6863 */    MCD_OPC_CheckPredicate, 6, 88, 25, // Skip to: 13355
/* 6867 */    MCD_OPC_Decode, 134, 12, 115, // Opcode: SUBSUS_U_H
/* 6871 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 6883
/* 6875 */    MCD_OPC_CheckPredicate, 6, 76, 25, // Skip to: 13355
/* 6879 */    MCD_OPC_Decode, 135, 12, 116, // Opcode: SUBSUS_U_W
/* 6883 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 6895
/* 6887 */    MCD_OPC_CheckPredicate, 6, 64, 25, // Skip to: 13355
/* 6891 */    MCD_OPC_Decode, 133, 12, 117, // Opcode: SUBSUS_U_D
/* 6895 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 6907
/* 6899 */    MCD_OPC_CheckPredicate, 6, 52, 25, // Skip to: 13355
/* 6903 */    MCD_OPC_Decode, 136, 12, 114, // Opcode: SUBSUU_S_B
/* 6907 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 6919
/* 6911 */    MCD_OPC_CheckPredicate, 6, 40, 25, // Skip to: 13355
/* 6915 */    MCD_OPC_Decode, 138, 12, 115, // Opcode: SUBSUU_S_H
/* 6919 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 6931
/* 6923 */    MCD_OPC_CheckPredicate, 6, 28, 25, // Skip to: 13355
/* 6927 */    MCD_OPC_Decode, 139, 12, 116, // Opcode: SUBSUU_S_W
/* 6931 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 6943
/* 6935 */    MCD_OPC_CheckPredicate, 6, 16, 25, // Skip to: 13355
/* 6939 */    MCD_OPC_Decode, 137, 12, 117, // Opcode: SUBSUU_S_D
/* 6943 */    MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 6954
/* 6947 */    MCD_OPC_CheckPredicate, 6, 4, 25, // Skip to: 13355
/* 6951 */    MCD_OPC_Decode, 87, 114, // Opcode: ASUB_S_B
/* 6954 */    MCD_OPC_FilterValue, 17, 7, 0, // Skip to: 6965
/* 6958 */    MCD_OPC_CheckPredicate, 6, 249, 24, // Skip to: 13355
/* 6962 */    MCD_OPC_Decode, 89, 115, // Opcode: ASUB_S_H
/* 6965 */    MCD_OPC_FilterValue, 18, 7, 0, // Skip to: 6976
/* 6969 */    MCD_OPC_CheckPredicate, 6, 238, 24, // Skip to: 13355
/* 6973 */    MCD_OPC_Decode, 90, 116, // Opcode: ASUB_S_W
/* 6976 */    MCD_OPC_FilterValue, 19, 7, 0, // Skip to: 6987
/* 6980 */    MCD_OPC_CheckPredicate, 6, 227, 24, // Skip to: 13355
/* 6984 */    MCD_OPC_Decode, 88, 117, // Opcode: ASUB_S_D
/* 6987 */    MCD_OPC_FilterValue, 20, 7, 0, // Skip to: 6998
/* 6991 */    MCD_OPC_CheckPredicate, 6, 216, 24, // Skip to: 13355
/* 6995 */    MCD_OPC_Decode, 91, 114, // Opcode: ASUB_U_B
/* 6998 */    MCD_OPC_FilterValue, 21, 7, 0, // Skip to: 7009
/* 7002 */    MCD_OPC_CheckPredicate, 6, 205, 24, // Skip to: 13355
/* 7006 */    MCD_OPC_Decode, 93, 115, // Opcode: ASUB_U_H
/* 7009 */    MCD_OPC_FilterValue, 22, 7, 0, // Skip to: 7020
/* 7013 */    MCD_OPC_CheckPredicate, 6, 194, 24, // Skip to: 13355
/* 7017 */    MCD_OPC_Decode, 94, 116, // Opcode: ASUB_U_W
/* 7020 */    MCD_OPC_FilterValue, 23, 187, 24, // Skip to: 13355
/* 7024 */    MCD_OPC_CheckPredicate, 6, 183, 24, // Skip to: 13355
/* 7028 */    MCD_OPC_Decode, 92, 117, // Opcode: ASUB_U_D
/* 7031 */    MCD_OPC_FilterValue, 18, 83, 1, // Skip to: 7374
/* 7035 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 7038 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 7050
/* 7042 */    MCD_OPC_CheckPredicate, 6, 165, 24, // Skip to: 13355
/* 7046 */    MCD_OPC_Decode, 174, 9, 114, // Opcode: MULV_B
/* 7050 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 7062
/* 7054 */    MCD_OPC_CheckPredicate, 6, 153, 24, // Skip to: 13355
/* 7058 */    MCD_OPC_Decode, 176, 9, 115, // Opcode: MULV_H
/* 7062 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 7074
/* 7066 */    MCD_OPC_CheckPredicate, 6, 141, 24, // Skip to: 13355
/* 7070 */    MCD_OPC_Decode, 177, 9, 116, // Opcode: MULV_W
/* 7074 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 7086
/* 7078 */    MCD_OPC_CheckPredicate, 6, 129, 24, // Skip to: 13355
/* 7082 */    MCD_OPC_Decode, 175, 9, 117, // Opcode: MULV_D
/* 7086 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 7098
/* 7090 */    MCD_OPC_CheckPredicate, 6, 117, 24, // Skip to: 13355
/* 7094 */    MCD_OPC_Decode, 228, 7, 118, // Opcode: MADDV_B
/* 7098 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 7110
/* 7102 */    MCD_OPC_CheckPredicate, 6, 105, 24, // Skip to: 13355
/* 7106 */    MCD_OPC_Decode, 230, 7, 119, // Opcode: MADDV_H
/* 7110 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 7122
/* 7114 */    MCD_OPC_CheckPredicate, 6, 93, 24, // Skip to: 13355
/* 7118 */    MCD_OPC_Decode, 231, 7, 120, // Opcode: MADDV_W
/* 7122 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 7134
/* 7126 */    MCD_OPC_CheckPredicate, 6, 81, 24, // Skip to: 13355
/* 7130 */    MCD_OPC_Decode, 229, 7, 121, // Opcode: MADDV_D
/* 7134 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 7146
/* 7138 */    MCD_OPC_CheckPredicate, 6, 69, 24, // Skip to: 13355
/* 7142 */    MCD_OPC_Decode, 245, 8, 118, // Opcode: MSUBV_B
/* 7146 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 7158
/* 7150 */    MCD_OPC_CheckPredicate, 6, 57, 24, // Skip to: 13355
/* 7154 */    MCD_OPC_Decode, 247, 8, 119, // Opcode: MSUBV_H
/* 7158 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 7170
/* 7162 */    MCD_OPC_CheckPredicate, 6, 45, 24, // Skip to: 13355
/* 7166 */    MCD_OPC_Decode, 248, 8, 120, // Opcode: MSUBV_W
/* 7170 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 7182
/* 7174 */    MCD_OPC_CheckPredicate, 6, 33, 24, // Skip to: 13355
/* 7178 */    MCD_OPC_Decode, 246, 8, 121, // Opcode: MSUBV_D
/* 7182 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 7194
/* 7186 */    MCD_OPC_CheckPredicate, 6, 21, 24, // Skip to: 13355
/* 7190 */    MCD_OPC_Decode, 165, 4, 114, // Opcode: DIV_S_B
/* 7194 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 7206
/* 7198 */    MCD_OPC_CheckPredicate, 6, 9, 24, // Skip to: 13355
/* 7202 */    MCD_OPC_Decode, 167, 4, 115, // Opcode: DIV_S_H
/* 7206 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7218
/* 7210 */    MCD_OPC_CheckPredicate, 6, 253, 23, // Skip to: 13355
/* 7214 */    MCD_OPC_Decode, 168, 4, 116, // Opcode: DIV_S_W
/* 7218 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7230
/* 7222 */    MCD_OPC_CheckPredicate, 6, 241, 23, // Skip to: 13355
/* 7226 */    MCD_OPC_Decode, 166, 4, 117, // Opcode: DIV_S_D
/* 7230 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 7242
/* 7234 */    MCD_OPC_CheckPredicate, 6, 229, 23, // Skip to: 13355
/* 7238 */    MCD_OPC_Decode, 169, 4, 114, // Opcode: DIV_U_B
/* 7242 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7254
/* 7246 */    MCD_OPC_CheckPredicate, 6, 217, 23, // Skip to: 13355
/* 7250 */    MCD_OPC_Decode, 171, 4, 115, // Opcode: DIV_U_H
/* 7254 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7266
/* 7258 */    MCD_OPC_CheckPredicate, 6, 205, 23, // Skip to: 13355
/* 7262 */    MCD_OPC_Decode, 172, 4, 116, // Opcode: DIV_U_W
/* 7266 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 7278
/* 7270 */    MCD_OPC_CheckPredicate, 6, 193, 23, // Skip to: 13355
/* 7274 */    MCD_OPC_Decode, 170, 4, 117, // Opcode: DIV_U_D
/* 7278 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 7290
/* 7282 */    MCD_OPC_CheckPredicate, 6, 181, 23, // Skip to: 13355
/* 7286 */    MCD_OPC_Decode, 187, 8, 114, // Opcode: MOD_S_B
/* 7290 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 7302
/* 7294 */    MCD_OPC_CheckPredicate, 6, 169, 23, // Skip to: 13355
/* 7298 */    MCD_OPC_Decode, 189, 8, 115, // Opcode: MOD_S_H
/* 7302 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 7314
/* 7306 */    MCD_OPC_CheckPredicate, 6, 157, 23, // Skip to: 13355
/* 7310 */    MCD_OPC_Decode, 190, 8, 116, // Opcode: MOD_S_W
/* 7314 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 7326
/* 7318 */    MCD_OPC_CheckPredicate, 6, 145, 23, // Skip to: 13355
/* 7322 */    MCD_OPC_Decode, 188, 8, 117, // Opcode: MOD_S_D
/* 7326 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 7338
/* 7330 */    MCD_OPC_CheckPredicate, 6, 133, 23, // Skip to: 13355
/* 7334 */    MCD_OPC_Decode, 191, 8, 114, // Opcode: MOD_U_B
/* 7338 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 7350
/* 7342 */    MCD_OPC_CheckPredicate, 6, 121, 23, // Skip to: 13355
/* 7346 */    MCD_OPC_Decode, 193, 8, 115, // Opcode: MOD_U_H
/* 7350 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 7362
/* 7354 */    MCD_OPC_CheckPredicate, 6, 109, 23, // Skip to: 13355
/* 7358 */    MCD_OPC_Decode, 194, 8, 116, // Opcode: MOD_U_W
/* 7362 */    MCD_OPC_FilterValue, 31, 101, 23, // Skip to: 13355
/* 7366 */    MCD_OPC_CheckPredicate, 6, 97, 23, // Skip to: 13355
/* 7370 */    MCD_OPC_Decode, 192, 8, 117, // Opcode: MOD_U_D
/* 7374 */    MCD_OPC_FilterValue, 19, 219, 0, // Skip to: 7597
/* 7378 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 7381 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 7393
/* 7385 */    MCD_OPC_CheckPredicate, 6, 78, 23, // Skip to: 13355
/* 7389 */    MCD_OPC_Decode, 192, 4, 122, // Opcode: DOTP_S_H
/* 7393 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 7405
/* 7397 */    MCD_OPC_CheckPredicate, 6, 66, 23, // Skip to: 13355
/* 7401 */    MCD_OPC_Decode, 193, 4, 123, // Opcode: DOTP_S_W
/* 7405 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 7417
/* 7409 */    MCD_OPC_CheckPredicate, 6, 54, 23, // Skip to: 13355
/* 7413 */    MCD_OPC_Decode, 191, 4, 124, // Opcode: DOTP_S_D
/* 7417 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 7429
/* 7421 */    MCD_OPC_CheckPredicate, 6, 42, 23, // Skip to: 13355
/* 7425 */    MCD_OPC_Decode, 195, 4, 122, // Opcode: DOTP_U_H
/* 7429 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 7441
/* 7433 */    MCD_OPC_CheckPredicate, 6, 30, 23, // Skip to: 13355
/* 7437 */    MCD_OPC_Decode, 196, 4, 123, // Opcode: DOTP_U_W
/* 7441 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 7453
/* 7445 */    MCD_OPC_CheckPredicate, 6, 18, 23, // Skip to: 13355
/* 7449 */    MCD_OPC_Decode, 194, 4, 124, // Opcode: DOTP_U_D
/* 7453 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 7465
/* 7457 */    MCD_OPC_CheckPredicate, 6, 6, 23, // Skip to: 13355
/* 7461 */    MCD_OPC_Decode, 198, 4, 125, // Opcode: DPADD_S_H
/* 7465 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 7477
/* 7469 */    MCD_OPC_CheckPredicate, 6, 250, 22, // Skip to: 13355
/* 7473 */    MCD_OPC_Decode, 199, 4, 126, // Opcode: DPADD_S_W
/* 7477 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 7489
/* 7481 */    MCD_OPC_CheckPredicate, 6, 238, 22, // Skip to: 13355
/* 7485 */    MCD_OPC_Decode, 197, 4, 127, // Opcode: DPADD_S_D
/* 7489 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 7501
/* 7493 */    MCD_OPC_CheckPredicate, 6, 226, 22, // Skip to: 13355
/* 7497 */    MCD_OPC_Decode, 201, 4, 125, // Opcode: DPADD_U_H
/* 7501 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 7513
/* 7505 */    MCD_OPC_CheckPredicate, 6, 214, 22, // Skip to: 13355
/* 7509 */    MCD_OPC_Decode, 202, 4, 126, // Opcode: DPADD_U_W
/* 7513 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 7525
/* 7517 */    MCD_OPC_CheckPredicate, 6, 202, 22, // Skip to: 13355
/* 7521 */    MCD_OPC_Decode, 200, 4, 127, // Opcode: DPADD_U_D
/* 7525 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 7537
/* 7529 */    MCD_OPC_CheckPredicate, 6, 190, 22, // Skip to: 13355
/* 7533 */    MCD_OPC_Decode, 217, 4, 125, // Opcode: DPSUB_S_H
/* 7537 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7549
/* 7541 */    MCD_OPC_CheckPredicate, 6, 178, 22, // Skip to: 13355
/* 7545 */    MCD_OPC_Decode, 218, 4, 126, // Opcode: DPSUB_S_W
/* 7549 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7561
/* 7553 */    MCD_OPC_CheckPredicate, 6, 166, 22, // Skip to: 13355
/* 7557 */    MCD_OPC_Decode, 216, 4, 127, // Opcode: DPSUB_S_D
/* 7561 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7573
/* 7565 */    MCD_OPC_CheckPredicate, 6, 154, 22, // Skip to: 13355
/* 7569 */    MCD_OPC_Decode, 220, 4, 125, // Opcode: DPSUB_U_H
/* 7573 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7585
/* 7577 */    MCD_OPC_CheckPredicate, 6, 142, 22, // Skip to: 13355
/* 7581 */    MCD_OPC_Decode, 221, 4, 126, // Opcode: DPSUB_U_W
/* 7585 */    MCD_OPC_FilterValue, 23, 134, 22, // Skip to: 13355
/* 7589 */    MCD_OPC_CheckPredicate, 6, 130, 22, // Skip to: 13355
/* 7593 */    MCD_OPC_Decode, 219, 4, 127, // Opcode: DPSUB_U_D
/* 7597 */    MCD_OPC_FilterValue, 20, 139, 1, // Skip to: 7996
/* 7601 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 7604 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 7617
/* 7608 */    MCD_OPC_CheckPredicate, 6, 111, 22, // Skip to: 13355
/* 7612 */    MCD_OPC_Decode, 158, 11, 128, 1, // Opcode: SLD_B
/* 7617 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 7630
/* 7621 */    MCD_OPC_CheckPredicate, 6, 98, 22, // Skip to: 13355
/* 7625 */    MCD_OPC_Decode, 160, 11, 129, 1, // Opcode: SLD_H
/* 7630 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 7643
/* 7634 */    MCD_OPC_CheckPredicate, 6, 85, 22, // Skip to: 13355
/* 7638 */    MCD_OPC_Decode, 161, 11, 130, 1, // Opcode: SLD_W
/* 7643 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 7656
/* 7647 */    MCD_OPC_CheckPredicate, 6, 72, 22, // Skip to: 13355
/* 7651 */    MCD_OPC_Decode, 159, 11, 131, 1, // Opcode: SLD_D
/* 7656 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 7669
/* 7660 */    MCD_OPC_CheckPredicate, 6, 59, 22, // Skip to: 13355
/* 7664 */    MCD_OPC_Decode, 199, 11, 132, 1, // Opcode: SPLAT_B
/* 7669 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 7682
/* 7673 */    MCD_OPC_CheckPredicate, 6, 46, 22, // Skip to: 13355
/* 7677 */    MCD_OPC_Decode, 201, 11, 133, 1, // Opcode: SPLAT_H
/* 7682 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 7695
/* 7686 */    MCD_OPC_CheckPredicate, 6, 33, 22, // Skip to: 13355
/* 7690 */    MCD_OPC_Decode, 202, 11, 134, 1, // Opcode: SPLAT_W
/* 7695 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 7708
/* 7699 */    MCD_OPC_CheckPredicate, 6, 20, 22, // Skip to: 13355
/* 7703 */    MCD_OPC_Decode, 200, 11, 135, 1, // Opcode: SPLAT_D
/* 7708 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 7720
/* 7712 */    MCD_OPC_CheckPredicate, 6, 7, 22, // Skip to: 13355
/* 7716 */    MCD_OPC_Decode, 235, 9, 114, // Opcode: PCKEV_B
/* 7720 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 7732
/* 7724 */    MCD_OPC_CheckPredicate, 6, 251, 21, // Skip to: 13355
/* 7728 */    MCD_OPC_Decode, 237, 9, 115, // Opcode: PCKEV_H
/* 7732 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 7744
/* 7736 */    MCD_OPC_CheckPredicate, 6, 239, 21, // Skip to: 13355
/* 7740 */    MCD_OPC_Decode, 238, 9, 116, // Opcode: PCKEV_W
/* 7744 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 7756
/* 7748 */    MCD_OPC_CheckPredicate, 6, 227, 21, // Skip to: 13355
/* 7752 */    MCD_OPC_Decode, 236, 9, 117, // Opcode: PCKEV_D
/* 7756 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 7768
/* 7760 */    MCD_OPC_CheckPredicate, 6, 215, 21, // Skip to: 13355
/* 7764 */    MCD_OPC_Decode, 239, 9, 114, // Opcode: PCKOD_B
/* 7768 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 7780
/* 7772 */    MCD_OPC_CheckPredicate, 6, 203, 21, // Skip to: 13355
/* 7776 */    MCD_OPC_Decode, 241, 9, 115, // Opcode: PCKOD_H
/* 7780 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 7792
/* 7784 */    MCD_OPC_CheckPredicate, 6, 191, 21, // Skip to: 13355
/* 7788 */    MCD_OPC_Decode, 242, 9, 116, // Opcode: PCKOD_W
/* 7792 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 7804
/* 7796 */    MCD_OPC_CheckPredicate, 6, 179, 21, // Skip to: 13355
/* 7800 */    MCD_OPC_Decode, 240, 9, 117, // Opcode: PCKOD_D
/* 7804 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 7816
/* 7808 */    MCD_OPC_CheckPredicate, 6, 167, 21, // Skip to: 13355
/* 7812 */    MCD_OPC_Decode, 195, 6, 114, // Opcode: ILVL_B
/* 7816 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 7828
/* 7820 */    MCD_OPC_CheckPredicate, 6, 155, 21, // Skip to: 13355
/* 7824 */    MCD_OPC_Decode, 197, 6, 115, // Opcode: ILVL_H
/* 7828 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 7840
/* 7832 */    MCD_OPC_CheckPredicate, 6, 143, 21, // Skip to: 13355
/* 7836 */    MCD_OPC_Decode, 198, 6, 116, // Opcode: ILVL_W
/* 7840 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 7852
/* 7844 */    MCD_OPC_CheckPredicate, 6, 131, 21, // Skip to: 13355
/* 7848 */    MCD_OPC_Decode, 196, 6, 117, // Opcode: ILVL_D
/* 7852 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 7864
/* 7856 */    MCD_OPC_CheckPredicate, 6, 119, 21, // Skip to: 13355
/* 7860 */    MCD_OPC_Decode, 203, 6, 114, // Opcode: ILVR_B
/* 7864 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 7876
/* 7868 */    MCD_OPC_CheckPredicate, 6, 107, 21, // Skip to: 13355
/* 7872 */    MCD_OPC_Decode, 205, 6, 115, // Opcode: ILVR_H
/* 7876 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 7888
/* 7880 */    MCD_OPC_CheckPredicate, 6, 95, 21, // Skip to: 13355
/* 7884 */    MCD_OPC_Decode, 206, 6, 116, // Opcode: ILVR_W
/* 7888 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 7900
/* 7892 */    MCD_OPC_CheckPredicate, 6, 83, 21, // Skip to: 13355
/* 7896 */    MCD_OPC_Decode, 204, 6, 117, // Opcode: ILVR_D
/* 7900 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 7912
/* 7904 */    MCD_OPC_CheckPredicate, 6, 71, 21, // Skip to: 13355
/* 7908 */    MCD_OPC_Decode, 191, 6, 114, // Opcode: ILVEV_B
/* 7912 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 7924
/* 7916 */    MCD_OPC_CheckPredicate, 6, 59, 21, // Skip to: 13355
/* 7920 */    MCD_OPC_Decode, 193, 6, 115, // Opcode: ILVEV_H
/* 7924 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 7936
/* 7928 */    MCD_OPC_CheckPredicate, 6, 47, 21, // Skip to: 13355
/* 7932 */    MCD_OPC_Decode, 194, 6, 116, // Opcode: ILVEV_W
/* 7936 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 7948
/* 7940 */    MCD_OPC_CheckPredicate, 6, 35, 21, // Skip to: 13355
/* 7944 */    MCD_OPC_Decode, 192, 6, 117, // Opcode: ILVEV_D
/* 7948 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 7960
/* 7952 */    MCD_OPC_CheckPredicate, 6, 23, 21, // Skip to: 13355
/* 7956 */    MCD_OPC_Decode, 199, 6, 114, // Opcode: ILVOD_B
/* 7960 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 7972
/* 7964 */    MCD_OPC_CheckPredicate, 6, 11, 21, // Skip to: 13355
/* 7968 */    MCD_OPC_Decode, 201, 6, 115, // Opcode: ILVOD_H
/* 7972 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 7984
/* 7976 */    MCD_OPC_CheckPredicate, 6, 255, 20, // Skip to: 13355
/* 7980 */    MCD_OPC_Decode, 202, 6, 116, // Opcode: ILVOD_W
/* 7984 */    MCD_OPC_FilterValue, 31, 247, 20, // Skip to: 13355
/* 7988 */    MCD_OPC_CheckPredicate, 6, 243, 20, // Skip to: 13355
/* 7992 */    MCD_OPC_Decode, 200, 6, 117, // Opcode: ILVOD_D
/* 7996 */    MCD_OPC_FilterValue, 21, 35, 1, // Skip to: 8291
/* 8000 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 8003 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 8015
/* 8007 */    MCD_OPC_CheckPredicate, 6, 224, 20, // Skip to: 13355
/* 8011 */    MCD_OPC_Decode, 153, 13, 118, // Opcode: VSHF_B
/* 8015 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 8027
/* 8019 */    MCD_OPC_CheckPredicate, 6, 212, 20, // Skip to: 13355
/* 8023 */    MCD_OPC_Decode, 155, 13, 119, // Opcode: VSHF_H
/* 8027 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 8039
/* 8031 */    MCD_OPC_CheckPredicate, 6, 200, 20, // Skip to: 13355
/* 8035 */    MCD_OPC_Decode, 156, 13, 120, // Opcode: VSHF_W
/* 8039 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 8051
/* 8043 */    MCD_OPC_CheckPredicate, 6, 188, 20, // Skip to: 13355
/* 8047 */    MCD_OPC_Decode, 154, 13, 121, // Opcode: VSHF_D
/* 8051 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 8063
/* 8055 */    MCD_OPC_CheckPredicate, 6, 176, 20, // Skip to: 13355
/* 8059 */    MCD_OPC_Decode, 212, 11, 114, // Opcode: SRAR_B
/* 8063 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 8075
/* 8067 */    MCD_OPC_CheckPredicate, 6, 164, 20, // Skip to: 13355
/* 8071 */    MCD_OPC_Decode, 214, 11, 115, // Opcode: SRAR_H
/* 8075 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 8087
/* 8079 */    MCD_OPC_CheckPredicate, 6, 152, 20, // Skip to: 13355
/* 8083 */    MCD_OPC_Decode, 215, 11, 116, // Opcode: SRAR_W
/* 8087 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 8099
/* 8091 */    MCD_OPC_CheckPredicate, 6, 140, 20, // Skip to: 13355
/* 8095 */    MCD_OPC_Decode, 213, 11, 117, // Opcode: SRAR_D
/* 8099 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 8111
/* 8103 */    MCD_OPC_CheckPredicate, 6, 128, 20, // Skip to: 13355
/* 8107 */    MCD_OPC_Decode, 232, 11, 114, // Opcode: SRLR_B
/* 8111 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 8123
/* 8115 */    MCD_OPC_CheckPredicate, 6, 116, 20, // Skip to: 13355
/* 8119 */    MCD_OPC_Decode, 234, 11, 115, // Opcode: SRLR_H
/* 8123 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 8135
/* 8127 */    MCD_OPC_CheckPredicate, 6, 104, 20, // Skip to: 13355
/* 8131 */    MCD_OPC_Decode, 235, 11, 116, // Opcode: SRLR_W
/* 8135 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 8147
/* 8139 */    MCD_OPC_CheckPredicate, 6, 92, 20, // Skip to: 13355
/* 8143 */    MCD_OPC_Decode, 233, 11, 117, // Opcode: SRLR_D
/* 8147 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 8159
/* 8151 */    MCD_OPC_CheckPredicate, 6, 80, 20, // Skip to: 13355
/* 8155 */    MCD_OPC_Decode, 180, 6, 122, // Opcode: HADD_S_H
/* 8159 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 8171
/* 8163 */    MCD_OPC_CheckPredicate, 6, 68, 20, // Skip to: 13355
/* 8167 */    MCD_OPC_Decode, 181, 6, 123, // Opcode: HADD_S_W
/* 8171 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 8183
/* 8175 */    MCD_OPC_CheckPredicate, 6, 56, 20, // Skip to: 13355
/* 8179 */    MCD_OPC_Decode, 179, 6, 124, // Opcode: HADD_S_D
/* 8183 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 8195
/* 8187 */    MCD_OPC_CheckPredicate, 6, 44, 20, // Skip to: 13355
/* 8191 */    MCD_OPC_Decode, 183, 6, 122, // Opcode: HADD_U_H
/* 8195 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 8207
/* 8199 */    MCD_OPC_CheckPredicate, 6, 32, 20, // Skip to: 13355
/* 8203 */    MCD_OPC_Decode, 184, 6, 123, // Opcode: HADD_U_W
/* 8207 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 8219
/* 8211 */    MCD_OPC_CheckPredicate, 6, 20, 20, // Skip to: 13355
/* 8215 */    MCD_OPC_Decode, 182, 6, 124, // Opcode: HADD_U_D
/* 8219 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 8231
/* 8223 */    MCD_OPC_CheckPredicate, 6, 8, 20, // Skip to: 13355
/* 8227 */    MCD_OPC_Decode, 186, 6, 122, // Opcode: HSUB_S_H
/* 8231 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 8243
/* 8235 */    MCD_OPC_CheckPredicate, 6, 252, 19, // Skip to: 13355
/* 8239 */    MCD_OPC_Decode, 187, 6, 123, // Opcode: HSUB_S_W
/* 8243 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 8255
/* 8247 */    MCD_OPC_CheckPredicate, 6, 240, 19, // Skip to: 13355
/* 8251 */    MCD_OPC_Decode, 185, 6, 124, // Opcode: HSUB_S_D
/* 8255 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 8267
/* 8259 */    MCD_OPC_CheckPredicate, 6, 228, 19, // Skip to: 13355
/* 8263 */    MCD_OPC_Decode, 189, 6, 122, // Opcode: HSUB_U_H
/* 8267 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 8279
/* 8271 */    MCD_OPC_CheckPredicate, 6, 216, 19, // Skip to: 13355
/* 8275 */    MCD_OPC_Decode, 190, 6, 123, // Opcode: HSUB_U_W
/* 8279 */    MCD_OPC_FilterValue, 31, 208, 19, // Skip to: 13355
/* 8283 */    MCD_OPC_CheckPredicate, 6, 204, 19, // Skip to: 13355
/* 8287 */    MCD_OPC_Decode, 188, 6, 124, // Opcode: HSUB_U_D
/* 8291 */    MCD_OPC_FilterValue, 25, 230, 1, // Skip to: 8781
/* 8295 */    MCD_OPC_ExtractField, 20, 6,  // Inst{25-20} ...
/* 8298 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8311
/* 8302 */    MCD_OPC_CheckPredicate, 6, 185, 19, // Skip to: 13355
/* 8306 */    MCD_OPC_Decode, 154, 11, 136, 1, // Opcode: SLDI_B
/* 8311 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 8330
/* 8315 */    MCD_OPC_CheckPredicate, 6, 172, 19, // Skip to: 13355
/* 8319 */    MCD_OPC_CheckField, 19, 1, 0, 166, 19, // Skip to: 13355
/* 8325 */    MCD_OPC_Decode, 156, 11, 137, 1, // Opcode: SLDI_H
/* 8330 */    MCD_OPC_FilterValue, 3, 54, 0, // Skip to: 8388
/* 8334 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8337 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8350
/* 8341 */    MCD_OPC_CheckPredicate, 6, 146, 19, // Skip to: 13355
/* 8345 */    MCD_OPC_Decode, 157, 11, 138, 1, // Opcode: SLDI_W
/* 8350 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 8369
/* 8354 */    MCD_OPC_CheckPredicate, 6, 133, 19, // Skip to: 13355
/* 8358 */    MCD_OPC_CheckField, 17, 1, 0, 127, 19, // Skip to: 13355
/* 8364 */    MCD_OPC_Decode, 155, 11, 139, 1, // Opcode: SLDI_D
/* 8369 */    MCD_OPC_FilterValue, 3, 118, 19, // Skip to: 13355
/* 8373 */    MCD_OPC_CheckPredicate, 6, 114, 19, // Skip to: 13355
/* 8377 */    MCD_OPC_CheckField, 16, 2, 2, 108, 19, // Skip to: 13355
/* 8383 */    MCD_OPC_Decode, 192, 3, 140, 1, // Opcode: CTCMSA
/* 8388 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 8401
/* 8392 */    MCD_OPC_CheckPredicate, 6, 95, 19, // Skip to: 13355
/* 8396 */    MCD_OPC_Decode, 195, 11, 141, 1, // Opcode: SPLATI_B
/* 8401 */    MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 8420
/* 8405 */    MCD_OPC_CheckPredicate, 6, 82, 19, // Skip to: 13355
/* 8409 */    MCD_OPC_CheckField, 19, 1, 0, 76, 19, // Skip to: 13355
/* 8415 */    MCD_OPC_Decode, 197, 11, 142, 1, // Opcode: SPLATI_H
/* 8420 */    MCD_OPC_FilterValue, 7, 54, 0, // Skip to: 8478
/* 8424 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8427 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8440
/* 8431 */    MCD_OPC_CheckPredicate, 6, 56, 19, // Skip to: 13355
/* 8435 */    MCD_OPC_Decode, 198, 11, 143, 1, // Opcode: SPLATI_W
/* 8440 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 8459
/* 8444 */    MCD_OPC_CheckPredicate, 6, 43, 19, // Skip to: 13355
/* 8448 */    MCD_OPC_CheckField, 17, 1, 0, 37, 19, // Skip to: 13355
/* 8454 */    MCD_OPC_Decode, 196, 11, 144, 1, // Opcode: SPLATI_D
/* 8459 */    MCD_OPC_FilterValue, 3, 28, 19, // Skip to: 13355
/* 8463 */    MCD_OPC_CheckPredicate, 6, 24, 19, // Skip to: 13355
/* 8467 */    MCD_OPC_CheckField, 16, 2, 2, 18, 19, // Skip to: 13355
/* 8473 */    MCD_OPC_Decode, 220, 2, 145, 1, // Opcode: CFCMSA
/* 8478 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 8491
/* 8482 */    MCD_OPC_CheckPredicate, 6, 5, 19, // Skip to: 13355
/* 8486 */    MCD_OPC_Decode, 182, 3, 146, 1, // Opcode: COPY_S_B
/* 8491 */    MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 8510
/* 8495 */    MCD_OPC_CheckPredicate, 6, 248, 18, // Skip to: 13355
/* 8499 */    MCD_OPC_CheckField, 19, 1, 0, 242, 18, // Skip to: 13355
/* 8505 */    MCD_OPC_Decode, 184, 3, 147, 1, // Opcode: COPY_S_H
/* 8510 */    MCD_OPC_FilterValue, 11, 54, 0, // Skip to: 8568
/* 8514 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8517 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8530
/* 8521 */    MCD_OPC_CheckPredicate, 6, 222, 18, // Skip to: 13355
/* 8525 */    MCD_OPC_Decode, 185, 3, 148, 1, // Opcode: COPY_S_W
/* 8530 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 8549
/* 8534 */    MCD_OPC_CheckPredicate, 13, 209, 18, // Skip to: 13355
/* 8538 */    MCD_OPC_CheckField, 17, 1, 0, 203, 18, // Skip to: 13355
/* 8544 */    MCD_OPC_Decode, 183, 3, 149, 1, // Opcode: COPY_S_D
/* 8549 */    MCD_OPC_FilterValue, 3, 194, 18, // Skip to: 13355
/* 8553 */    MCD_OPC_CheckPredicate, 6, 190, 18, // Skip to: 13355
/* 8557 */    MCD_OPC_CheckField, 16, 2, 2, 184, 18, // Skip to: 13355
/* 8563 */    MCD_OPC_Decode, 196, 8, 150, 1, // Opcode: MOVE_V
/* 8568 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 8581
/* 8572 */    MCD_OPC_CheckPredicate, 6, 171, 18, // Skip to: 13355
/* 8576 */    MCD_OPC_Decode, 186, 3, 146, 1, // Opcode: COPY_U_B
/* 8581 */    MCD_OPC_FilterValue, 14, 15, 0, // Skip to: 8600
/* 8585 */    MCD_OPC_CheckPredicate, 6, 158, 18, // Skip to: 13355
/* 8589 */    MCD_OPC_CheckField, 19, 1, 0, 152, 18, // Skip to: 13355
/* 8595 */    MCD_OPC_Decode, 188, 3, 147, 1, // Opcode: COPY_U_H
/* 8600 */    MCD_OPC_FilterValue, 15, 35, 0, // Skip to: 8639
/* 8604 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8607 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8620
/* 8611 */    MCD_OPC_CheckPredicate, 6, 132, 18, // Skip to: 13355
/* 8615 */    MCD_OPC_Decode, 189, 3, 148, 1, // Opcode: COPY_U_W
/* 8620 */    MCD_OPC_FilterValue, 2, 123, 18, // Skip to: 13355
/* 8624 */    MCD_OPC_CheckPredicate, 13, 119, 18, // Skip to: 13355
/* 8628 */    MCD_OPC_CheckField, 17, 1, 0, 113, 18, // Skip to: 13355
/* 8634 */    MCD_OPC_Decode, 187, 3, 149, 1, // Opcode: COPY_U_D
/* 8639 */    MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 8652
/* 8643 */    MCD_OPC_CheckPredicate, 6, 100, 18, // Skip to: 13355
/* 8647 */    MCD_OPC_Decode, 208, 6, 151, 1, // Opcode: INSERT_B
/* 8652 */    MCD_OPC_FilterValue, 18, 15, 0, // Skip to: 8671
/* 8656 */    MCD_OPC_CheckPredicate, 6, 87, 18, // Skip to: 13355
/* 8660 */    MCD_OPC_CheckField, 19, 1, 0, 81, 18, // Skip to: 13355
/* 8666 */    MCD_OPC_Decode, 216, 6, 152, 1, // Opcode: INSERT_H
/* 8671 */    MCD_OPC_FilterValue, 19, 35, 0, // Skip to: 8710
/* 8675 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8678 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8691
/* 8682 */    MCD_OPC_CheckPredicate, 6, 61, 18, // Skip to: 13355
/* 8686 */    MCD_OPC_Decode, 218, 6, 153, 1, // Opcode: INSERT_W
/* 8691 */    MCD_OPC_FilterValue, 2, 52, 18, // Skip to: 13355
/* 8695 */    MCD_OPC_CheckPredicate, 13, 48, 18, // Skip to: 13355
/* 8699 */    MCD_OPC_CheckField, 17, 1, 0, 42, 18, // Skip to: 13355
/* 8705 */    MCD_OPC_Decode, 210, 6, 154, 1, // Opcode: INSERT_D
/* 8710 */    MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 8723
/* 8714 */    MCD_OPC_CheckPredicate, 6, 29, 18, // Skip to: 13355
/* 8718 */    MCD_OPC_Decode, 221, 6, 155, 1, // Opcode: INSVE_B
/* 8723 */    MCD_OPC_FilterValue, 22, 15, 0, // Skip to: 8742
/* 8727 */    MCD_OPC_CheckPredicate, 6, 16, 18, // Skip to: 13355
/* 8731 */    MCD_OPC_CheckField, 19, 1, 0, 10, 18, // Skip to: 13355
/* 8737 */    MCD_OPC_Decode, 223, 6, 155, 1, // Opcode: INSVE_H
/* 8742 */    MCD_OPC_FilterValue, 23, 1, 18, // Skip to: 13355
/* 8746 */    MCD_OPC_ExtractField, 18, 2,  // Inst{19-18} ...
/* 8749 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 8762
/* 8753 */    MCD_OPC_CheckPredicate, 6, 246, 17, // Skip to: 13355
/* 8757 */    MCD_OPC_Decode, 224, 6, 155, 1, // Opcode: INSVE_W
/* 8762 */    MCD_OPC_FilterValue, 2, 237, 17, // Skip to: 13355
/* 8766 */    MCD_OPC_CheckPredicate, 6, 233, 17, // Skip to: 13355
/* 8770 */    MCD_OPC_CheckField, 17, 1, 0, 227, 17, // Skip to: 13355
/* 8776 */    MCD_OPC_Decode, 222, 6, 155, 1, // Opcode: INSVE_D
/* 8781 */    MCD_OPC_FilterValue, 26, 131, 1, // Skip to: 9172
/* 8785 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 8788 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 8800
/* 8792 */    MCD_OPC_CheckPredicate, 6, 207, 17, // Skip to: 13355
/* 8796 */    MCD_OPC_Decode, 157, 5, 116, // Opcode: FCAF_W
/* 8800 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 8812
/* 8804 */    MCD_OPC_CheckPredicate, 6, 195, 17, // Skip to: 13355
/* 8808 */    MCD_OPC_Decode, 156, 5, 117, // Opcode: FCAF_D
/* 8812 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 8824
/* 8816 */    MCD_OPC_CheckPredicate, 6, 183, 17, // Skip to: 13355
/* 8820 */    MCD_OPC_Decode, 184, 5, 116, // Opcode: FCUN_W
/* 8824 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 8836
/* 8828 */    MCD_OPC_CheckPredicate, 6, 171, 17, // Skip to: 13355
/* 8832 */    MCD_OPC_Decode, 183, 5, 117, // Opcode: FCUN_D
/* 8836 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 8848
/* 8840 */    MCD_OPC_CheckPredicate, 6, 159, 17, // Skip to: 13355
/* 8844 */    MCD_OPC_Decode, 159, 5, 116, // Opcode: FCEQ_W
/* 8848 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 8860
/* 8852 */    MCD_OPC_CheckPredicate, 6, 147, 17, // Skip to: 13355
/* 8856 */    MCD_OPC_Decode, 158, 5, 117, // Opcode: FCEQ_D
/* 8860 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 8872
/* 8864 */    MCD_OPC_CheckPredicate, 6, 135, 17, // Skip to: 13355
/* 8868 */    MCD_OPC_Decode, 176, 5, 116, // Opcode: FCUEQ_W
/* 8872 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 8884
/* 8876 */    MCD_OPC_CheckPredicate, 6, 123, 17, // Skip to: 13355
/* 8880 */    MCD_OPC_Decode, 175, 5, 117, // Opcode: FCUEQ_D
/* 8884 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 8896
/* 8888 */    MCD_OPC_CheckPredicate, 6, 111, 17, // Skip to: 13355
/* 8892 */    MCD_OPC_Decode, 165, 5, 116, // Opcode: FCLT_W
/* 8896 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 8908
/* 8900 */    MCD_OPC_CheckPredicate, 6, 99, 17, // Skip to: 13355
/* 8904 */    MCD_OPC_Decode, 164, 5, 117, // Opcode: FCLT_D
/* 8908 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 8920
/* 8912 */    MCD_OPC_CheckPredicate, 6, 87, 17, // Skip to: 13355
/* 8916 */    MCD_OPC_Decode, 180, 5, 116, // Opcode: FCULT_W
/* 8920 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 8932
/* 8924 */    MCD_OPC_CheckPredicate, 6, 75, 17, // Skip to: 13355
/* 8928 */    MCD_OPC_Decode, 179, 5, 117, // Opcode: FCULT_D
/* 8932 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 8944
/* 8936 */    MCD_OPC_CheckPredicate, 6, 63, 17, // Skip to: 13355
/* 8940 */    MCD_OPC_Decode, 163, 5, 116, // Opcode: FCLE_W
/* 8944 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 8956
/* 8948 */    MCD_OPC_CheckPredicate, 6, 51, 17, // Skip to: 13355
/* 8952 */    MCD_OPC_Decode, 162, 5, 117, // Opcode: FCLE_D
/* 8956 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 8968
/* 8960 */    MCD_OPC_CheckPredicate, 6, 39, 17, // Skip to: 13355
/* 8964 */    MCD_OPC_Decode, 178, 5, 116, // Opcode: FCULE_W
/* 8968 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 8980
/* 8972 */    MCD_OPC_CheckPredicate, 6, 27, 17, // Skip to: 13355
/* 8976 */    MCD_OPC_Decode, 177, 5, 117, // Opcode: FCULE_D
/* 8980 */    MCD_OPC_FilterValue, 16, 8, 0, // Skip to: 8992
/* 8984 */    MCD_OPC_CheckPredicate, 6, 15, 17, // Skip to: 13355
/* 8988 */    MCD_OPC_Decode, 133, 6, 116, // Opcode: FSAF_W
/* 8992 */    MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 9004
/* 8996 */    MCD_OPC_CheckPredicate, 6, 3, 17, // Skip to: 13355
/* 9000 */    MCD_OPC_Decode, 132, 6, 117, // Opcode: FSAF_D
/* 9004 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 9016
/* 9008 */    MCD_OPC_CheckPredicate, 6, 247, 16, // Skip to: 13355
/* 9012 */    MCD_OPC_Decode, 167, 6, 116, // Opcode: FSUN_W
/* 9016 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 9028
/* 9020 */    MCD_OPC_CheckPredicate, 6, 235, 16, // Skip to: 13355
/* 9024 */    MCD_OPC_Decode, 166, 6, 117, // Opcode: FSUN_D
/* 9028 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 9040
/* 9032 */    MCD_OPC_CheckPredicate, 6, 223, 16, // Skip to: 13355
/* 9036 */    MCD_OPC_Decode, 135, 6, 116, // Opcode: FSEQ_W
/* 9040 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 9052
/* 9044 */    MCD_OPC_CheckPredicate, 6, 211, 16, // Skip to: 13355
/* 9048 */    MCD_OPC_Decode, 134, 6, 117, // Opcode: FSEQ_D
/* 9052 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 9064
/* 9056 */    MCD_OPC_CheckPredicate, 6, 199, 16, // Skip to: 13355
/* 9060 */    MCD_OPC_Decode, 159, 6, 116, // Opcode: FSUEQ_W
/* 9064 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 9076
/* 9068 */    MCD_OPC_CheckPredicate, 6, 187, 16, // Skip to: 13355
/* 9072 */    MCD_OPC_Decode, 158, 6, 117, // Opcode: FSUEQ_D
/* 9076 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 9088
/* 9080 */    MCD_OPC_CheckPredicate, 6, 175, 16, // Skip to: 13355
/* 9084 */    MCD_OPC_Decode, 139, 6, 116, // Opcode: FSLT_W
/* 9088 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 9100
/* 9092 */    MCD_OPC_CheckPredicate, 6, 163, 16, // Skip to: 13355
/* 9096 */    MCD_OPC_Decode, 138, 6, 117, // Opcode: FSLT_D
/* 9100 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 9112
/* 9104 */    MCD_OPC_CheckPredicate, 6, 151, 16, // Skip to: 13355
/* 9108 */    MCD_OPC_Decode, 163, 6, 116, // Opcode: FSULT_W
/* 9112 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 9124
/* 9116 */    MCD_OPC_CheckPredicate, 6, 139, 16, // Skip to: 13355
/* 9120 */    MCD_OPC_Decode, 162, 6, 117, // Opcode: FSULT_D
/* 9124 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 9136
/* 9128 */    MCD_OPC_CheckPredicate, 6, 127, 16, // Skip to: 13355
/* 9132 */    MCD_OPC_Decode, 137, 6, 116, // Opcode: FSLE_W
/* 9136 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 9148
/* 9140 */    MCD_OPC_CheckPredicate, 6, 115, 16, // Skip to: 13355
/* 9144 */    MCD_OPC_Decode, 136, 6, 117, // Opcode: FSLE_D
/* 9148 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 9160
/* 9152 */    MCD_OPC_CheckPredicate, 6, 103, 16, // Skip to: 13355
/* 9156 */    MCD_OPC_Decode, 161, 6, 116, // Opcode: FSULE_W
/* 9160 */    MCD_OPC_FilterValue, 31, 95, 16, // Skip to: 13355
/* 9164 */    MCD_OPC_CheckPredicate, 6, 91, 16, // Skip to: 13355
/* 9168 */    MCD_OPC_Decode, 160, 6, 117, // Opcode: FSULE_D
/* 9172 */    MCD_OPC_FilterValue, 27, 63, 1, // Skip to: 9495
/* 9176 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 9179 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 9191
/* 9183 */    MCD_OPC_CheckPredicate, 6, 72, 16, // Skip to: 13355
/* 9187 */    MCD_OPC_Decode, 155, 5, 116, // Opcode: FADD_W
/* 9191 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 9203
/* 9195 */    MCD_OPC_CheckPredicate, 6, 60, 16, // Skip to: 13355
/* 9199 */    MCD_OPC_Decode, 149, 5, 117, // Opcode: FADD_D
/* 9203 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 9215
/* 9207 */    MCD_OPC_CheckPredicate, 6, 48, 16, // Skip to: 13355
/* 9211 */    MCD_OPC_Decode, 157, 6, 116, // Opcode: FSUB_W
/* 9215 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 9227
/* 9219 */    MCD_OPC_CheckPredicate, 6, 36, 16, // Skip to: 13355
/* 9223 */    MCD_OPC_Decode, 151, 6, 117, // Opcode: FSUB_D
/* 9227 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 9239
/* 9231 */    MCD_OPC_CheckPredicate, 6, 24, 16, // Skip to: 13355
/* 9235 */    MCD_OPC_Decode, 248, 5, 116, // Opcode: FMUL_W
/* 9239 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 9251
/* 9243 */    MCD_OPC_CheckPredicate, 6, 12, 16, // Skip to: 13355
/* 9247 */    MCD_OPC_Decode, 242, 5, 117, // Opcode: FMUL_D
/* 9251 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 9263
/* 9255 */    MCD_OPC_CheckPredicate, 6, 0, 16, // Skip to: 13355
/* 9259 */    MCD_OPC_Decode, 191, 5, 116, // Opcode: FDIV_W
/* 9263 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 9275
/* 9267 */    MCD_OPC_CheckPredicate, 6, 244, 15, // Skip to: 13355
/* 9271 */    MCD_OPC_Decode, 185, 5, 117, // Opcode: FDIV_D
/* 9275 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 9287
/* 9279 */    MCD_OPC_CheckPredicate, 6, 232, 15, // Skip to: 13355
/* 9283 */    MCD_OPC_Decode, 226, 5, 120, // Opcode: FMADD_W
/* 9287 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 9299
/* 9291 */    MCD_OPC_CheckPredicate, 6, 220, 15, // Skip to: 13355
/* 9295 */    MCD_OPC_Decode, 225, 5, 121, // Opcode: FMADD_D
/* 9299 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 9311
/* 9303 */    MCD_OPC_CheckPredicate, 6, 208, 15, // Skip to: 13355
/* 9307 */    MCD_OPC_Decode, 241, 5, 120, // Opcode: FMSUB_W
/* 9311 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 9323
/* 9315 */    MCD_OPC_CheckPredicate, 6, 196, 15, // Skip to: 13355
/* 9319 */    MCD_OPC_Decode, 240, 5, 121, // Opcode: FMSUB_D
/* 9323 */    MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 9335
/* 9327 */    MCD_OPC_CheckPredicate, 6, 184, 15, // Skip to: 13355
/* 9331 */    MCD_OPC_Decode, 196, 5, 116, // Opcode: FEXP2_W
/* 9335 */    MCD_OPC_FilterValue, 15, 8, 0, // Skip to: 9347
/* 9339 */    MCD_OPC_CheckPredicate, 6, 172, 15, // Skip to: 13355
/* 9343 */    MCD_OPC_Decode, 194, 5, 117, // Opcode: FEXP2_D
/* 9347 */    MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 9360
/* 9351 */    MCD_OPC_CheckPredicate, 6, 160, 15, // Skip to: 13355
/* 9355 */    MCD_OPC_Decode, 192, 5, 156, 1, // Opcode: FEXDO_H
/* 9360 */    MCD_OPC_FilterValue, 17, 9, 0, // Skip to: 9373
/* 9364 */    MCD_OPC_CheckPredicate, 6, 147, 15, // Skip to: 13355
/* 9368 */    MCD_OPC_Decode, 193, 5, 157, 1, // Opcode: FEXDO_W
/* 9373 */    MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 9386
/* 9377 */    MCD_OPC_CheckPredicate, 6, 134, 15, // Skip to: 13355
/* 9381 */    MCD_OPC_Decode, 172, 6, 156, 1, // Opcode: FTQ_H
/* 9386 */    MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 9399
/* 9390 */    MCD_OPC_CheckPredicate, 6, 121, 15, // Skip to: 13355
/* 9394 */    MCD_OPC_Decode, 173, 6, 157, 1, // Opcode: FTQ_W
/* 9399 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 9411
/* 9403 */    MCD_OPC_CheckPredicate, 6, 108, 15, // Skip to: 13355
/* 9407 */    MCD_OPC_Decode, 234, 5, 116, // Opcode: FMIN_W
/* 9411 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 9423
/* 9415 */    MCD_OPC_CheckPredicate, 6, 96, 15, // Skip to: 13355
/* 9419 */    MCD_OPC_Decode, 233, 5, 117, // Opcode: FMIN_D
/* 9423 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 9435
/* 9427 */    MCD_OPC_CheckPredicate, 6, 84, 15, // Skip to: 13355
/* 9431 */    MCD_OPC_Decode, 232, 5, 116, // Opcode: FMIN_A_W
/* 9435 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 9447
/* 9439 */    MCD_OPC_CheckPredicate, 6, 72, 15, // Skip to: 13355
/* 9443 */    MCD_OPC_Decode, 231, 5, 117, // Opcode: FMIN_A_D
/* 9447 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 9459
/* 9451 */    MCD_OPC_CheckPredicate, 6, 60, 15, // Skip to: 13355
/* 9455 */    MCD_OPC_Decode, 230, 5, 116, // Opcode: FMAX_W
/* 9459 */    MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 9471
/* 9463 */    MCD_OPC_CheckPredicate, 6, 48, 15, // Skip to: 13355
/* 9467 */    MCD_OPC_Decode, 229, 5, 117, // Opcode: FMAX_D
/* 9471 */    MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 9483
/* 9475 */    MCD_OPC_CheckPredicate, 6, 36, 15, // Skip to: 13355
/* 9479 */    MCD_OPC_Decode, 228, 5, 116, // Opcode: FMAX_A_W
/* 9483 */    MCD_OPC_FilterValue, 31, 28, 15, // Skip to: 13355
/* 9487 */    MCD_OPC_CheckPredicate, 6, 24, 15, // Skip to: 13355
/* 9491 */    MCD_OPC_Decode, 227, 5, 117, // Opcode: FMAX_A_D
/* 9495 */    MCD_OPC_FilterValue, 28, 35, 1, // Skip to: 9790
/* 9499 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 9502 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 9514
/* 9506 */    MCD_OPC_CheckPredicate, 6, 5, 15, // Skip to: 13355
/* 9510 */    MCD_OPC_Decode, 174, 5, 116, // Opcode: FCOR_W
/* 9514 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 9526
/* 9518 */    MCD_OPC_CheckPredicate, 6, 249, 14, // Skip to: 13355
/* 9522 */    MCD_OPC_Decode, 173, 5, 117, // Opcode: FCOR_D
/* 9526 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 9538
/* 9530 */    MCD_OPC_CheckPredicate, 6, 237, 14, // Skip to: 13355
/* 9534 */    MCD_OPC_Decode, 182, 5, 116, // Opcode: FCUNE_W
/* 9538 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 9550
/* 9542 */    MCD_OPC_CheckPredicate, 6, 225, 14, // Skip to: 13355
/* 9546 */    MCD_OPC_Decode, 181, 5, 117, // Opcode: FCUNE_D
/* 9550 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 9562
/* 9554 */    MCD_OPC_CheckPredicate, 6, 213, 14, // Skip to: 13355
/* 9558 */    MCD_OPC_Decode, 172, 5, 116, // Opcode: FCNE_W
/* 9562 */    MCD_OPC_FilterValue, 7, 8, 0, // Skip to: 9574
/* 9566 */    MCD_OPC_CheckPredicate, 6, 201, 14, // Skip to: 13355
/* 9570 */    MCD_OPC_Decode, 171, 5, 117, // Opcode: FCNE_D
/* 9574 */    MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 9586
/* 9578 */    MCD_OPC_CheckPredicate, 6, 189, 14, // Skip to: 13355
/* 9582 */    MCD_OPC_Decode, 180, 9, 115, // Opcode: MUL_Q_H
/* 9586 */    MCD_OPC_FilterValue, 9, 8, 0, // Skip to: 9598
/* 9590 */    MCD_OPC_CheckPredicate, 6, 177, 14, // Skip to: 13355
/* 9594 */    MCD_OPC_Decode, 181, 9, 116, // Opcode: MUL_Q_W
/* 9598 */    MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 9610
/* 9602 */    MCD_OPC_CheckPredicate, 6, 165, 14, // Skip to: 13355
/* 9606 */    MCD_OPC_Decode, 237, 7, 119, // Opcode: MADD_Q_H
/* 9610 */    MCD_OPC_FilterValue, 11, 8, 0, // Skip to: 9622
/* 9614 */    MCD_OPC_CheckPredicate, 6, 153, 14, // Skip to: 13355
/* 9618 */    MCD_OPC_Decode, 238, 7, 120, // Opcode: MADD_Q_W
/* 9622 */    MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 9634
/* 9626 */    MCD_OPC_CheckPredicate, 6, 141, 14, // Skip to: 13355
/* 9630 */    MCD_OPC_Decode, 254, 8, 119, // Opcode: MSUB_Q_H
/* 9634 */    MCD_OPC_FilterValue, 13, 8, 0, // Skip to: 9646
/* 9638 */    MCD_OPC_CheckPredicate, 6, 129, 14, // Skip to: 13355
/* 9642 */    MCD_OPC_Decode, 255, 8, 120, // Opcode: MSUB_Q_W
/* 9646 */    MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 9658
/* 9650 */    MCD_OPC_CheckPredicate, 6, 117, 14, // Skip to: 13355
/* 9654 */    MCD_OPC_Decode, 143, 6, 116, // Opcode: FSOR_W
/* 9658 */    MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 9670
/* 9662 */    MCD_OPC_CheckPredicate, 6, 105, 14, // Skip to: 13355
/* 9666 */    MCD_OPC_Decode, 142, 6, 117, // Opcode: FSOR_D
/* 9670 */    MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 9682
/* 9674 */    MCD_OPC_CheckPredicate, 6, 93, 14, // Skip to: 13355
/* 9678 */    MCD_OPC_Decode, 165, 6, 116, // Opcode: FSUNE_W
/* 9682 */    MCD_OPC_FilterValue, 21, 8, 0, // Skip to: 9694
/* 9686 */    MCD_OPC_CheckPredicate, 6, 81, 14, // Skip to: 13355
/* 9690 */    MCD_OPC_Decode, 164, 6, 117, // Opcode: FSUNE_D
/* 9694 */    MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 9706
/* 9698 */    MCD_OPC_CheckPredicate, 6, 69, 14, // Skip to: 13355
/* 9702 */    MCD_OPC_Decode, 141, 6, 116, // Opcode: FSNE_W
/* 9706 */    MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 9718
/* 9710 */    MCD_OPC_CheckPredicate, 6, 57, 14, // Skip to: 13355
/* 9714 */    MCD_OPC_Decode, 140, 6, 117, // Opcode: FSNE_D
/* 9718 */    MCD_OPC_FilterValue, 24, 8, 0, // Skip to: 9730
/* 9722 */    MCD_OPC_CheckPredicate, 6, 45, 14, // Skip to: 13355
/* 9726 */    MCD_OPC_Decode, 163, 9, 115, // Opcode: MULR_Q_H
/* 9730 */    MCD_OPC_FilterValue, 25, 8, 0, // Skip to: 9742
/* 9734 */    MCD_OPC_CheckPredicate, 6, 33, 14, // Skip to: 13355
/* 9738 */    MCD_OPC_Decode, 164, 9, 116, // Opcode: MULR_Q_W
/* 9742 */    MCD_OPC_FilterValue, 26, 8, 0, // Skip to: 9754
/* 9746 */    MCD_OPC_CheckPredicate, 6, 21, 14, // Skip to: 13355
/* 9750 */    MCD_OPC_Decode, 223, 7, 119, // Opcode: MADDR_Q_H
/* 9754 */    MCD_OPC_FilterValue, 27, 8, 0, // Skip to: 9766
/* 9758 */    MCD_OPC_CheckPredicate, 6, 9, 14, // Skip to: 13355
/* 9762 */    MCD_OPC_Decode, 224, 7, 120, // Opcode: MADDR_Q_W
/* 9766 */    MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 9778
/* 9770 */    MCD_OPC_CheckPredicate, 6, 253, 13, // Skip to: 13355
/* 9774 */    MCD_OPC_Decode, 240, 8, 119, // Opcode: MSUBR_Q_H
/* 9778 */    MCD_OPC_FilterValue, 29, 245, 13, // Skip to: 13355
/* 9782 */    MCD_OPC_CheckPredicate, 6, 241, 13, // Skip to: 13355
/* 9786 */    MCD_OPC_Decode, 241, 8, 120, // Opcode: MSUBR_Q_W
/* 9790 */    MCD_OPC_FilterValue, 30, 212, 2, // Skip to: 10518
/* 9794 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 9797 */    MCD_OPC_FilterValue, 0, 7, 0, // Skip to: 9808
/* 9801 */    MCD_OPC_CheckPredicate, 6, 222, 13, // Skip to: 13355
/* 9805 */    MCD_OPC_Decode, 79, 114, // Opcode: AND_V
/* 9808 */    MCD_OPC_FilterValue, 1, 8, 0, // Skip to: 9820
/* 9812 */    MCD_OPC_CheckPredicate, 6, 211, 13, // Skip to: 13355
/* 9816 */    MCD_OPC_Decode, 225, 9, 114, // Opcode: OR_V
/* 9820 */    MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 9832
/* 9824 */    MCD_OPC_CheckPredicate, 6, 199, 13, // Skip to: 13355
/* 9828 */    MCD_OPC_Decode, 215, 9, 114, // Opcode: NOR_V
/* 9832 */    MCD_OPC_FilterValue, 3, 8, 0, // Skip to: 9844
/* 9836 */    MCD_OPC_CheckPredicate, 6, 187, 13, // Skip to: 13355
/* 9840 */    MCD_OPC_Decode, 166, 13, 114, // Opcode: XOR_V
/* 9844 */    MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 9856
/* 9848 */    MCD_OPC_CheckPredicate, 6, 175, 13, // Skip to: 13355
/* 9852 */    MCD_OPC_Decode, 254, 1, 118, // Opcode: BMNZ_V
/* 9856 */    MCD_OPC_FilterValue, 5, 8, 0, // Skip to: 9868
/* 9860 */    MCD_OPC_CheckPredicate, 6, 163, 13, // Skip to: 13355
/* 9864 */    MCD_OPC_Decode, 128, 2, 118, // Opcode: BMZ_V
/* 9868 */    MCD_OPC_FilterValue, 6, 8, 0, // Skip to: 9880
/* 9872 */    MCD_OPC_CheckPredicate, 6, 151, 13, // Skip to: 13355
/* 9876 */    MCD_OPC_Decode, 161, 2, 118, // Opcode: BSEL_V
/* 9880 */    MCD_OPC_FilterValue, 24, 211, 0, // Skip to: 10095
/* 9884 */    MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 9887 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 9900
/* 9891 */    MCD_OPC_CheckPredicate, 6, 132, 13, // Skip to: 13355
/* 9895 */    MCD_OPC_Decode, 210, 5, 158, 1, // Opcode: FILL_B
/* 9900 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 9913
/* 9904 */    MCD_OPC_CheckPredicate, 6, 119, 13, // Skip to: 13355
/* 9908 */    MCD_OPC_Decode, 214, 5, 159, 1, // Opcode: FILL_H
/* 9913 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 9926
/* 9917 */    MCD_OPC_CheckPredicate, 6, 106, 13, // Skip to: 13355
/* 9921 */    MCD_OPC_Decode, 215, 5, 160, 1, // Opcode: FILL_W
/* 9926 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 9939
/* 9930 */    MCD_OPC_CheckPredicate, 13, 93, 13, // Skip to: 13355
/* 9934 */    MCD_OPC_Decode, 211, 5, 161, 1, // Opcode: FILL_D
/* 9939 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 9952
/* 9943 */    MCD_OPC_CheckPredicate, 6, 80, 13, // Skip to: 13355
/* 9947 */    MCD_OPC_Decode, 243, 9, 150, 1, // Opcode: PCNT_B
/* 9952 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 9965
/* 9956 */    MCD_OPC_CheckPredicate, 6, 67, 13, // Skip to: 13355
/* 9960 */    MCD_OPC_Decode, 245, 9, 162, 1, // Opcode: PCNT_H
/* 9965 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 9978
/* 9969 */    MCD_OPC_CheckPredicate, 6, 54, 13, // Skip to: 13355
/* 9973 */    MCD_OPC_Decode, 246, 9, 163, 1, // Opcode: PCNT_W
/* 9978 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 9991
/* 9982 */    MCD_OPC_CheckPredicate, 6, 41, 13, // Skip to: 13355
/* 9986 */    MCD_OPC_Decode, 244, 9, 164, 1, // Opcode: PCNT_D
/* 9991 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 10004
/* 9995 */    MCD_OPC_CheckPredicate, 6, 28, 13, // Skip to: 13355
/* 9999 */    MCD_OPC_Decode, 192, 9, 150, 1, // Opcode: NLOC_B
/* 10004 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 10017
/* 10008 */   MCD_OPC_CheckPredicate, 6, 15, 13, // Skip to: 13355
/* 10012 */   MCD_OPC_Decode, 194, 9, 162, 1, // Opcode: NLOC_H
/* 10017 */   MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 10030
/* 10021 */   MCD_OPC_CheckPredicate, 6, 2, 13, // Skip to: 13355
/* 10025 */   MCD_OPC_Decode, 195, 9, 163, 1, // Opcode: NLOC_W
/* 10030 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 10043
/* 10034 */   MCD_OPC_CheckPredicate, 6, 245, 12, // Skip to: 13355
/* 10038 */   MCD_OPC_Decode, 193, 9, 164, 1, // Opcode: NLOC_D
/* 10043 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 10056
/* 10047 */   MCD_OPC_CheckPredicate, 6, 232, 12, // Skip to: 13355
/* 10051 */   MCD_OPC_Decode, 196, 9, 150, 1, // Opcode: NLZC_B
/* 10056 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 10069
/* 10060 */   MCD_OPC_CheckPredicate, 6, 219, 12, // Skip to: 13355
/* 10064 */   MCD_OPC_Decode, 198, 9, 162, 1, // Opcode: NLZC_H
/* 10069 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 10082
/* 10073 */   MCD_OPC_CheckPredicate, 6, 206, 12, // Skip to: 13355
/* 10077 */   MCD_OPC_Decode, 199, 9, 163, 1, // Opcode: NLZC_W
/* 10082 */   MCD_OPC_FilterValue, 15, 197, 12, // Skip to: 13355
/* 10086 */   MCD_OPC_CheckPredicate, 6, 193, 12, // Skip to: 13355
/* 10090 */   MCD_OPC_Decode, 197, 9, 164, 1, // Opcode: NLZC_D
/* 10095 */   MCD_OPC_FilterValue, 25, 184, 12, // Skip to: 13355
/* 10099 */   MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 10102 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 10115
/* 10106 */   MCD_OPC_CheckPredicate, 6, 173, 12, // Skip to: 13355
/* 10110 */   MCD_OPC_Decode, 161, 5, 163, 1, // Opcode: FCLASS_W
/* 10115 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 10128
/* 10119 */   MCD_OPC_CheckPredicate, 6, 160, 12, // Skip to: 13355
/* 10123 */   MCD_OPC_Decode, 160, 5, 164, 1, // Opcode: FCLASS_D
/* 10128 */   MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 10141
/* 10132 */   MCD_OPC_CheckPredicate, 6, 147, 12, // Skip to: 13355
/* 10136 */   MCD_OPC_Decode, 175, 6, 163, 1, // Opcode: FTRUNC_S_W
/* 10141 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 10154
/* 10145 */   MCD_OPC_CheckPredicate, 6, 134, 12, // Skip to: 13355
/* 10149 */   MCD_OPC_Decode, 174, 6, 164, 1, // Opcode: FTRUNC_S_D
/* 10154 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 10167
/* 10158 */   MCD_OPC_CheckPredicate, 6, 121, 12, // Skip to: 13355
/* 10162 */   MCD_OPC_Decode, 177, 6, 163, 1, // Opcode: FTRUNC_U_W
/* 10167 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 10180
/* 10171 */   MCD_OPC_CheckPredicate, 6, 108, 12, // Skip to: 13355
/* 10175 */   MCD_OPC_Decode, 176, 6, 164, 1, // Opcode: FTRUNC_U_D
/* 10180 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 10193
/* 10184 */   MCD_OPC_CheckPredicate, 6, 95, 12, // Skip to: 13355
/* 10188 */   MCD_OPC_Decode, 150, 6, 163, 1, // Opcode: FSQRT_W
/* 10193 */   MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 10206
/* 10197 */   MCD_OPC_CheckPredicate, 6, 82, 12, // Skip to: 13355
/* 10201 */   MCD_OPC_Decode, 144, 6, 164, 1, // Opcode: FSQRT_D
/* 10206 */   MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 10219
/* 10210 */   MCD_OPC_CheckPredicate, 6, 69, 12, // Skip to: 13355
/* 10214 */   MCD_OPC_Decode, 131, 6, 163, 1, // Opcode: FRSQRT_W
/* 10219 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 10232
/* 10223 */   MCD_OPC_CheckPredicate, 6, 56, 12, // Skip to: 13355
/* 10227 */   MCD_OPC_Decode, 130, 6, 164, 1, // Opcode: FRSQRT_D
/* 10232 */   MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 10245
/* 10236 */   MCD_OPC_CheckPredicate, 6, 43, 12, // Skip to: 13355
/* 10240 */   MCD_OPC_Decode, 255, 5, 163, 1, // Opcode: FRCP_W
/* 10245 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 10258
/* 10249 */   MCD_OPC_CheckPredicate, 6, 30, 12, // Skip to: 13355
/* 10253 */   MCD_OPC_Decode, 254, 5, 164, 1, // Opcode: FRCP_D
/* 10258 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 10271
/* 10262 */   MCD_OPC_CheckPredicate, 6, 17, 12, // Skip to: 13355
/* 10266 */   MCD_OPC_Decode, 129, 6, 163, 1, // Opcode: FRINT_W
/* 10271 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 10284
/* 10275 */   MCD_OPC_CheckPredicate, 6, 4, 12, // Skip to: 13355
/* 10279 */   MCD_OPC_Decode, 128, 6, 164, 1, // Opcode: FRINT_D
/* 10284 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 10297
/* 10288 */   MCD_OPC_CheckPredicate, 6, 247, 11, // Skip to: 13355
/* 10292 */   MCD_OPC_Decode, 217, 5, 163, 1, // Opcode: FLOG2_W
/* 10297 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 10310
/* 10301 */   MCD_OPC_CheckPredicate, 6, 234, 11, // Skip to: 13355
/* 10305 */   MCD_OPC_Decode, 216, 5, 164, 1, // Opcode: FLOG2_D
/* 10310 */   MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 10323
/* 10314 */   MCD_OPC_CheckPredicate, 6, 221, 11, // Skip to: 13355
/* 10318 */   MCD_OPC_Decode, 199, 5, 165, 1, // Opcode: FEXUPL_W
/* 10323 */   MCD_OPC_FilterValue, 17, 9, 0, // Skip to: 10336
/* 10327 */   MCD_OPC_CheckPredicate, 6, 208, 11, // Skip to: 13355
/* 10331 */   MCD_OPC_Decode, 198, 5, 166, 1, // Opcode: FEXUPL_D
/* 10336 */   MCD_OPC_FilterValue, 18, 9, 0, // Skip to: 10349
/* 10340 */   MCD_OPC_CheckPredicate, 6, 195, 11, // Skip to: 13355
/* 10344 */   MCD_OPC_Decode, 201, 5, 165, 1, // Opcode: FEXUPR_W
/* 10349 */   MCD_OPC_FilterValue, 19, 9, 0, // Skip to: 10362
/* 10353 */   MCD_OPC_CheckPredicate, 6, 182, 11, // Skip to: 13355
/* 10357 */   MCD_OPC_Decode, 200, 5, 166, 1, // Opcode: FEXUPR_D
/* 10362 */   MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 10375
/* 10366 */   MCD_OPC_CheckPredicate, 6, 169, 11, // Skip to: 13355
/* 10370 */   MCD_OPC_Decode, 207, 5, 165, 1, // Opcode: FFQL_W
/* 10375 */   MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 10388
/* 10379 */   MCD_OPC_CheckPredicate, 6, 156, 11, // Skip to: 13355
/* 10383 */   MCD_OPC_Decode, 206, 5, 166, 1, // Opcode: FFQL_D
/* 10388 */   MCD_OPC_FilterValue, 22, 9, 0, // Skip to: 10401
/* 10392 */   MCD_OPC_CheckPredicate, 6, 143, 11, // Skip to: 13355
/* 10396 */   MCD_OPC_Decode, 209, 5, 165, 1, // Opcode: FFQR_W
/* 10401 */   MCD_OPC_FilterValue, 23, 9, 0, // Skip to: 10414
/* 10405 */   MCD_OPC_CheckPredicate, 6, 130, 11, // Skip to: 13355
/* 10409 */   MCD_OPC_Decode, 208, 5, 166, 1, // Opcode: FFQR_D
/* 10414 */   MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 10427
/* 10418 */   MCD_OPC_CheckPredicate, 6, 117, 11, // Skip to: 13355
/* 10422 */   MCD_OPC_Decode, 169, 6, 163, 1, // Opcode: FTINT_S_W
/* 10427 */   MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 10440
/* 10431 */   MCD_OPC_CheckPredicate, 6, 104, 11, // Skip to: 13355
/* 10435 */   MCD_OPC_Decode, 168, 6, 164, 1, // Opcode: FTINT_S_D
/* 10440 */   MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 10453
/* 10444 */   MCD_OPC_CheckPredicate, 6, 91, 11, // Skip to: 13355
/* 10448 */   MCD_OPC_Decode, 171, 6, 163, 1, // Opcode: FTINT_U_W
/* 10453 */   MCD_OPC_FilterValue, 27, 9, 0, // Skip to: 10466
/* 10457 */   MCD_OPC_CheckPredicate, 6, 78, 11, // Skip to: 13355
/* 10461 */   MCD_OPC_Decode, 170, 6, 164, 1, // Opcode: FTINT_U_D
/* 10466 */   MCD_OPC_FilterValue, 28, 9, 0, // Skip to: 10479
/* 10470 */   MCD_OPC_CheckPredicate, 6, 65, 11, // Skip to: 13355
/* 10474 */   MCD_OPC_Decode, 203, 5, 163, 1, // Opcode: FFINT_S_W
/* 10479 */   MCD_OPC_FilterValue, 29, 9, 0, // Skip to: 10492
/* 10483 */   MCD_OPC_CheckPredicate, 6, 52, 11, // Skip to: 13355
/* 10487 */   MCD_OPC_Decode, 202, 5, 164, 1, // Opcode: FFINT_S_D
/* 10492 */   MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 10505
/* 10496 */   MCD_OPC_CheckPredicate, 6, 39, 11, // Skip to: 13355
/* 10500 */   MCD_OPC_Decode, 205, 5, 163, 1, // Opcode: FFINT_U_W
/* 10505 */   MCD_OPC_FilterValue, 31, 30, 11, // Skip to: 13355
/* 10509 */   MCD_OPC_CheckPredicate, 6, 26, 11, // Skip to: 13355
/* 10513 */   MCD_OPC_Decode, 204, 5, 164, 1, // Opcode: FFINT_U_D
/* 10518 */   MCD_OPC_FilterValue, 32, 9, 0, // Skip to: 10531
/* 10522 */   MCD_OPC_CheckPredicate, 6, 13, 11, // Skip to: 13355
/* 10526 */   MCD_OPC_Decode, 149, 7, 167, 1, // Opcode: LD_B
/* 10531 */   MCD_OPC_FilterValue, 33, 9, 0, // Skip to: 10544
/* 10535 */   MCD_OPC_CheckPredicate, 6, 0, 11, // Skip to: 13355
/* 10539 */   MCD_OPC_Decode, 151, 7, 167, 1, // Opcode: LD_H
/* 10544 */   MCD_OPC_FilterValue, 34, 9, 0, // Skip to: 10557
/* 10548 */   MCD_OPC_CheckPredicate, 6, 243, 10, // Skip to: 13355
/* 10552 */   MCD_OPC_Decode, 152, 7, 167, 1, // Opcode: LD_W
/* 10557 */   MCD_OPC_FilterValue, 35, 9, 0, // Skip to: 10570
/* 10561 */   MCD_OPC_CheckPredicate, 6, 230, 10, // Skip to: 13355
/* 10565 */   MCD_OPC_Decode, 150, 7, 167, 1, // Opcode: LD_D
/* 10570 */   MCD_OPC_FilterValue, 36, 9, 0, // Skip to: 10583
/* 10574 */   MCD_OPC_CheckPredicate, 6, 217, 10, // Skip to: 13355
/* 10578 */   MCD_OPC_Decode, 248, 11, 167, 1, // Opcode: ST_B
/* 10583 */   MCD_OPC_FilterValue, 37, 9, 0, // Skip to: 10596
/* 10587 */   MCD_OPC_CheckPredicate, 6, 204, 10, // Skip to: 13355
/* 10591 */   MCD_OPC_Decode, 250, 11, 167, 1, // Opcode: ST_H
/* 10596 */   MCD_OPC_FilterValue, 38, 9, 0, // Skip to: 10609
/* 10600 */   MCD_OPC_CheckPredicate, 6, 191, 10, // Skip to: 13355
/* 10604 */   MCD_OPC_Decode, 251, 11, 167, 1, // Opcode: ST_W
/* 10609 */   MCD_OPC_FilterValue, 39, 182, 10, // Skip to: 13355
/* 10613 */   MCD_OPC_CheckPredicate, 6, 178, 10, // Skip to: 13355
/* 10617 */   MCD_OPC_Decode, 249, 11, 167, 1, // Opcode: ST_D
/* 10622 */   MCD_OPC_FilterValue, 31, 113, 9, // Skip to: 13043
/* 10626 */   MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10629 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 10642
/* 10633 */   MCD_OPC_CheckPredicate, 4, 158, 10, // Skip to: 13355
/* 10637 */   MCD_OPC_Decode, 252, 4, 168, 1, // Opcode: EXT
/* 10642 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 10655
/* 10646 */   MCD_OPC_CheckPredicate, 4, 145, 10, // Skip to: 13355
/* 10650 */   MCD_OPC_Decode, 207, 6, 169, 1, // Opcode: INS
/* 10655 */   MCD_OPC_FilterValue, 10, 42, 0, // Skip to: 10701
/* 10659 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10662 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 10675
/* 10666 */   MCD_OPC_CheckPredicate, 11, 125, 10, // Skip to: 13355
/* 10670 */   MCD_OPC_Decode, 199, 7, 170, 1, // Opcode: LWX
/* 10675 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 10688
/* 10679 */   MCD_OPC_CheckPredicate, 11, 112, 10, // Skip to: 13355
/* 10683 */   MCD_OPC_Decode, 158, 7, 170, 1, // Opcode: LHX
/* 10688 */   MCD_OPC_FilterValue, 6, 103, 10, // Skip to: 13355
/* 10692 */   MCD_OPC_CheckPredicate, 11, 99, 10, // Skip to: 13355
/* 10696 */   MCD_OPC_Decode, 128, 7, 170, 1, // Opcode: LBUX
/* 10701 */   MCD_OPC_FilterValue, 12, 15, 0, // Skip to: 10720
/* 10705 */   MCD_OPC_CheckPredicate, 11, 86, 10, // Skip to: 13355
/* 10709 */   MCD_OPC_CheckField, 6, 10, 0, 80, 10, // Skip to: 13355
/* 10715 */   MCD_OPC_Decode, 220, 6, 171, 1, // Opcode: INSV
/* 10720 */   MCD_OPC_FilterValue, 16, 51, 1, // Skip to: 11031
/* 10724 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 10727 */   MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 10739
/* 10731 */   MCD_OPC_CheckPredicate, 11, 60, 10, // Skip to: 13355
/* 10735 */   MCD_OPC_Decode, 48, 172, 1, // Opcode: ADDU_QB
/* 10739 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 10752
/* 10743 */   MCD_OPC_CheckPredicate, 11, 48, 10, // Skip to: 13355
/* 10747 */   MCD_OPC_Decode, 151, 12, 172, 1, // Opcode: SUBU_QB
/* 10752 */   MCD_OPC_FilterValue, 4, 8, 0, // Skip to: 10764
/* 10756 */   MCD_OPC_CheckPredicate, 11, 35, 10, // Skip to: 13355
/* 10760 */   MCD_OPC_Decode, 50, 172, 1, // Opcode: ADDU_S_QB
/* 10764 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 10777
/* 10768 */   MCD_OPC_CheckPredicate, 11, 23, 10, // Skip to: 13355
/* 10772 */   MCD_OPC_Decode, 153, 12, 172, 1, // Opcode: SUBU_S_QB
/* 10777 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 10790
/* 10781 */   MCD_OPC_CheckPredicate, 11, 10, 10, // Skip to: 13355
/* 10785 */   MCD_OPC_Decode, 157, 9, 172, 1, // Opcode: MULEU_S_PH_QBL
/* 10790 */   MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 10803
/* 10794 */   MCD_OPC_CheckPredicate, 11, 253, 9, // Skip to: 13355
/* 10798 */   MCD_OPC_Decode, 158, 9, 172, 1, // Opcode: MULEU_S_PH_QBR
/* 10803 */   MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 10815
/* 10807 */   MCD_OPC_CheckPredicate, 29, 240, 9, // Skip to: 13355
/* 10811 */   MCD_OPC_Decode, 47, 172, 1, // Opcode: ADDU_PH
/* 10815 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 10828
/* 10819 */   MCD_OPC_CheckPredicate, 29, 228, 9, // Skip to: 13355
/* 10823 */   MCD_OPC_Decode, 150, 12, 172, 1, // Opcode: SUBU_PH
/* 10828 */   MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 10840
/* 10832 */   MCD_OPC_CheckPredicate, 11, 215, 9, // Skip to: 13355
/* 10836 */   MCD_OPC_Decode, 29, 172, 1, // Opcode: ADDQ_PH
/* 10840 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 10853
/* 10844 */   MCD_OPC_CheckPredicate, 11, 203, 9, // Skip to: 13355
/* 10848 */   MCD_OPC_Decode, 129, 12, 172, 1, // Opcode: SUBQ_PH
/* 10853 */   MCD_OPC_FilterValue, 12, 8, 0, // Skip to: 10865
/* 10857 */   MCD_OPC_CheckPredicate, 29, 190, 9, // Skip to: 13355
/* 10861 */   MCD_OPC_Decode, 49, 172, 1, // Opcode: ADDU_S_PH
/* 10865 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 10878
/* 10869 */   MCD_OPC_CheckPredicate, 29, 178, 9, // Skip to: 13355
/* 10873 */   MCD_OPC_Decode, 152, 12, 172, 1, // Opcode: SUBU_S_PH
/* 10878 */   MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 10890
/* 10882 */   MCD_OPC_CheckPredicate, 11, 165, 9, // Skip to: 13355
/* 10886 */   MCD_OPC_Decode, 30, 172, 1, // Opcode: ADDQ_S_PH
/* 10890 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 10903
/* 10894 */   MCD_OPC_CheckPredicate, 11, 153, 9, // Skip to: 13355
/* 10898 */   MCD_OPC_Decode, 130, 12, 172, 1, // Opcode: SUBQ_S_PH
/* 10903 */   MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 10914
/* 10907 */   MCD_OPC_CheckPredicate, 11, 140, 9, // Skip to: 13355
/* 10911 */   MCD_OPC_Decode, 32, 17, // Opcode: ADDSC
/* 10914 */   MCD_OPC_FilterValue, 17, 7, 0, // Skip to: 10925
/* 10918 */   MCD_OPC_CheckPredicate, 11, 129, 9, // Skip to: 13355
/* 10922 */   MCD_OPC_Decode, 59, 17, // Opcode: ADDWC
/* 10925 */   MCD_OPC_FilterValue, 18, 8, 0, // Skip to: 10937
/* 10929 */   MCD_OPC_CheckPredicate, 11, 118, 9, // Skip to: 13355
/* 10933 */   MCD_OPC_Decode, 185, 8, 17, // Opcode: MODSUB
/* 10937 */   MCD_OPC_FilterValue, 20, 15, 0, // Skip to: 10956
/* 10941 */   MCD_OPC_CheckPredicate, 11, 106, 9, // Skip to: 13355
/* 10945 */   MCD_OPC_CheckField, 16, 5, 0, 100, 9, // Skip to: 13355
/* 10951 */   MCD_OPC_Decode, 178, 10, 173, 1, // Opcode: RADDU_W_QB
/* 10956 */   MCD_OPC_FilterValue, 22, 7, 0, // Skip to: 10967
/* 10960 */   MCD_OPC_CheckPredicate, 11, 87, 9, // Skip to: 13355
/* 10964 */   MCD_OPC_Decode, 31, 17, // Opcode: ADDQ_S_W
/* 10967 */   MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 10979
/* 10971 */   MCD_OPC_CheckPredicate, 11, 76, 9, // Skip to: 13355
/* 10975 */   MCD_OPC_Decode, 131, 12, 17, // Opcode: SUBQ_S_W
/* 10979 */   MCD_OPC_FilterValue, 28, 9, 0, // Skip to: 10992
/* 10983 */   MCD_OPC_CheckPredicate, 11, 64, 9, // Skip to: 13355
/* 10987 */   MCD_OPC_Decode, 155, 9, 174, 1, // Opcode: MULEQ_S_W_PHL
/* 10992 */   MCD_OPC_FilterValue, 29, 9, 0, // Skip to: 11005
/* 10996 */   MCD_OPC_CheckPredicate, 11, 51, 9, // Skip to: 13355
/* 11000 */   MCD_OPC_Decode, 156, 9, 174, 1, // Opcode: MULEQ_S_W_PHR
/* 11005 */   MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 11018
/* 11009 */   MCD_OPC_CheckPredicate, 29, 38, 9, // Skip to: 13355
/* 11013 */   MCD_OPC_Decode, 161, 9, 172, 1, // Opcode: MULQ_S_PH
/* 11018 */   MCD_OPC_FilterValue, 31, 29, 9, // Skip to: 13355
/* 11022 */   MCD_OPC_CheckPredicate, 11, 25, 9, // Skip to: 13355
/* 11026 */   MCD_OPC_Decode, 159, 9, 172, 1, // Opcode: MULQ_RS_PH
/* 11031 */   MCD_OPC_FilterValue, 17, 69, 1, // Skip to: 11360
/* 11035 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11038 */   MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 11057
/* 11042 */   MCD_OPC_CheckPredicate, 11, 5, 9, // Skip to: 13355
/* 11046 */   MCD_OPC_CheckField, 11, 5, 0, 255, 8, // Skip to: 13355
/* 11052 */   MCD_OPC_Decode, 141, 3, 175, 1, // Opcode: CMPU_EQ_QB
/* 11057 */   MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 11076
/* 11061 */   MCD_OPC_CheckPredicate, 11, 242, 8, // Skip to: 13355
/* 11065 */   MCD_OPC_CheckField, 11, 5, 0, 236, 8, // Skip to: 13355
/* 11071 */   MCD_OPC_Decode, 143, 3, 175, 1, // Opcode: CMPU_LT_QB
/* 11076 */   MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 11095
/* 11080 */   MCD_OPC_CheckPredicate, 11, 223, 8, // Skip to: 13355
/* 11084 */   MCD_OPC_CheckField, 11, 5, 0, 217, 8, // Skip to: 13355
/* 11090 */   MCD_OPC_Decode, 142, 3, 175, 1, // Opcode: CMPU_LE_QB
/* 11095 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 11108
/* 11099 */   MCD_OPC_CheckPredicate, 11, 204, 8, // Skip to: 13355
/* 11103 */   MCD_OPC_Decode, 248, 9, 172, 1, // Opcode: PICK_QB
/* 11108 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 11121
/* 11112 */   MCD_OPC_CheckPredicate, 11, 191, 8, // Skip to: 13355
/* 11116 */   MCD_OPC_Decode, 138, 3, 174, 1, // Opcode: CMPGU_EQ_QB
/* 11121 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 11134
/* 11125 */   MCD_OPC_CheckPredicate, 11, 178, 8, // Skip to: 13355
/* 11129 */   MCD_OPC_Decode, 140, 3, 174, 1, // Opcode: CMPGU_LT_QB
/* 11134 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 11147
/* 11138 */   MCD_OPC_CheckPredicate, 11, 165, 8, // Skip to: 13355
/* 11142 */   MCD_OPC_Decode, 139, 3, 174, 1, // Opcode: CMPGU_LE_QB
/* 11147 */   MCD_OPC_FilterValue, 8, 15, 0, // Skip to: 11166
/* 11151 */   MCD_OPC_CheckPredicate, 11, 152, 8, // Skip to: 13355
/* 11155 */   MCD_OPC_CheckField, 11, 5, 0, 146, 8, // Skip to: 13355
/* 11161 */   MCD_OPC_Decode, 145, 3, 175, 1, // Opcode: CMP_EQ_PH
/* 11166 */   MCD_OPC_FilterValue, 9, 15, 0, // Skip to: 11185
/* 11170 */   MCD_OPC_CheckPredicate, 11, 133, 8, // Skip to: 13355
/* 11174 */   MCD_OPC_CheckField, 11, 5, 0, 127, 8, // Skip to: 13355
/* 11180 */   MCD_OPC_Decode, 153, 3, 175, 1, // Opcode: CMP_LT_PH
/* 11185 */   MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 11204
/* 11189 */   MCD_OPC_CheckPredicate, 11, 114, 8, // Skip to: 13355
/* 11193 */   MCD_OPC_CheckField, 11, 5, 0, 108, 8, // Skip to: 13355
/* 11199 */   MCD_OPC_Decode, 150, 3, 175, 1, // Opcode: CMP_LE_PH
/* 11204 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 11217
/* 11208 */   MCD_OPC_CheckPredicate, 11, 95, 8, // Skip to: 13355
/* 11212 */   MCD_OPC_Decode, 247, 9, 172, 1, // Opcode: PICK_PH
/* 11217 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 11230
/* 11221 */   MCD_OPC_CheckPredicate, 11, 82, 8, // Skip to: 13355
/* 11225 */   MCD_OPC_Decode, 134, 10, 172, 1, // Opcode: PRECRQ_QB_PH
/* 11230 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 11243
/* 11234 */   MCD_OPC_CheckPredicate, 29, 69, 8, // Skip to: 13355
/* 11238 */   MCD_OPC_Decode, 136, 10, 172, 1, // Opcode: PRECR_QB_PH
/* 11243 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 11256
/* 11247 */   MCD_OPC_CheckPredicate, 11, 56, 8, // Skip to: 13355
/* 11251 */   MCD_OPC_Decode, 233, 9, 172, 1, // Opcode: PACKRL_PH
/* 11256 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 11269
/* 11260 */   MCD_OPC_CheckPredicate, 11, 43, 8, // Skip to: 13355
/* 11264 */   MCD_OPC_Decode, 132, 10, 172, 1, // Opcode: PRECRQU_S_QB_PH
/* 11269 */   MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 11282
/* 11273 */   MCD_OPC_CheckPredicate, 11, 30, 8, // Skip to: 13355
/* 11277 */   MCD_OPC_Decode, 133, 10, 176, 1, // Opcode: PRECRQ_PH_W
/* 11282 */   MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 11295
/* 11286 */   MCD_OPC_CheckPredicate, 11, 17, 8, // Skip to: 13355
/* 11290 */   MCD_OPC_Decode, 135, 10, 176, 1, // Opcode: PRECRQ_RS_PH_W
/* 11295 */   MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 11308
/* 11299 */   MCD_OPC_CheckPredicate, 29, 4, 8, // Skip to: 13355
/* 11303 */   MCD_OPC_Decode, 135, 3, 174, 1, // Opcode: CMPGDU_EQ_QB
/* 11308 */   MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 11321
/* 11312 */   MCD_OPC_CheckPredicate, 29, 247, 7, // Skip to: 13355
/* 11316 */   MCD_OPC_Decode, 137, 3, 174, 1, // Opcode: CMPGDU_LT_QB
/* 11321 */   MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 11334
/* 11325 */   MCD_OPC_CheckPredicate, 29, 234, 7, // Skip to: 13355
/* 11329 */   MCD_OPC_Decode, 136, 3, 174, 1, // Opcode: CMPGDU_LE_QB
/* 11334 */   MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 11347
/* 11338 */   MCD_OPC_CheckPredicate, 29, 221, 7, // Skip to: 13355
/* 11342 */   MCD_OPC_Decode, 137, 10, 177, 1, // Opcode: PRECR_SRA_PH_W
/* 11347 */   MCD_OPC_FilterValue, 31, 212, 7, // Skip to: 13355
/* 11351 */   MCD_OPC_CheckPredicate, 29, 208, 7, // Skip to: 13355
/* 11355 */   MCD_OPC_Decode, 138, 10, 177, 1, // Opcode: PRECR_SRA_R_PH_W
/* 11360 */   MCD_OPC_FilterValue, 18, 74, 1, // Skip to: 11694
/* 11364 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11367 */   MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 11385
/* 11371 */   MCD_OPC_CheckPredicate, 29, 188, 7, // Skip to: 13355
/* 11375 */   MCD_OPC_CheckField, 21, 5, 0, 182, 7, // Skip to: 13355
/* 11381 */   MCD_OPC_Decode, 21, 178, 1, // Opcode: ABSQ_S_QB
/* 11385 */   MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 11398
/* 11389 */   MCD_OPC_CheckPredicate, 11, 170, 7, // Skip to: 13355
/* 11393 */   MCD_OPC_Decode, 185, 10, 179, 1, // Opcode: REPL_QB
/* 11398 */   MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 11417
/* 11402 */   MCD_OPC_CheckPredicate, 11, 157, 7, // Skip to: 13355
/* 11406 */   MCD_OPC_CheckField, 21, 5, 0, 151, 7, // Skip to: 13355
/* 11412 */   MCD_OPC_Decode, 183, 10, 180, 1, // Opcode: REPLV_QB
/* 11417 */   MCD_OPC_FilterValue, 4, 15, 0, // Skip to: 11436
/* 11421 */   MCD_OPC_CheckPredicate, 11, 138, 7, // Skip to: 13355
/* 11425 */   MCD_OPC_CheckField, 21, 5, 0, 132, 7, // Skip to: 13355
/* 11431 */   MCD_OPC_Decode, 250, 9, 178, 1, // Opcode: PRECEQU_PH_QBL
/* 11436 */   MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 11455
/* 11440 */   MCD_OPC_CheckPredicate, 11, 119, 7, // Skip to: 13355
/* 11444 */   MCD_OPC_CheckField, 21, 5, 0, 113, 7, // Skip to: 13355
/* 11450 */   MCD_OPC_Decode, 252, 9, 178, 1, // Opcode: PRECEQU_PH_QBR
/* 11455 */   MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 11474
/* 11459 */   MCD_OPC_CheckPredicate, 11, 100, 7, // Skip to: 13355
/* 11463 */   MCD_OPC_CheckField, 21, 5, 0, 94, 7, // Skip to: 13355
/* 11469 */   MCD_OPC_Decode, 251, 9, 178, 1, // Opcode: PRECEQU_PH_QBLA
/* 11474 */   MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 11493
/* 11478 */   MCD_OPC_CheckPredicate, 11, 81, 7, // Skip to: 13355
/* 11482 */   MCD_OPC_CheckField, 21, 5, 0, 75, 7, // Skip to: 13355
/* 11488 */   MCD_OPC_Decode, 253, 9, 178, 1, // Opcode: PRECEQU_PH_QBRA
/* 11493 */   MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 11511
/* 11497 */   MCD_OPC_CheckPredicate, 11, 62, 7, // Skip to: 13355
/* 11501 */   MCD_OPC_CheckField, 21, 5, 0, 56, 7, // Skip to: 13355
/* 11507 */   MCD_OPC_Decode, 20, 178, 1, // Opcode: ABSQ_S_PH
/* 11511 */   MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 11524
/* 11515 */   MCD_OPC_CheckPredicate, 11, 44, 7, // Skip to: 13355
/* 11519 */   MCD_OPC_Decode, 184, 10, 179, 1, // Opcode: REPL_PH
/* 11524 */   MCD_OPC_FilterValue, 11, 15, 0, // Skip to: 11543
/* 11528 */   MCD_OPC_CheckPredicate, 11, 31, 7, // Skip to: 13355
/* 11532 */   MCD_OPC_CheckField, 21, 5, 0, 25, 7, // Skip to: 13355
/* 11538 */   MCD_OPC_Decode, 182, 10, 180, 1, // Opcode: REPLV_PH
/* 11543 */   MCD_OPC_FilterValue, 12, 15, 0, // Skip to: 11562
/* 11547 */   MCD_OPC_CheckPredicate, 11, 12, 7, // Skip to: 13355
/* 11551 */   MCD_OPC_CheckField, 21, 5, 0, 6, 7, // Skip to: 13355
/* 11557 */   MCD_OPC_Decode, 254, 9, 181, 1, // Opcode: PRECEQ_W_PHL
/* 11562 */   MCD_OPC_FilterValue, 13, 15, 0, // Skip to: 11581
/* 11566 */   MCD_OPC_CheckPredicate, 11, 249, 6, // Skip to: 13355
/* 11570 */   MCD_OPC_CheckField, 21, 5, 0, 243, 6, // Skip to: 13355
/* 11576 */   MCD_OPC_Decode, 255, 9, 181, 1, // Opcode: PRECEQ_W_PHR
/* 11581 */   MCD_OPC_FilterValue, 17, 14, 0, // Skip to: 11599
/* 11585 */   MCD_OPC_CheckPredicate, 11, 230, 6, // Skip to: 13355
/* 11589 */   MCD_OPC_CheckField, 21, 5, 0, 224, 6, // Skip to: 13355
/* 11595 */   MCD_OPC_Decode, 22, 182, 1, // Opcode: ABSQ_S_W
/* 11599 */   MCD_OPC_FilterValue, 27, 15, 0, // Skip to: 11618
/* 11603 */   MCD_OPC_CheckPredicate, 11, 212, 6, // Skip to: 13355
/* 11607 */   MCD_OPC_CheckField, 21, 5, 0, 206, 6, // Skip to: 13355
/* 11613 */   MCD_OPC_Decode, 233, 1, 182, 1, // Opcode: BITREV
/* 11618 */   MCD_OPC_FilterValue, 28, 15, 0, // Skip to: 11637
/* 11622 */   MCD_OPC_CheckPredicate, 11, 193, 6, // Skip to: 13355
/* 11626 */   MCD_OPC_CheckField, 21, 5, 0, 187, 6, // Skip to: 13355
/* 11632 */   MCD_OPC_Decode, 128, 10, 178, 1, // Opcode: PRECEU_PH_QBL
/* 11637 */   MCD_OPC_FilterValue, 29, 15, 0, // Skip to: 11656
/* 11641 */   MCD_OPC_CheckPredicate, 11, 174, 6, // Skip to: 13355
/* 11645 */   MCD_OPC_CheckField, 21, 5, 0, 168, 6, // Skip to: 13355
/* 11651 */   MCD_OPC_Decode, 130, 10, 178, 1, // Opcode: PRECEU_PH_QBR
/* 11656 */   MCD_OPC_FilterValue, 30, 15, 0, // Skip to: 11675
/* 11660 */   MCD_OPC_CheckPredicate, 11, 155, 6, // Skip to: 13355
/* 11664 */   MCD_OPC_CheckField, 21, 5, 0, 149, 6, // Skip to: 13355
/* 11670 */   MCD_OPC_Decode, 129, 10, 178, 1, // Opcode: PRECEU_PH_QBLA
/* 11675 */   MCD_OPC_FilterValue, 31, 140, 6, // Skip to: 13355
/* 11679 */   MCD_OPC_CheckPredicate, 11, 136, 6, // Skip to: 13355
/* 11683 */   MCD_OPC_CheckField, 21, 5, 0, 130, 6, // Skip to: 13355
/* 11689 */   MCD_OPC_Decode, 131, 10, 178, 1, // Opcode: PRECEU_PH_QBRA
/* 11694 */   MCD_OPC_FilterValue, 19, 31, 1, // Skip to: 11985
/* 11698 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11701 */   MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 11714
/* 11705 */   MCD_OPC_CheckPredicate, 11, 110, 6, // Skip to: 13355
/* 11709 */   MCD_OPC_Decode, 136, 11, 183, 1, // Opcode: SHLL_QB
/* 11714 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 11727
/* 11718 */   MCD_OPC_CheckPredicate, 11, 97, 6, // Skip to: 13355
/* 11722 */   MCD_OPC_Decode, 152, 11, 183, 1, // Opcode: SHRL_QB
/* 11727 */   MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 11740
/* 11731 */   MCD_OPC_CheckPredicate, 11, 84, 6, // Skip to: 13355
/* 11735 */   MCD_OPC_Decode, 132, 11, 184, 1, // Opcode: SHLLV_QB
/* 11740 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 11753
/* 11744 */   MCD_OPC_CheckPredicate, 11, 71, 6, // Skip to: 13355
/* 11748 */   MCD_OPC_Decode, 150, 11, 184, 1, // Opcode: SHRLV_QB
/* 11753 */   MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 11766
/* 11757 */   MCD_OPC_CheckPredicate, 29, 58, 6, // Skip to: 13355
/* 11761 */   MCD_OPC_Decode, 145, 11, 183, 1, // Opcode: SHRA_QB
/* 11766 */   MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 11779
/* 11770 */   MCD_OPC_CheckPredicate, 29, 45, 6, // Skip to: 13355
/* 11774 */   MCD_OPC_Decode, 147, 11, 183, 1, // Opcode: SHRA_R_QB
/* 11779 */   MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 11792
/* 11783 */   MCD_OPC_CheckPredicate, 29, 32, 6, // Skip to: 13355
/* 11787 */   MCD_OPC_Decode, 140, 11, 184, 1, // Opcode: SHRAV_QB
/* 11792 */   MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 11805
/* 11796 */   MCD_OPC_CheckPredicate, 29, 19, 6, // Skip to: 13355
/* 11800 */   MCD_OPC_Decode, 142, 11, 184, 1, // Opcode: SHRAV_R_QB
/* 11805 */   MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 11818
/* 11809 */   MCD_OPC_CheckPredicate, 11, 6, 6, // Skip to: 13355
/* 11813 */   MCD_OPC_Decode, 135, 11, 183, 1, // Opcode: SHLL_PH
/* 11818 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 11831
/* 11822 */   MCD_OPC_CheckPredicate, 11, 249, 5, // Skip to: 13355
/* 11826 */   MCD_OPC_Decode, 144, 11, 183, 1, // Opcode: SHRA_PH
/* 11831 */   MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 11844
/* 11835 */   MCD_OPC_CheckPredicate, 11, 236, 5, // Skip to: 13355
/* 11839 */   MCD_OPC_Decode, 131, 11, 184, 1, // Opcode: SHLLV_PH
/* 11844 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 11857
/* 11848 */   MCD_OPC_CheckPredicate, 11, 223, 5, // Skip to: 13355
/* 11852 */   MCD_OPC_Decode, 139, 11, 184, 1, // Opcode: SHRAV_PH
/* 11857 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 11870
/* 11861 */   MCD_OPC_CheckPredicate, 11, 210, 5, // Skip to: 13355
/* 11865 */   MCD_OPC_Decode, 137, 11, 183, 1, // Opcode: SHLL_S_PH
/* 11870 */   MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 11883
/* 11874 */   MCD_OPC_CheckPredicate, 11, 197, 5, // Skip to: 13355
/* 11878 */   MCD_OPC_Decode, 146, 11, 183, 1, // Opcode: SHRA_R_PH
/* 11883 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 11896
/* 11887 */   MCD_OPC_CheckPredicate, 11, 184, 5, // Skip to: 13355
/* 11891 */   MCD_OPC_Decode, 133, 11, 184, 1, // Opcode: SHLLV_S_PH
/* 11896 */   MCD_OPC_FilterValue, 15, 9, 0, // Skip to: 11909
/* 11900 */   MCD_OPC_CheckPredicate, 11, 171, 5, // Skip to: 13355
/* 11904 */   MCD_OPC_Decode, 141, 11, 184, 1, // Opcode: SHRAV_R_PH
/* 11909 */   MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 11922
/* 11913 */   MCD_OPC_CheckPredicate, 11, 158, 5, // Skip to: 13355
/* 11917 */   MCD_OPC_Decode, 138, 11, 185, 1, // Opcode: SHLL_S_W
/* 11922 */   MCD_OPC_FilterValue, 21, 9, 0, // Skip to: 11935
/* 11926 */   MCD_OPC_CheckPredicate, 11, 145, 5, // Skip to: 13355
/* 11930 */   MCD_OPC_Decode, 148, 11, 185, 1, // Opcode: SHRA_R_W
/* 11935 */   MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 11947
/* 11939 */   MCD_OPC_CheckPredicate, 11, 132, 5, // Skip to: 13355
/* 11943 */   MCD_OPC_Decode, 134, 11, 18, // Opcode: SHLLV_S_W
/* 11947 */   MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 11959
/* 11951 */   MCD_OPC_CheckPredicate, 11, 120, 5, // Skip to: 13355
/* 11955 */   MCD_OPC_Decode, 143, 11, 18, // Opcode: SHRAV_R_W
/* 11959 */   MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 11972
/* 11963 */   MCD_OPC_CheckPredicate, 29, 108, 5, // Skip to: 13355
/* 11967 */   MCD_OPC_Decode, 151, 11, 183, 1, // Opcode: SHRL_PH
/* 11972 */   MCD_OPC_FilterValue, 27, 99, 5, // Skip to: 13355
/* 11976 */   MCD_OPC_CheckPredicate, 29, 95, 5, // Skip to: 13355
/* 11980 */   MCD_OPC_Decode, 149, 11, 184, 1, // Opcode: SHRLV_PH
/* 11985 */   MCD_OPC_FilterValue, 24, 199, 0, // Skip to: 12188
/* 11989 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 11992 */   MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 12004
/* 11996 */   MCD_OPC_CheckPredicate, 29, 75, 5, // Skip to: 13355
/* 12000 */   MCD_OPC_Decode, 45, 172, 1, // Opcode: ADDUH_QB
/* 12004 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 12017
/* 12008 */   MCD_OPC_CheckPredicate, 29, 63, 5, // Skip to: 13355
/* 12012 */   MCD_OPC_Decode, 148, 12, 172, 1, // Opcode: SUBUH_QB
/* 12017 */   MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 12029
/* 12021 */   MCD_OPC_CheckPredicate, 29, 50, 5, // Skip to: 13355
/* 12025 */   MCD_OPC_Decode, 46, 172, 1, // Opcode: ADDUH_R_QB
/* 12029 */   MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 12042
/* 12033 */   MCD_OPC_CheckPredicate, 29, 38, 5, // Skip to: 13355
/* 12037 */   MCD_OPC_Decode, 149, 12, 172, 1, // Opcode: SUBUH_R_QB
/* 12042 */   MCD_OPC_FilterValue, 8, 8, 0, // Skip to: 12054
/* 12046 */   MCD_OPC_CheckPredicate, 29, 25, 5, // Skip to: 13355
/* 12050 */   MCD_OPC_Decode, 25, 172, 1, // Opcode: ADDQH_PH
/* 12054 */   MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 12067
/* 12058 */   MCD_OPC_CheckPredicate, 29, 13, 5, // Skip to: 13355
/* 12062 */   MCD_OPC_Decode, 253, 11, 172, 1, // Opcode: SUBQH_PH
/* 12067 */   MCD_OPC_FilterValue, 10, 8, 0, // Skip to: 12079
/* 12071 */   MCD_OPC_CheckPredicate, 29, 0, 5, // Skip to: 13355
/* 12075 */   MCD_OPC_Decode, 26, 172, 1, // Opcode: ADDQH_R_PH
/* 12079 */   MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 12092
/* 12083 */   MCD_OPC_CheckPredicate, 29, 244, 4, // Skip to: 13355
/* 12087 */   MCD_OPC_Decode, 254, 11, 172, 1, // Opcode: SUBQH_R_PH
/* 12092 */   MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 12105
/* 12096 */   MCD_OPC_CheckPredicate, 29, 231, 4, // Skip to: 13355
/* 12100 */   MCD_OPC_Decode, 179, 9, 172, 1, // Opcode: MUL_PH
/* 12105 */   MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 12118
/* 12109 */   MCD_OPC_CheckPredicate, 29, 218, 4, // Skip to: 13355
/* 12113 */   MCD_OPC_Decode, 183, 9, 172, 1, // Opcode: MUL_S_PH
/* 12118 */   MCD_OPC_FilterValue, 16, 7, 0, // Skip to: 12129
/* 12122 */   MCD_OPC_CheckPredicate, 29, 205, 4, // Skip to: 13355
/* 12126 */   MCD_OPC_Decode, 28, 17, // Opcode: ADDQH_W
/* 12129 */   MCD_OPC_FilterValue, 17, 8, 0, // Skip to: 12141
/* 12133 */   MCD_OPC_CheckPredicate, 29, 194, 4, // Skip to: 13355
/* 12137 */   MCD_OPC_Decode, 128, 12, 17, // Opcode: SUBQH_W
/* 12141 */   MCD_OPC_FilterValue, 18, 7, 0, // Skip to: 12152
/* 12145 */   MCD_OPC_CheckPredicate, 29, 182, 4, // Skip to: 13355
/* 12149 */   MCD_OPC_Decode, 27, 17, // Opcode: ADDQH_R_W
/* 12152 */   MCD_OPC_FilterValue, 19, 8, 0, // Skip to: 12164
/* 12156 */   MCD_OPC_CheckPredicate, 29, 171, 4, // Skip to: 13355
/* 12160 */   MCD_OPC_Decode, 255, 11, 17, // Opcode: SUBQH_R_W
/* 12164 */   MCD_OPC_FilterValue, 22, 8, 0, // Skip to: 12176
/* 12168 */   MCD_OPC_CheckPredicate, 29, 159, 4, // Skip to: 13355
/* 12172 */   MCD_OPC_Decode, 162, 9, 17, // Opcode: MULQ_S_W
/* 12176 */   MCD_OPC_FilterValue, 23, 151, 4, // Skip to: 13355
/* 12180 */   MCD_OPC_CheckPredicate, 29, 147, 4, // Skip to: 13355
/* 12184 */   MCD_OPC_Decode, 160, 9, 17, // Opcode: MULQ_RS_W
/* 12188 */   MCD_OPC_FilterValue, 32, 60, 0, // Skip to: 12252
/* 12192 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 12195 */   MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 12214
/* 12199 */   MCD_OPC_CheckPredicate, 4, 128, 4, // Skip to: 13355
/* 12203 */   MCD_OPC_CheckField, 21, 5, 0, 122, 4, // Skip to: 13355
/* 12209 */   MCD_OPC_Decode, 160, 13, 182, 1, // Opcode: WSBH
/* 12214 */   MCD_OPC_FilterValue, 16, 15, 0, // Skip to: 12233
/* 12218 */   MCD_OPC_CheckPredicate, 4, 109, 4, // Skip to: 13355
/* 12222 */   MCD_OPC_CheckField, 21, 5, 0, 103, 4, // Skip to: 13355
/* 12228 */   MCD_OPC_Decode, 234, 10, 182, 1, // Opcode: SEB
/* 12233 */   MCD_OPC_FilterValue, 24, 94, 4, // Skip to: 13355
/* 12237 */   MCD_OPC_CheckPredicate, 4, 90, 4, // Skip to: 13355
/* 12241 */   MCD_OPC_CheckField, 21, 5, 0, 84, 4, // Skip to: 13355
/* 12247 */   MCD_OPC_Decode, 237, 10, 182, 1, // Opcode: SEH
/* 12252 */   MCD_OPC_FilterValue, 48, 143, 1, // Skip to: 12655
/* 12256 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 12259 */   MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 12277
/* 12263 */   MCD_OPC_CheckPredicate, 29, 64, 4, // Skip to: 13355
/* 12267 */   MCD_OPC_CheckField, 13, 3, 0, 58, 4, // Skip to: 13355
/* 12273 */   MCD_OPC_Decode, 210, 4, 93, // Opcode: DPA_W_PH
/* 12277 */   MCD_OPC_FilterValue, 1, 14, 0, // Skip to: 12295
/* 12281 */   MCD_OPC_CheckPredicate, 29, 46, 4, // Skip to: 13355
/* 12285 */   MCD_OPC_CheckField, 13, 3, 0, 40, 4, // Skip to: 13355
/* 12291 */   MCD_OPC_Decode, 225, 4, 93, // Opcode: DPS_W_PH
/* 12295 */   MCD_OPC_FilterValue, 2, 14, 0, // Skip to: 12313
/* 12299 */   MCD_OPC_CheckPredicate, 29, 28, 4, // Skip to: 13355
/* 12303 */   MCD_OPC_CheckField, 13, 3, 0, 22, 4, // Skip to: 13355
/* 12309 */   MCD_OPC_Decode, 166, 9, 93, // Opcode: MULSA_W_PH
/* 12313 */   MCD_OPC_FilterValue, 3, 14, 0, // Skip to: 12331
/* 12317 */   MCD_OPC_CheckPredicate, 11, 10, 4, // Skip to: 13355
/* 12321 */   MCD_OPC_CheckField, 13, 3, 0, 4, 4, // Skip to: 13355
/* 12327 */   MCD_OPC_Decode, 207, 4, 93, // Opcode: DPAU_H_QBL
/* 12331 */   MCD_OPC_FilterValue, 4, 14, 0, // Skip to: 12349
/* 12335 */   MCD_OPC_CheckPredicate, 11, 248, 3, // Skip to: 13355
/* 12339 */   MCD_OPC_CheckField, 13, 3, 0, 242, 3, // Skip to: 13355
/* 12345 */   MCD_OPC_Decode, 206, 4, 93, // Opcode: DPAQ_S_W_PH
/* 12349 */   MCD_OPC_FilterValue, 5, 14, 0, // Skip to: 12367
/* 12353 */   MCD_OPC_CheckPredicate, 11, 230, 3, // Skip to: 13355
/* 12357 */   MCD_OPC_CheckField, 13, 3, 0, 224, 3, // Skip to: 13355
/* 12363 */   MCD_OPC_Decode, 215, 4, 93, // Opcode: DPSQ_S_W_PH
/* 12367 */   MCD_OPC_FilterValue, 6, 14, 0, // Skip to: 12385
/* 12371 */   MCD_OPC_CheckPredicate, 11, 212, 3, // Skip to: 13355
/* 12375 */   MCD_OPC_CheckField, 13, 3, 0, 206, 3, // Skip to: 13355
/* 12381 */   MCD_OPC_Decode, 165, 9, 93, // Opcode: MULSAQ_S_W_PH
/* 12385 */   MCD_OPC_FilterValue, 7, 14, 0, // Skip to: 12403
/* 12389 */   MCD_OPC_CheckPredicate, 11, 194, 3, // Skip to: 13355
/* 12393 */   MCD_OPC_CheckField, 13, 3, 0, 188, 3, // Skip to: 13355
/* 12399 */   MCD_OPC_Decode, 208, 4, 93, // Opcode: DPAU_H_QBR
/* 12403 */   MCD_OPC_FilterValue, 8, 14, 0, // Skip to: 12421
/* 12407 */   MCD_OPC_CheckPredicate, 29, 176, 3, // Skip to: 13355
/* 12411 */   MCD_OPC_CheckField, 13, 3, 0, 170, 3, // Skip to: 13355
/* 12417 */   MCD_OPC_Decode, 209, 4, 93, // Opcode: DPAX_W_PH
/* 12421 */   MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 12439
/* 12425 */   MCD_OPC_CheckPredicate, 29, 158, 3, // Skip to: 13355
/* 12429 */   MCD_OPC_CheckField, 13, 3, 0, 152, 3, // Skip to: 13355
/* 12435 */   MCD_OPC_Decode, 224, 4, 93, // Opcode: DPSX_W_PH
/* 12439 */   MCD_OPC_FilterValue, 11, 14, 0, // Skip to: 12457
/* 12443 */   MCD_OPC_CheckPredicate, 11, 140, 3, // Skip to: 13355
/* 12447 */   MCD_OPC_CheckField, 13, 3, 0, 134, 3, // Skip to: 13355
/* 12453 */   MCD_OPC_Decode, 222, 4, 93, // Opcode: DPSU_H_QBL
/* 12457 */   MCD_OPC_FilterValue, 12, 14, 0, // Skip to: 12475
/* 12461 */   MCD_OPC_CheckPredicate, 11, 122, 3, // Skip to: 13355
/* 12465 */   MCD_OPC_CheckField, 13, 3, 0, 116, 3, // Skip to: 13355
/* 12471 */   MCD_OPC_Decode, 205, 4, 93, // Opcode: DPAQ_SA_L_W
/* 12475 */   MCD_OPC_FilterValue, 13, 14, 0, // Skip to: 12493
/* 12479 */   MCD_OPC_CheckPredicate, 11, 104, 3, // Skip to: 13355
/* 12483 */   MCD_OPC_CheckField, 13, 3, 0, 98, 3, // Skip to: 13355
/* 12489 */   MCD_OPC_Decode, 214, 4, 93, // Opcode: DPSQ_SA_L_W
/* 12493 */   MCD_OPC_FilterValue, 15, 14, 0, // Skip to: 12511
/* 12497 */   MCD_OPC_CheckPredicate, 11, 86, 3, // Skip to: 13355
/* 12501 */   MCD_OPC_CheckField, 13, 3, 0, 80, 3, // Skip to: 13355
/* 12507 */   MCD_OPC_Decode, 223, 4, 93, // Opcode: DPSU_H_QBR
/* 12511 */   MCD_OPC_FilterValue, 16, 14, 0, // Skip to: 12529
/* 12515 */   MCD_OPC_CheckPredicate, 11, 68, 3, // Skip to: 13355
/* 12519 */   MCD_OPC_CheckField, 13, 3, 0, 62, 3, // Skip to: 13355
/* 12525 */   MCD_OPC_Decode, 241, 7, 93, // Opcode: MAQ_SA_W_PHL
/* 12529 */   MCD_OPC_FilterValue, 18, 14, 0, // Skip to: 12547
/* 12533 */   MCD_OPC_CheckPredicate, 11, 50, 3, // Skip to: 13355
/* 12537 */   MCD_OPC_CheckField, 13, 3, 0, 44, 3, // Skip to: 13355
/* 12543 */   MCD_OPC_Decode, 242, 7, 93, // Opcode: MAQ_SA_W_PHR
/* 12547 */   MCD_OPC_FilterValue, 20, 14, 0, // Skip to: 12565
/* 12551 */   MCD_OPC_CheckPredicate, 11, 32, 3, // Skip to: 13355
/* 12555 */   MCD_OPC_CheckField, 13, 3, 0, 26, 3, // Skip to: 13355
/* 12561 */   MCD_OPC_Decode, 243, 7, 93, // Opcode: MAQ_S_W_PHL
/* 12565 */   MCD_OPC_FilterValue, 22, 14, 0, // Skip to: 12583
/* 12569 */   MCD_OPC_CheckPredicate, 11, 14, 3, // Skip to: 13355
/* 12573 */   MCD_OPC_CheckField, 13, 3, 0, 8, 3, // Skip to: 13355
/* 12579 */   MCD_OPC_Decode, 244, 7, 93, // Opcode: MAQ_S_W_PHR
/* 12583 */   MCD_OPC_FilterValue, 24, 14, 0, // Skip to: 12601
/* 12587 */   MCD_OPC_CheckPredicate, 29, 252, 2, // Skip to: 13355
/* 12591 */   MCD_OPC_CheckField, 13, 3, 0, 246, 2, // Skip to: 13355
/* 12597 */   MCD_OPC_Decode, 204, 4, 93, // Opcode: DPAQX_S_W_PH
/* 12601 */   MCD_OPC_FilterValue, 25, 14, 0, // Skip to: 12619
/* 12605 */   MCD_OPC_CheckPredicate, 29, 234, 2, // Skip to: 13355
/* 12609 */   MCD_OPC_CheckField, 13, 3, 0, 228, 2, // Skip to: 13355
/* 12615 */   MCD_OPC_Decode, 213, 4, 93, // Opcode: DPSQX_S_W_PH
/* 12619 */   MCD_OPC_FilterValue, 26, 14, 0, // Skip to: 12637
/* 12623 */   MCD_OPC_CheckPredicate, 29, 216, 2, // Skip to: 13355
/* 12627 */   MCD_OPC_CheckField, 13, 3, 0, 210, 2, // Skip to: 13355
/* 12633 */   MCD_OPC_Decode, 203, 4, 93, // Opcode: DPAQX_SA_W_PH
/* 12637 */   MCD_OPC_FilterValue, 27, 202, 2, // Skip to: 13355
/* 12641 */   MCD_OPC_CheckPredicate, 29, 198, 2, // Skip to: 13355
/* 12645 */   MCD_OPC_CheckField, 13, 3, 0, 192, 2, // Skip to: 13355
/* 12651 */   MCD_OPC_Decode, 212, 4, 93, // Opcode: DPSQX_SA_W_PH
/* 12655 */   MCD_OPC_FilterValue, 49, 41, 0, // Skip to: 12700
/* 12659 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 12662 */   MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 12674
/* 12666 */   MCD_OPC_CheckPredicate, 29, 173, 2, // Skip to: 13355
/* 12670 */   MCD_OPC_Decode, 86, 186, 1, // Opcode: APPEND
/* 12674 */   MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 12687
/* 12678 */   MCD_OPC_CheckPredicate, 29, 161, 2, // Skip to: 13355
/* 12682 */   MCD_OPC_Decode, 141, 10, 186, 1, // Opcode: PREPEND
/* 12687 */   MCD_OPC_FilterValue, 16, 152, 2, // Skip to: 13355
/* 12691 */   MCD_OPC_CheckPredicate, 29, 148, 2, // Skip to: 13355
/* 12695 */   MCD_OPC_Decode, 158, 1, 186, 1, // Opcode: BALIGN
/* 12700 */   MCD_OPC_FilterValue, 56, 58, 1, // Skip to: 13018
/* 12704 */   MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 12707 */   MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 12726
/* 12711 */   MCD_OPC_CheckPredicate, 11, 128, 2, // Skip to: 13355
/* 12715 */   MCD_OPC_CheckField, 13, 3, 0, 122, 2, // Skip to: 13355
/* 12721 */   MCD_OPC_Decode, 136, 5, 187, 1, // Opcode: EXTR_W
/* 12726 */   MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 12745
/* 12730 */   MCD_OPC_CheckPredicate, 11, 109, 2, // Skip to: 13355
/* 12734 */   MCD_OPC_CheckField, 13, 3, 0, 103, 2, // Skip to: 13355
/* 12740 */   MCD_OPC_Decode, 132, 5, 188, 1, // Opcode: EXTRV_W
/* 12745 */   MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 12764
/* 12749 */   MCD_OPC_CheckPredicate, 11, 90, 2, // Skip to: 13355
/* 12753 */   MCD_OPC_CheckField, 13, 3, 0, 84, 2, // Skip to: 13355
/* 12759 */   MCD_OPC_Decode, 253, 4, 187, 1, // Opcode: EXTP
/* 12764 */   MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 12783
/* 12768 */   MCD_OPC_CheckPredicate, 11, 71, 2, // Skip to: 13355
/* 12772 */   MCD_OPC_CheckField, 13, 3, 0, 65, 2, // Skip to: 13355
/* 12778 */   MCD_OPC_Decode, 128, 5, 188, 1, // Opcode: EXTPV
/* 12783 */   MCD_OPC_FilterValue, 4, 15, 0, // Skip to: 12802
/* 12787 */   MCD_OPC_CheckPredicate, 11, 52, 2, // Skip to: 13355
/* 12791 */   MCD_OPC_CheckField, 13, 3, 0, 46, 2, // Skip to: 13355
/* 12797 */   MCD_OPC_Decode, 134, 5, 187, 1, // Opcode: EXTR_R_W
/* 12802 */   MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 12821
/* 12806 */   MCD_OPC_CheckPredicate, 11, 33, 2, // Skip to: 13355
/* 12810 */   MCD_OPC_CheckField, 13, 3, 0, 27, 2, // Skip to: 13355
/* 12816 */   MCD_OPC_Decode, 130, 5, 188, 1, // Opcode: EXTRV_R_W
/* 12821 */   MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 12840
/* 12825 */   MCD_OPC_CheckPredicate, 11, 14, 2, // Skip to: 13355
/* 12829 */   MCD_OPC_CheckField, 13, 3, 0, 8, 2, // Skip to: 13355
/* 12835 */   MCD_OPC_Decode, 133, 5, 187, 1, // Opcode: EXTR_RS_W
/* 12840 */   MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 12859
/* 12844 */   MCD_OPC_CheckPredicate, 11, 251, 1, // Skip to: 13355
/* 12848 */   MCD_OPC_CheckField, 13, 3, 0, 245, 1, // Skip to: 13355
/* 12854 */   MCD_OPC_Decode, 129, 5, 188, 1, // Opcode: EXTRV_RS_W
/* 12859 */   MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 12878
/* 12863 */   MCD_OPC_CheckPredicate, 11, 232, 1, // Skip to: 13355
/* 12867 */   MCD_OPC_CheckField, 13, 3, 0, 226, 1, // Skip to: 13355
/* 12873 */   MCD_OPC_Decode, 254, 4, 187, 1, // Opcode: EXTPDP
/* 12878 */   MCD_OPC_FilterValue, 11, 15, 0, // Skip to: 12897
/* 12882 */   MCD_OPC_CheckPredicate, 11, 213, 1, // Skip to: 13355
/* 12886 */   MCD_OPC_CheckField, 13, 3, 0, 207, 1, // Skip to: 13355
/* 12892 */   MCD_OPC_Decode, 255, 4, 188, 1, // Opcode: EXTPDPV
/* 12897 */   MCD_OPC_FilterValue, 14, 15, 0, // Skip to: 12916
/* 12901 */   MCD_OPC_CheckPredicate, 11, 194, 1, // Skip to: 13355
/* 12905 */   MCD_OPC_CheckField, 13, 3, 0, 188, 1, // Skip to: 13355
/* 12911 */   MCD_OPC_Decode, 135, 5, 187, 1, // Opcode: EXTR_S_H
/* 12916 */   MCD_OPC_FilterValue, 15, 15, 0, // Skip to: 12935
/* 12920 */   MCD_OPC_CheckPredicate, 11, 175, 1, // Skip to: 13355
/* 12924 */   MCD_OPC_CheckField, 13, 3, 0, 169, 1, // Skip to: 13355
/* 12930 */   MCD_OPC_Decode, 131, 5, 188, 1, // Opcode: EXTRV_S_H
/* 12935 */   MCD_OPC_FilterValue, 18, 9, 0, // Skip to: 12948
/* 12939 */   MCD_OPC_CheckPredicate, 11, 156, 1, // Skip to: 13355
/* 12943 */   MCD_OPC_Decode, 179, 10, 189, 1, // Opcode: RDDSP
/* 12948 */   MCD_OPC_FilterValue, 19, 9, 0, // Skip to: 12961
/* 12952 */   MCD_OPC_CheckPredicate, 11, 143, 1, // Skip to: 13355
/* 12956 */   MCD_OPC_Decode, 159, 13, 190, 1, // Opcode: WRDSP
/* 12961 */   MCD_OPC_FilterValue, 26, 15, 0, // Skip to: 12980
/* 12965 */   MCD_OPC_CheckPredicate, 11, 130, 1, // Skip to: 13355
/* 12969 */   MCD_OPC_CheckField, 13, 7, 0, 124, 1, // Skip to: 13355
/* 12975 */   MCD_OPC_Decode, 129, 11, 191, 1, // Opcode: SHILO
/* 12980 */   MCD_OPC_FilterValue, 27, 15, 0, // Skip to: 12999
/* 12984 */   MCD_OPC_CheckPredicate, 11, 111, 1, // Skip to: 13355
/* 12988 */   MCD_OPC_CheckField, 13, 8, 0, 105, 1, // Skip to: 13355
/* 12994 */   MCD_OPC_Decode, 130, 11, 192, 1, // Opcode: SHILOV
/* 12999 */   MCD_OPC_FilterValue, 31, 96, 1, // Skip to: 13355
/* 13003 */   MCD_OPC_CheckPredicate, 11, 92, 1, // Skip to: 13355
/* 13007 */   MCD_OPC_CheckField, 13, 8, 0, 86, 1, // Skip to: 13355
/* 13013 */   MCD_OPC_Decode, 141, 9, 192, 1, // Opcode: MTHLIP
/* 13018 */   MCD_OPC_FilterValue, 59, 77, 1, // Skip to: 13355
/* 13022 */   MCD_OPC_CheckPredicate, 1, 73, 1, // Skip to: 13355
/* 13026 */   MCD_OPC_CheckField, 21, 5, 0, 67, 1, // Skip to: 13355
/* 13032 */   MCD_OPC_CheckField, 6, 5, 0, 61, 1, // Skip to: 13355
/* 13038 */   MCD_OPC_Decode, 180, 10, 193, 1, // Opcode: RDHWR
/* 13043 */   MCD_OPC_FilterValue, 32, 9, 0, // Skip to: 13056
/* 13047 */   MCD_OPC_CheckPredicate, 1, 48, 1, // Skip to: 13355
/* 13051 */   MCD_OPC_Decode, 254, 6, 194, 1, // Opcode: LB
/* 13056 */   MCD_OPC_FilterValue, 33, 9, 0, // Skip to: 13069
/* 13060 */   MCD_OPC_CheckPredicate, 1, 35, 1, // Skip to: 13355
/* 13064 */   MCD_OPC_Decode, 156, 7, 194, 1, // Opcode: LH
/* 13069 */   MCD_OPC_FilterValue, 34, 9, 0, // Skip to: 13082
/* 13073 */   MCD_OPC_CheckPredicate, 10, 22, 1, // Skip to: 13355
/* 13077 */   MCD_OPC_Decode, 190, 7, 194, 1, // Opcode: LWL
/* 13082 */   MCD_OPC_FilterValue, 35, 9, 0, // Skip to: 13095
/* 13086 */   MCD_OPC_CheckPredicate, 1, 9, 1, // Skip to: 13355
/* 13090 */   MCD_OPC_Decode, 183, 7, 194, 1, // Opcode: LW
/* 13095 */   MCD_OPC_FilterValue, 36, 9, 0, // Skip to: 13108
/* 13099 */   MCD_OPC_CheckPredicate, 1, 252, 0, // Skip to: 13355
/* 13103 */   MCD_OPC_Decode, 130, 7, 194, 1, // Opcode: LBu
/* 13108 */   MCD_OPC_FilterValue, 37, 9, 0, // Skip to: 13121
/* 13112 */   MCD_OPC_CheckPredicate, 1, 239, 0, // Skip to: 13355
/* 13116 */   MCD_OPC_Decode, 160, 7, 194, 1, // Opcode: LHu
/* 13121 */   MCD_OPC_FilterValue, 38, 9, 0, // Skip to: 13134
/* 13125 */   MCD_OPC_CheckPredicate, 10, 226, 0, // Skip to: 13355
/* 13129 */   MCD_OPC_Decode, 194, 7, 194, 1, // Opcode: LWR
/* 13134 */   MCD_OPC_FilterValue, 40, 9, 0, // Skip to: 13147
/* 13138 */   MCD_OPC_CheckPredicate, 1, 213, 0, // Skip to: 13355
/* 13142 */   MCD_OPC_Decode, 211, 10, 194, 1, // Opcode: SB
/* 13147 */   MCD_OPC_FilterValue, 41, 9, 0, // Skip to: 13160
/* 13151 */   MCD_OPC_CheckPredicate, 1, 200, 0, // Skip to: 13355
/* 13155 */   MCD_OPC_Decode, 252, 10, 194, 1, // Opcode: SH
/* 13160 */   MCD_OPC_FilterValue, 42, 9, 0, // Skip to: 13173
/* 13164 */   MCD_OPC_CheckPredicate, 10, 187, 0, // Skip to: 13355
/* 13168 */   MCD_OPC_Decode, 175, 12, 194, 1, // Opcode: SWL
/* 13173 */   MCD_OPC_FilterValue, 43, 9, 0, // Skip to: 13186
/* 13177 */   MCD_OPC_CheckPredicate, 1, 174, 0, // Skip to: 13355
/* 13181 */   MCD_OPC_Decode, 168, 12, 194, 1, // Opcode: SW
/* 13186 */   MCD_OPC_FilterValue, 46, 9, 0, // Skip to: 13199
/* 13190 */   MCD_OPC_CheckPredicate, 10, 161, 0, // Skip to: 13355
/* 13194 */   MCD_OPC_Decode, 178, 12, 194, 1, // Opcode: SWR
/* 13199 */   MCD_OPC_FilterValue, 47, 9, 0, // Skip to: 13212
/* 13203 */   MCD_OPC_CheckPredicate, 30, 148, 0, // Skip to: 13355
/* 13207 */   MCD_OPC_Decode, 201, 2, 195, 1, // Opcode: CACHE
/* 13212 */   MCD_OPC_FilterValue, 48, 9, 0, // Skip to: 13225
/* 13216 */   MCD_OPC_CheckPredicate, 31, 135, 0, // Skip to: 13355
/* 13220 */   MCD_OPC_Decode, 163, 7, 194, 1, // Opcode: LL
/* 13225 */   MCD_OPC_FilterValue, 49, 9, 0, // Skip to: 13238
/* 13229 */   MCD_OPC_CheckPredicate, 1, 122, 0, // Skip to: 13355
/* 13233 */   MCD_OPC_Decode, 185, 7, 196, 1, // Opcode: LWC1
/* 13238 */   MCD_OPC_FilterValue, 50, 9, 0, // Skip to: 13251
/* 13242 */   MCD_OPC_CheckPredicate, 12, 109, 0, // Skip to: 13355
/* 13246 */   MCD_OPC_Decode, 187, 7, 197, 1, // Opcode: LWC2
/* 13251 */   MCD_OPC_FilterValue, 51, 9, 0, // Skip to: 13264
/* 13255 */   MCD_OPC_CheckPredicate, 30, 96, 0, // Skip to: 13355
/* 13259 */   MCD_OPC_Decode, 139, 10, 195, 1, // Opcode: PREF
/* 13264 */   MCD_OPC_FilterValue, 53, 9, 0, // Skip to: 13277
/* 13268 */   MCD_OPC_CheckPredicate, 32, 83, 0, // Skip to: 13355
/* 13272 */   MCD_OPC_Decode, 134, 7, 196, 1, // Opcode: LDC1
/* 13277 */   MCD_OPC_FilterValue, 54, 9, 0, // Skip to: 13290
/* 13281 */   MCD_OPC_CheckPredicate, 14, 70, 0, // Skip to: 13355
/* 13285 */   MCD_OPC_Decode, 137, 7, 197, 1, // Opcode: LDC2
/* 13290 */   MCD_OPC_FilterValue, 56, 9, 0, // Skip to: 13303
/* 13294 */   MCD_OPC_CheckPredicate, 31, 57, 0, // Skip to: 13355
/* 13298 */   MCD_OPC_Decode, 214, 10, 194, 1, // Opcode: SC
/* 13303 */   MCD_OPC_FilterValue, 57, 9, 0, // Skip to: 13316
/* 13307 */   MCD_OPC_CheckPredicate, 1, 44, 0, // Skip to: 13355
/* 13311 */   MCD_OPC_Decode, 170, 12, 196, 1, // Opcode: SWC1
/* 13316 */   MCD_OPC_FilterValue, 58, 9, 0, // Skip to: 13329
/* 13320 */   MCD_OPC_CheckPredicate, 12, 31, 0, // Skip to: 13355
/* 13324 */   MCD_OPC_Decode, 172, 12, 197, 1, // Opcode: SWC2
/* 13329 */   MCD_OPC_FilterValue, 61, 9, 0, // Skip to: 13342
/* 13333 */   MCD_OPC_CheckPredicate, 32, 18, 0, // Skip to: 13355
/* 13337 */   MCD_OPC_Decode, 222, 10, 196, 1, // Opcode: SDC1
/* 13342 */   MCD_OPC_FilterValue, 62, 9, 0, // Skip to: 13355
/* 13346 */   MCD_OPC_CheckPredicate, 14, 5, 0, // Skip to: 13355
/* 13350 */   MCD_OPC_Decode, 225, 10, 197, 1, // Opcode: SDC2
/* 13355 */   MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMips32r6_64r632[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 205, 1, // Skip to: 468
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 29
/* 14 */      MCD_OPC_CheckPredicate, 33, 38, 7, // Skip to: 1848
/* 18 */      MCD_OPC_CheckField, 8, 3, 0, 32, 7, // Skip to: 1848
/* 24 */      MCD_OPC_Decode, 176, 7, 198, 1, // Opcode: LSA_R6
/* 29 */      MCD_OPC_FilterValue, 9, 14, 0, // Skip to: 47
/* 33 */      MCD_OPC_CheckPredicate, 33, 19, 7, // Skip to: 1848
/* 37 */      MCD_OPC_CheckField, 6, 15, 16, 13, 7, // Skip to: 1848
/* 43 */      MCD_OPC_Decode, 245, 6, 39, // Opcode: JR_HB_R6
/* 47 */      MCD_OPC_FilterValue, 14, 8, 0, // Skip to: 59
/* 51 */      MCD_OPC_CheckPredicate, 33, 1, 7, // Skip to: 1848
/* 55 */      MCD_OPC_Decode, 221, 10, 42, // Opcode: SDBBP_R6
/* 59 */      MCD_OPC_FilterValue, 16, 20, 0, // Skip to: 83
/* 63 */      MCD_OPC_CheckPredicate, 33, 245, 6, // Skip to: 1848
/* 67 */      MCD_OPC_CheckField, 16, 5, 0, 239, 6, // Skip to: 1848
/* 73 */      MCD_OPC_CheckField, 6, 5, 1, 233, 6, // Skip to: 1848
/* 79 */      MCD_OPC_Decode, 134, 3, 40, // Opcode: CLZ_R6
/* 83 */      MCD_OPC_FilterValue, 17, 20, 0, // Skip to: 107
/* 87 */      MCD_OPC_CheckPredicate, 33, 221, 6, // Skip to: 1848
/* 91 */      MCD_OPC_CheckField, 16, 5, 0, 215, 6, // Skip to: 1848
/* 97 */      MCD_OPC_CheckField, 6, 5, 1, 209, 6, // Skip to: 1848
/* 103 */     MCD_OPC_Decode, 243, 2, 40, // Opcode: CLO_R6
/* 107 */     MCD_OPC_FilterValue, 18, 21, 0, // Skip to: 132
/* 111 */     MCD_OPC_CheckPredicate, 34, 197, 6, // Skip to: 1848
/* 115 */     MCD_OPC_CheckField, 16, 5, 0, 191, 6, // Skip to: 1848
/* 121 */     MCD_OPC_CheckField, 6, 5, 1, 185, 6, // Skip to: 1848
/* 127 */     MCD_OPC_Decode, 151, 4, 199, 1, // Opcode: DCLZ_R6
/* 132 */     MCD_OPC_FilterValue, 19, 21, 0, // Skip to: 157
/* 136 */     MCD_OPC_CheckPredicate, 34, 172, 6, // Skip to: 1848
/* 140 */     MCD_OPC_CheckField, 16, 5, 0, 166, 6, // Skip to: 1848
/* 146 */     MCD_OPC_CheckField, 6, 5, 1, 160, 6, // Skip to: 1848
/* 152 */     MCD_OPC_Decode, 149, 4, 199, 1, // Opcode: DCLO_R6
/* 157 */     MCD_OPC_FilterValue, 21, 15, 0, // Skip to: 176
/* 161 */     MCD_OPC_CheckPredicate, 34, 147, 6, // Skip to: 1848
/* 165 */     MCD_OPC_CheckField, 8, 3, 0, 141, 6, // Skip to: 1848
/* 171 */     MCD_OPC_Decode, 175, 4, 200, 1, // Opcode: DLSA_R6
/* 176 */     MCD_OPC_FilterValue, 24, 27, 0, // Skip to: 207
/* 180 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 183 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 195
/* 187 */     MCD_OPC_CheckPredicate, 33, 121, 6, // Skip to: 1848
/* 191 */     MCD_OPC_Decode, 182, 9, 17, // Opcode: MUL_R6
/* 195 */     MCD_OPC_FilterValue, 3, 113, 6, // Skip to: 1848
/* 199 */     MCD_OPC_CheckPredicate, 33, 109, 6, // Skip to: 1848
/* 203 */     MCD_OPC_Decode, 152, 9, 17, // Opcode: MUH
/* 207 */     MCD_OPC_FilterValue, 25, 27, 0, // Skip to: 238
/* 211 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 214 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 226
/* 218 */     MCD_OPC_CheckPredicate, 33, 90, 6, // Skip to: 1848
/* 222 */     MCD_OPC_Decode, 173, 9, 17, // Opcode: MULU
/* 226 */     MCD_OPC_FilterValue, 3, 82, 6, // Skip to: 1848
/* 230 */     MCD_OPC_CheckPredicate, 33, 78, 6, // Skip to: 1848
/* 234 */     MCD_OPC_Decode, 153, 9, 17, // Opcode: MUHU
/* 238 */     MCD_OPC_FilterValue, 26, 27, 0, // Skip to: 269
/* 242 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 245 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 257
/* 249 */     MCD_OPC_CheckPredicate, 33, 59, 6, // Skip to: 1848
/* 253 */     MCD_OPC_Decode, 163, 4, 17, // Opcode: DIV
/* 257 */     MCD_OPC_FilterValue, 3, 51, 6, // Skip to: 1848
/* 261 */     MCD_OPC_CheckPredicate, 33, 47, 6, // Skip to: 1848
/* 265 */     MCD_OPC_Decode, 184, 8, 17, // Opcode: MOD
/* 269 */     MCD_OPC_FilterValue, 27, 27, 0, // Skip to: 300
/* 273 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 276 */     MCD_OPC_FilterValue, 2, 8, 0, // Skip to: 288
/* 280 */     MCD_OPC_CheckPredicate, 33, 28, 6, // Skip to: 1848
/* 284 */     MCD_OPC_Decode, 164, 4, 17, // Opcode: DIVU
/* 288 */     MCD_OPC_FilterValue, 3, 20, 6, // Skip to: 1848
/* 292 */     MCD_OPC_CheckPredicate, 33, 16, 6, // Skip to: 1848
/* 296 */     MCD_OPC_Decode, 186, 8, 17, // Opcode: MODU
/* 300 */     MCD_OPC_FilterValue, 28, 29, 0, // Skip to: 333
/* 304 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 307 */     MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 320
/* 311 */     MCD_OPC_CheckPredicate, 34, 253, 5, // Skip to: 1848
/* 315 */     MCD_OPC_Decode, 190, 4, 201, 1, // Opcode: DMUL_R6
/* 320 */     MCD_OPC_FilterValue, 3, 244, 5, // Skip to: 1848
/* 324 */     MCD_OPC_CheckPredicate, 34, 240, 5, // Skip to: 1848
/* 328 */     MCD_OPC_Decode, 184, 4, 201, 1, // Opcode: DMUH
/* 333 */     MCD_OPC_FilterValue, 29, 29, 0, // Skip to: 366
/* 337 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 340 */     MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 353
/* 344 */     MCD_OPC_CheckPredicate, 34, 220, 5, // Skip to: 1848
/* 348 */     MCD_OPC_Decode, 189, 4, 201, 1, // Opcode: DMULU
/* 353 */     MCD_OPC_FilterValue, 3, 211, 5, // Skip to: 1848
/* 357 */     MCD_OPC_CheckPredicate, 34, 207, 5, // Skip to: 1848
/* 361 */     MCD_OPC_Decode, 185, 4, 201, 1, // Opcode: DMUHU
/* 366 */     MCD_OPC_FilterValue, 30, 29, 0, // Skip to: 399
/* 370 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 373 */     MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 386
/* 377 */     MCD_OPC_CheckPredicate, 34, 187, 5, // Skip to: 1848
/* 381 */     MCD_OPC_Decode, 152, 4, 201, 1, // Opcode: DDIV
/* 386 */     MCD_OPC_FilterValue, 3, 178, 5, // Skip to: 1848
/* 390 */     MCD_OPC_CheckPredicate, 34, 174, 5, // Skip to: 1848
/* 394 */     MCD_OPC_Decode, 179, 4, 201, 1, // Opcode: DMOD
/* 399 */     MCD_OPC_FilterValue, 31, 29, 0, // Skip to: 432
/* 403 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 406 */     MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 419
/* 410 */     MCD_OPC_CheckPredicate, 34, 154, 5, // Skip to: 1848
/* 414 */     MCD_OPC_Decode, 153, 4, 201, 1, // Opcode: DDIVU
/* 419 */     MCD_OPC_FilterValue, 3, 145, 5, // Skip to: 1848
/* 423 */     MCD_OPC_CheckPredicate, 34, 141, 5, // Skip to: 1848
/* 427 */     MCD_OPC_Decode, 180, 4, 201, 1, // Opcode: DMODU
/* 432 */     MCD_OPC_FilterValue, 53, 14, 0, // Skip to: 450
/* 436 */     MCD_OPC_CheckPredicate, 35, 128, 5, // Skip to: 1848
/* 440 */     MCD_OPC_CheckField, 6, 5, 0, 122, 5, // Skip to: 1848
/* 446 */     MCD_OPC_Decode, 240, 10, 17, // Opcode: SELEQZ
/* 450 */     MCD_OPC_FilterValue, 55, 114, 5, // Skip to: 1848
/* 454 */     MCD_OPC_CheckPredicate, 35, 110, 5, // Skip to: 1848
/* 458 */     MCD_OPC_CheckField, 6, 5, 0, 104, 5, // Skip to: 1848
/* 464 */     MCD_OPC_Decode, 244, 10, 17, // Opcode: SELNEZ
/* 468 */     MCD_OPC_FilterValue, 1, 47, 0, // Skip to: 519
/* 472 */     MCD_OPC_ExtractField, 16, 5,  // Inst{20-16} ...
/* 475 */     MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 488
/* 479 */     MCD_OPC_CheckPredicate, 34, 85, 5, // Skip to: 1848
/* 483 */     MCD_OPC_Decode, 143, 4, 202, 1, // Opcode: DAHI
/* 488 */     MCD_OPC_FilterValue, 17, 14, 0, // Skip to: 506
/* 492 */     MCD_OPC_CheckPredicate, 33, 72, 5, // Skip to: 1848
/* 496 */     MCD_OPC_CheckField, 21, 5, 0, 66, 5, // Skip to: 1848
/* 502 */     MCD_OPC_Decode, 156, 1, 53, // Opcode: BAL
/* 506 */     MCD_OPC_FilterValue, 30, 58, 5, // Skip to: 1848
/* 510 */     MCD_OPC_CheckPredicate, 34, 54, 5, // Skip to: 1848
/* 514 */     MCD_OPC_Decode, 145, 4, 202, 1, // Opcode: DATI
/* 519 */     MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 532
/* 523 */     MCD_OPC_CheckPredicate, 33, 41, 5, // Skip to: 1848
/* 527 */     MCD_OPC_Decode, 204, 1, 203, 1, // Opcode: BGEZALC
/* 532 */     MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 545
/* 536 */     MCD_OPC_CheckPredicate, 33, 28, 5, // Skip to: 1848
/* 540 */     MCD_OPC_Decode, 246, 1, 204, 1, // Opcode: BLTZALC
/* 545 */     MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 558
/* 549 */     MCD_OPC_CheckPredicate, 33, 15, 5, // Skip to: 1848
/* 553 */     MCD_OPC_Decode, 193, 1, 205, 1, // Opcode: BEQC
/* 558 */     MCD_OPC_FilterValue, 15, 7, 0, // Skip to: 569
/* 562 */     MCD_OPC_CheckPredicate, 33, 2, 5, // Skip to: 1848
/* 566 */     MCD_OPC_Decode, 127, 27, // Opcode: AUI
/* 569 */     MCD_OPC_FilterValue, 17, 5, 3, // Skip to: 1346
/* 573 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 576 */     MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 589
/* 580 */     MCD_OPC_CheckPredicate, 33, 240, 4, // Skip to: 1848
/* 584 */     MCD_OPC_Decode, 165, 1, 206, 1, // Opcode: BC1EQZ
/* 589 */     MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 602
/* 593 */     MCD_OPC_CheckPredicate, 33, 227, 4, // Skip to: 1848
/* 597 */     MCD_OPC_Decode, 169, 1, 206, 1, // Opcode: BC1NEZ
/* 602 */     MCD_OPC_FilterValue, 16, 150, 0, // Skip to: 756
/* 606 */     MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 609 */     MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 622
/* 613 */     MCD_OPC_CheckPredicate, 33, 207, 4, // Skip to: 1848
/* 617 */     MCD_OPC_Decode, 249, 10, 207, 1, // Opcode: SEL_S
/* 622 */     MCD_OPC_FilterValue, 20, 8, 0, // Skip to: 634
/* 626 */     MCD_OPC_CheckPredicate, 33, 194, 4, // Skip to: 1848
/* 630 */     MCD_OPC_Decode, 243, 10, 70, // Opcode: SELEQZ_S
/* 634 */     MCD_OPC_FilterValue, 23, 8, 0, // Skip to: 646
/* 638 */     MCD_OPC_CheckPredicate, 33, 182, 4, // Skip to: 1848
/* 642 */     MCD_OPC_Decode, 247, 10, 70, // Opcode: SELNEZ_S
/* 646 */     MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 659
/* 650 */     MCD_OPC_CheckPredicate, 33, 170, 4, // Skip to: 1848
/* 654 */     MCD_OPC_Decode, 222, 7, 208, 1, // Opcode: MADDF_S
/* 659 */     MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 672
/* 663 */     MCD_OPC_CheckPredicate, 33, 157, 4, // Skip to: 1848
/* 667 */     MCD_OPC_Decode, 239, 8, 208, 1, // Opcode: MSUBF_S
/* 672 */     MCD_OPC_FilterValue, 26, 14, 0, // Skip to: 690
/* 676 */     MCD_OPC_CheckPredicate, 33, 144, 4, // Skip to: 1848
/* 680 */     MCD_OPC_CheckField, 16, 5, 0, 138, 4, // Skip to: 1848
/* 686 */     MCD_OPC_Decode, 187, 10, 71, // Opcode: RINT_S
/* 690 */     MCD_OPC_FilterValue, 27, 14, 0, // Skip to: 708
/* 694 */     MCD_OPC_CheckPredicate, 33, 126, 4, // Skip to: 1848
/* 698 */     MCD_OPC_CheckField, 16, 5, 0, 120, 4, // Skip to: 1848
/* 704 */     MCD_OPC_Decode, 224, 2, 71, // Opcode: CLASS_S
/* 708 */     MCD_OPC_FilterValue, 28, 8, 0, // Skip to: 720
/* 712 */     MCD_OPC_CheckPredicate, 33, 108, 4, // Skip to: 1848
/* 716 */     MCD_OPC_Decode, 173, 8, 70, // Opcode: MIN_S
/* 720 */     MCD_OPC_FilterValue, 29, 8, 0, // Skip to: 732
/* 724 */     MCD_OPC_CheckPredicate, 33, 96, 4, // Skip to: 1848
/* 728 */     MCD_OPC_Decode, 132, 8, 70, // Opcode: MAX_S
/* 732 */     MCD_OPC_FilterValue, 30, 8, 0, // Skip to: 744
/* 736 */     MCD_OPC_CheckPredicate, 33, 84, 4, // Skip to: 1848
/* 740 */     MCD_OPC_Decode, 159, 8, 70, // Opcode: MINA_S
/* 744 */     MCD_OPC_FilterValue, 31, 76, 4, // Skip to: 1848
/* 748 */     MCD_OPC_CheckPredicate, 33, 72, 4, // Skip to: 1848
/* 752 */     MCD_OPC_Decode, 246, 7, 70, // Opcode: MAXA_S
/* 756 */     MCD_OPC_FilterValue, 17, 156, 0, // Skip to: 916
/* 760 */     MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 763 */     MCD_OPC_FilterValue, 16, 9, 0, // Skip to: 776
/* 767 */     MCD_OPC_CheckPredicate, 33, 53, 4, // Skip to: 1848
/* 771 */     MCD_OPC_Decode, 248, 10, 209, 1, // Opcode: SEL_D
/* 776 */     MCD_OPC_FilterValue, 20, 9, 0, // Skip to: 789
/* 780 */     MCD_OPC_CheckPredicate, 33, 40, 4, // Skip to: 1848
/* 784 */     MCD_OPC_Decode, 242, 10, 210, 1, // Opcode: SELEQZ_D
/* 789 */     MCD_OPC_FilterValue, 23, 9, 0, // Skip to: 802
/* 793 */     MCD_OPC_CheckPredicate, 33, 27, 4, // Skip to: 1848
/* 797 */     MCD_OPC_Decode, 246, 10, 210, 1, // Opcode: SELNEZ_D
/* 802 */     MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 815
/* 806 */     MCD_OPC_CheckPredicate, 33, 14, 4, // Skip to: 1848
/* 810 */     MCD_OPC_Decode, 221, 7, 211, 1, // Opcode: MADDF_D
/* 815 */     MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 828
/* 819 */     MCD_OPC_CheckPredicate, 33, 1, 4, // Skip to: 1848
/* 823 */     MCD_OPC_Decode, 238, 8, 211, 1, // Opcode: MSUBF_D
/* 828 */     MCD_OPC_FilterValue, 26, 14, 0, // Skip to: 846
/* 832 */     MCD_OPC_CheckPredicate, 33, 244, 3, // Skip to: 1848
/* 836 */     MCD_OPC_CheckField, 16, 5, 0, 238, 3, // Skip to: 1848
/* 842 */     MCD_OPC_Decode, 186, 10, 82, // Opcode: RINT_D
/* 846 */     MCD_OPC_FilterValue, 27, 14, 0, // Skip to: 864
/* 850 */     MCD_OPC_CheckPredicate, 33, 226, 3, // Skip to: 1848
/* 854 */     MCD_OPC_CheckField, 16, 5, 0, 220, 3, // Skip to: 1848
/* 860 */     MCD_OPC_Decode, 223, 2, 82, // Opcode: CLASS_D
/* 864 */     MCD_OPC_FilterValue, 28, 9, 0, // Skip to: 877
/* 868 */     MCD_OPC_CheckPredicate, 33, 208, 3, // Skip to: 1848
/* 872 */     MCD_OPC_Decode, 172, 8, 210, 1, // Opcode: MIN_D
/* 877 */     MCD_OPC_FilterValue, 29, 9, 0, // Skip to: 890
/* 881 */     MCD_OPC_CheckPredicate, 33, 195, 3, // Skip to: 1848
/* 885 */     MCD_OPC_Decode, 131, 8, 210, 1, // Opcode: MAX_D
/* 890 */     MCD_OPC_FilterValue, 30, 9, 0, // Skip to: 903
/* 894 */     MCD_OPC_CheckPredicate, 33, 182, 3, // Skip to: 1848
/* 898 */     MCD_OPC_Decode, 158, 8, 210, 1, // Opcode: MINA_D
/* 903 */     MCD_OPC_FilterValue, 31, 173, 3, // Skip to: 1848
/* 907 */     MCD_OPC_CheckPredicate, 33, 169, 3, // Skip to: 1848
/* 911 */     MCD_OPC_Decode, 245, 7, 210, 1, // Opcode: MAXA_D
/* 916 */     MCD_OPC_FilterValue, 20, 211, 0, // Skip to: 1131
/* 920 */     MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 923 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 936
/* 927 */     MCD_OPC_CheckPredicate, 33, 149, 3, // Skip to: 1848
/* 931 */     MCD_OPC_Decode, 148, 3, 212, 1, // Opcode: CMP_F_S
/* 936 */     MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 949
/* 940 */     MCD_OPC_CheckPredicate, 33, 136, 3, // Skip to: 1848
/* 944 */     MCD_OPC_Decode, 178, 3, 212, 1, // Opcode: CMP_UN_S
/* 949 */     MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 962
/* 953 */     MCD_OPC_CheckPredicate, 33, 123, 3, // Skip to: 1848
/* 957 */     MCD_OPC_Decode, 146, 3, 212, 1, // Opcode: CMP_EQ_S
/* 962 */     MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 975
/* 966 */     MCD_OPC_CheckPredicate, 33, 110, 3, // Skip to: 1848
/* 970 */     MCD_OPC_Decode, 172, 3, 212, 1, // Opcode: CMP_UEQ_S
/* 975 */     MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 988
/* 979 */     MCD_OPC_CheckPredicate, 33, 97, 3, // Skip to: 1848
/* 983 */     MCD_OPC_Decode, 154, 3, 212, 1, // Opcode: CMP_LT_S
/* 988 */     MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 1001
/* 992 */     MCD_OPC_CheckPredicate, 33, 84, 3, // Skip to: 1848
/* 996 */     MCD_OPC_Decode, 176, 3, 212, 1, // Opcode: CMP_ULT_S
/* 1001 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 1014
/* 1005 */    MCD_OPC_CheckPredicate, 33, 71, 3, // Skip to: 1848
/* 1009 */    MCD_OPC_Decode, 151, 3, 212, 1, // Opcode: CMP_LE_S
/* 1014 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 1027
/* 1018 */    MCD_OPC_CheckPredicate, 33, 58, 3, // Skip to: 1848
/* 1022 */    MCD_OPC_Decode, 174, 3, 212, 1, // Opcode: CMP_ULE_S
/* 1027 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 1040
/* 1031 */    MCD_OPC_CheckPredicate, 33, 45, 3, // Skip to: 1848
/* 1035 */    MCD_OPC_Decode, 156, 3, 212, 1, // Opcode: CMP_SAF_S
/* 1040 */    MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 1053
/* 1044 */    MCD_OPC_CheckPredicate, 33, 32, 3, // Skip to: 1848
/* 1048 */    MCD_OPC_Decode, 170, 3, 212, 1, // Opcode: CMP_SUN_S
/* 1053 */    MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 1066
/* 1057 */    MCD_OPC_CheckPredicate, 33, 19, 3, // Skip to: 1848
/* 1061 */    MCD_OPC_Decode, 158, 3, 212, 1, // Opcode: CMP_SEQ_S
/* 1066 */    MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 1079
/* 1070 */    MCD_OPC_CheckPredicate, 33, 6, 3, // Skip to: 1848
/* 1074 */    MCD_OPC_Decode, 164, 3, 212, 1, // Opcode: CMP_SUEQ_S
/* 1079 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 1092
/* 1083 */    MCD_OPC_CheckPredicate, 33, 249, 2, // Skip to: 1848
/* 1087 */    MCD_OPC_Decode, 162, 3, 212, 1, // Opcode: CMP_SLT_S
/* 1092 */    MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 1105
/* 1096 */    MCD_OPC_CheckPredicate, 33, 236, 2, // Skip to: 1848
/* 1100 */    MCD_OPC_Decode, 168, 3, 212, 1, // Opcode: CMP_SULT_S
/* 1105 */    MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 1118
/* 1109 */    MCD_OPC_CheckPredicate, 33, 223, 2, // Skip to: 1848
/* 1113 */    MCD_OPC_Decode, 160, 3, 212, 1, // Opcode: CMP_SLE_S
/* 1118 */    MCD_OPC_FilterValue, 15, 214, 2, // Skip to: 1848
/* 1122 */    MCD_OPC_CheckPredicate, 33, 210, 2, // Skip to: 1848
/* 1126 */    MCD_OPC_Decode, 166, 3, 212, 1, // Opcode: CMP_SULE_S
/* 1131 */    MCD_OPC_FilterValue, 21, 201, 2, // Skip to: 1848
/* 1135 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1138 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 1151
/* 1142 */    MCD_OPC_CheckPredicate, 33, 190, 2, // Skip to: 1848
/* 1146 */    MCD_OPC_Decode, 147, 3, 213, 1, // Opcode: CMP_F_D
/* 1151 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 1164
/* 1155 */    MCD_OPC_CheckPredicate, 33, 177, 2, // Skip to: 1848
/* 1159 */    MCD_OPC_Decode, 177, 3, 213, 1, // Opcode: CMP_UN_D
/* 1164 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 1177
/* 1168 */    MCD_OPC_CheckPredicate, 33, 164, 2, // Skip to: 1848
/* 1172 */    MCD_OPC_Decode, 144, 3, 213, 1, // Opcode: CMP_EQ_D
/* 1177 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 1190
/* 1181 */    MCD_OPC_CheckPredicate, 33, 151, 2, // Skip to: 1848
/* 1185 */    MCD_OPC_Decode, 171, 3, 213, 1, // Opcode: CMP_UEQ_D
/* 1190 */    MCD_OPC_FilterValue, 4, 9, 0, // Skip to: 1203
/* 1194 */    MCD_OPC_CheckPredicate, 33, 138, 2, // Skip to: 1848
/* 1198 */    MCD_OPC_Decode, 152, 3, 213, 1, // Opcode: CMP_LT_D
/* 1203 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 1216
/* 1207 */    MCD_OPC_CheckPredicate, 33, 125, 2, // Skip to: 1848
/* 1211 */    MCD_OPC_Decode, 175, 3, 213, 1, // Opcode: CMP_ULT_D
/* 1216 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 1229
/* 1220 */    MCD_OPC_CheckPredicate, 33, 112, 2, // Skip to: 1848
/* 1224 */    MCD_OPC_Decode, 149, 3, 213, 1, // Opcode: CMP_LE_D
/* 1229 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 1242
/* 1233 */    MCD_OPC_CheckPredicate, 33, 99, 2, // Skip to: 1848
/* 1237 */    MCD_OPC_Decode, 173, 3, 213, 1, // Opcode: CMP_ULE_D
/* 1242 */    MCD_OPC_FilterValue, 8, 9, 0, // Skip to: 1255
/* 1246 */    MCD_OPC_CheckPredicate, 33, 86, 2, // Skip to: 1848
/* 1250 */    MCD_OPC_Decode, 155, 3, 213, 1, // Opcode: CMP_SAF_D
/* 1255 */    MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 1268
/* 1259 */    MCD_OPC_CheckPredicate, 33, 73, 2, // Skip to: 1848
/* 1263 */    MCD_OPC_Decode, 169, 3, 213, 1, // Opcode: CMP_SUN_D
/* 1268 */    MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 1281
/* 1272 */    MCD_OPC_CheckPredicate, 33, 60, 2, // Skip to: 1848
/* 1276 */    MCD_OPC_Decode, 157, 3, 213, 1, // Opcode: CMP_SEQ_D
/* 1281 */    MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 1294
/* 1285 */    MCD_OPC_CheckPredicate, 33, 47, 2, // Skip to: 1848
/* 1289 */    MCD_OPC_Decode, 163, 3, 213, 1, // Opcode: CMP_SUEQ_D
/* 1294 */    MCD_OPC_FilterValue, 12, 9, 0, // Skip to: 1307
/* 1298 */    MCD_OPC_CheckPredicate, 33, 34, 2, // Skip to: 1848
/* 1302 */    MCD_OPC_Decode, 161, 3, 213, 1, // Opcode: CMP_SLT_D
/* 1307 */    MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 1320
/* 1311 */    MCD_OPC_CheckPredicate, 33, 21, 2, // Skip to: 1848
/* 1315 */    MCD_OPC_Decode, 167, 3, 213, 1, // Opcode: CMP_SULT_D
/* 1320 */    MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 1333
/* 1324 */    MCD_OPC_CheckPredicate, 33, 8, 2, // Skip to: 1848
/* 1328 */    MCD_OPC_Decode, 159, 3, 213, 1, // Opcode: CMP_SLE_D
/* 1333 */    MCD_OPC_FilterValue, 15, 255, 1, // Skip to: 1848
/* 1337 */    MCD_OPC_CheckPredicate, 33, 251, 1, // Skip to: 1848
/* 1341 */    MCD_OPC_Decode, 165, 3, 213, 1, // Opcode: CMP_SULE_D
/* 1346 */    MCD_OPC_FilterValue, 18, 81, 0, // Skip to: 1431
/* 1350 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1353 */    MCD_OPC_FilterValue, 9, 9, 0, // Skip to: 1366
/* 1357 */    MCD_OPC_CheckPredicate, 33, 231, 1, // Skip to: 1848
/* 1361 */    MCD_OPC_Decode, 173, 1, 214, 1, // Opcode: BC2EQZ
/* 1366 */    MCD_OPC_FilterValue, 10, 9, 0, // Skip to: 1379
/* 1370 */    MCD_OPC_CheckPredicate, 33, 218, 1, // Skip to: 1848
/* 1374 */    MCD_OPC_Decode, 188, 7, 215, 1, // Opcode: LWC2_R6
/* 1379 */    MCD_OPC_FilterValue, 11, 9, 0, // Skip to: 1392
/* 1383 */    MCD_OPC_CheckPredicate, 33, 205, 1, // Skip to: 1848
/* 1387 */    MCD_OPC_Decode, 173, 12, 215, 1, // Opcode: SWC2_R6
/* 1392 */    MCD_OPC_FilterValue, 13, 9, 0, // Skip to: 1405
/* 1396 */    MCD_OPC_CheckPredicate, 33, 192, 1, // Skip to: 1848
/* 1400 */    MCD_OPC_Decode, 176, 1, 214, 1, // Opcode: BC2NEZ
/* 1405 */    MCD_OPC_FilterValue, 14, 9, 0, // Skip to: 1418
/* 1409 */    MCD_OPC_CheckPredicate, 33, 179, 1, // Skip to: 1848
/* 1413 */    MCD_OPC_Decode, 138, 7, 215, 1, // Opcode: LDC2_R6
/* 1418 */    MCD_OPC_FilterValue, 15, 170, 1, // Skip to: 1848
/* 1422 */    MCD_OPC_CheckPredicate, 33, 166, 1, // Skip to: 1848
/* 1426 */    MCD_OPC_Decode, 226, 10, 215, 1, // Opcode: SDC2_R6
/* 1431 */    MCD_OPC_FilterValue, 22, 9, 0, // Skip to: 1444
/* 1435 */    MCD_OPC_CheckPredicate, 33, 153, 1, // Skip to: 1848
/* 1439 */    MCD_OPC_Decode, 208, 1, 216, 1, // Opcode: BGEZC
/* 1444 */    MCD_OPC_FilterValue, 23, 9, 0, // Skip to: 1457
/* 1448 */    MCD_OPC_CheckPredicate, 33, 140, 1, // Skip to: 1848
/* 1452 */    MCD_OPC_Decode, 250, 1, 217, 1, // Opcode: BLTZC
/* 1457 */    MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 1470
/* 1461 */    MCD_OPC_CheckPredicate, 33, 127, 1, // Skip to: 1848
/* 1465 */    MCD_OPC_Decode, 131, 2, 218, 1, // Opcode: BNEC
/* 1470 */    MCD_OPC_FilterValue, 29, 9, 0, // Skip to: 1483
/* 1474 */    MCD_OPC_CheckPredicate, 34, 114, 1, // Skip to: 1848
/* 1478 */    MCD_OPC_Decode, 146, 4, 219, 1, // Opcode: DAUI
/* 1483 */    MCD_OPC_FilterValue, 31, 182, 0, // Skip to: 1669
/* 1487 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1490 */    MCD_OPC_FilterValue, 32, 40, 0, // Skip to: 1534
/* 1494 */    MCD_OPC_ExtractField, 8, 3,  // Inst{10-8} ...
/* 1497 */    MCD_OPC_FilterValue, 0, 21, 0, // Skip to: 1522
/* 1501 */    MCD_OPC_CheckPredicate, 33, 87, 1, // Skip to: 1848
/* 1505 */    MCD_OPC_CheckField, 21, 5, 0, 81, 1, // Skip to: 1848
/* 1511 */    MCD_OPC_CheckField, 6, 2, 0, 75, 1, // Skip to: 1848
/* 1517 */    MCD_OPC_Decode, 234, 1, 182, 1, // Opcode: BITSWAP
/* 1522 */    MCD_OPC_FilterValue, 2, 66, 1, // Skip to: 1848
/* 1526 */    MCD_OPC_CheckPredicate, 33, 62, 1, // Skip to: 1848
/* 1530 */    MCD_OPC_Decode, 73, 198, 1, // Opcode: ALIGN
/* 1534 */    MCD_OPC_FilterValue, 36, 41, 0, // Skip to: 1579
/* 1538 */    MCD_OPC_ExtractField, 9, 2,  // Inst{10-9} ...
/* 1541 */    MCD_OPC_FilterValue, 0, 21, 0, // Skip to: 1566
/* 1545 */    MCD_OPC_CheckPredicate, 34, 43, 1, // Skip to: 1848
/* 1549 */    MCD_OPC_CheckField, 21, 5, 0, 37, 1, // Skip to: 1848
/* 1555 */    MCD_OPC_CheckField, 6, 3, 0, 31, 1, // Skip to: 1848
/* 1561 */    MCD_OPC_Decode, 147, 4, 220, 1, // Opcode: DBITSWAP
/* 1566 */    MCD_OPC_FilterValue, 1, 22, 1, // Skip to: 1848
/* 1570 */    MCD_OPC_CheckPredicate, 34, 18, 1, // Skip to: 1848
/* 1574 */    MCD_OPC_Decode, 144, 4, 221, 1, // Opcode: DALIGN
/* 1579 */    MCD_OPC_FilterValue, 37, 15, 0, // Skip to: 1598
/* 1583 */    MCD_OPC_CheckPredicate, 33, 5, 1, // Skip to: 1848
/* 1587 */    MCD_OPC_CheckField, 6, 1, 0, 255, 0, // Skip to: 1848
/* 1593 */    MCD_OPC_Decode, 202, 2, 222, 1, // Opcode: CACHE_R6
/* 1598 */    MCD_OPC_FilterValue, 38, 9, 0, // Skip to: 1611
/* 1602 */    MCD_OPC_CheckPredicate, 33, 242, 0, // Skip to: 1848
/* 1606 */    MCD_OPC_Decode, 218, 10, 223, 1, // Opcode: SC_R6
/* 1611 */    MCD_OPC_FilterValue, 39, 9, 0, // Skip to: 1624
/* 1615 */    MCD_OPC_CheckPredicate, 33, 229, 0, // Skip to: 1848
/* 1619 */    MCD_OPC_Decode, 216, 10, 223, 1, // Opcode: SCD_R6
/* 1624 */    MCD_OPC_FilterValue, 53, 15, 0, // Skip to: 1643
/* 1628 */    MCD_OPC_CheckPredicate, 33, 216, 0, // Skip to: 1848
/* 1632 */    MCD_OPC_CheckField, 6, 1, 0, 210, 0, // Skip to: 1848
/* 1638 */    MCD_OPC_Decode, 140, 10, 222, 1, // Opcode: PREF_R6
/* 1643 */    MCD_OPC_FilterValue, 54, 9, 0, // Skip to: 1656
/* 1647 */    MCD_OPC_CheckPredicate, 33, 197, 0, // Skip to: 1848
/* 1651 */    MCD_OPC_Decode, 167, 7, 223, 1, // Opcode: LL_R6
/* 1656 */    MCD_OPC_FilterValue, 55, 188, 0, // Skip to: 1848
/* 1660 */    MCD_OPC_CheckPredicate, 33, 184, 0, // Skip to: 1848
/* 1664 */    MCD_OPC_Decode, 165, 7, 223, 1, // Opcode: LLD_R6
/* 1669 */    MCD_OPC_FilterValue, 50, 9, 0, // Skip to: 1682
/* 1673 */    MCD_OPC_CheckPredicate, 33, 171, 0, // Skip to: 1848
/* 1677 */    MCD_OPC_Decode, 160, 1, 224, 1, // Opcode: BC
/* 1682 */    MCD_OPC_FilterValue, 54, 24, 0, // Skip to: 1710
/* 1686 */    MCD_OPC_CheckPredicate, 33, 11, 0, // Skip to: 1701
/* 1690 */    MCD_OPC_CheckField, 21, 5, 0, 5, 0, // Skip to: 1701
/* 1696 */    MCD_OPC_Decode, 240, 6, 225, 1, // Opcode: JIC
/* 1701 */    MCD_OPC_CheckPredicate, 33, 143, 0, // Skip to: 1848
/* 1705 */    MCD_OPC_Decode, 196, 1, 226, 1, // Opcode: BEQZC
/* 1710 */    MCD_OPC_FilterValue, 58, 9, 0, // Skip to: 1723
/* 1714 */    MCD_OPC_CheckPredicate, 33, 130, 0, // Skip to: 1848
/* 1718 */    MCD_OPC_Decode, 157, 1, 224, 1, // Opcode: BALC
/* 1723 */    MCD_OPC_FilterValue, 59, 93, 0, // Skip to: 1820
/* 1727 */    MCD_OPC_ExtractField, 19, 2,  // Inst{20-19} ...
/* 1730 */    MCD_OPC_FilterValue, 0, 8, 0, // Skip to: 1742
/* 1734 */    MCD_OPC_CheckPredicate, 33, 110, 0, // Skip to: 1848
/* 1738 */    MCD_OPC_Decode, 24, 227, 1, // Opcode: ADDIUPC
/* 1742 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 1755
/* 1746 */    MCD_OPC_CheckPredicate, 33, 98, 0, // Skip to: 1848
/* 1750 */    MCD_OPC_Decode, 193, 7, 227, 1, // Opcode: LWPC
/* 1755 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 1768
/* 1759 */    MCD_OPC_CheckPredicate, 33, 85, 0, // Skip to: 1848
/* 1763 */    MCD_OPC_Decode, 197, 7, 227, 1, // Opcode: LWUPC
/* 1768 */    MCD_OPC_FilterValue, 3, 76, 0, // Skip to: 1848
/* 1772 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 1775 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 1788
/* 1779 */    MCD_OPC_CheckPredicate, 34, 65, 0, // Skip to: 1848
/* 1783 */    MCD_OPC_Decode, 145, 7, 228, 1, // Opcode: LDPC
/* 1788 */    MCD_OPC_FilterValue, 1, 56, 0, // Skip to: 1848
/* 1792 */    MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 1795 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 1808
/* 1799 */    MCD_OPC_CheckPredicate, 33, 45, 0, // Skip to: 1848
/* 1803 */    MCD_OPC_Decode, 128, 1, 229, 1, // Opcode: AUIPC
/* 1808 */    MCD_OPC_FilterValue, 3, 36, 0, // Skip to: 1848
/* 1812 */    MCD_OPC_CheckPredicate, 33, 32, 0, // Skip to: 1848
/* 1816 */    MCD_OPC_Decode, 74, 229, 1, // Opcode: ALUIPC
/* 1820 */    MCD_OPC_FilterValue, 62, 24, 0, // Skip to: 1848
/* 1824 */    MCD_OPC_CheckPredicate, 33, 11, 0, // Skip to: 1839
/* 1828 */    MCD_OPC_CheckField, 21, 5, 0, 5, 0, // Skip to: 1839
/* 1834 */    MCD_OPC_Decode, 239, 6, 225, 1, // Opcode: JIALC
/* 1839 */    MCD_OPC_CheckPredicate, 33, 5, 0, // Skip to: 1848
/* 1843 */    MCD_OPC_Decode, 142, 2, 226, 1, // Opcode: BNEZC
/* 1848 */    MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMips32r6_64r6_GP6432[] = {
/* 0 */       MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 3 */       MCD_OPC_FilterValue, 53, 15, 0, // Skip to: 22
/* 7 */       MCD_OPC_CheckPredicate, 36, 30, 0, // Skip to: 41
/* 11 */      MCD_OPC_CheckField, 26, 6, 0, 24, 0, // Skip to: 41
/* 17 */      MCD_OPC_Decode, 241, 10, 201, 1, // Opcode: SELEQZ64
/* 22 */      MCD_OPC_FilterValue, 55, 15, 0, // Skip to: 41
/* 26 */      MCD_OPC_CheckPredicate, 36, 11, 0, // Skip to: 41
/* 30 */      MCD_OPC_CheckField, 26, 6, 0, 5, 0, // Skip to: 41
/* 36 */      MCD_OPC_Decode, 245, 10, 201, 1, // Opcode: SELNEZ64
/* 41 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableMips6432[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 0, 112, 1, // Skip to: 375
/* 7 */       MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 10 */      MCD_OPC_FilterValue, 20, 15, 0, // Skip to: 29
/* 14 */      MCD_OPC_CheckPredicate, 17, 194, 8, // Skip to: 2260
/* 18 */      MCD_OPC_CheckField, 6, 5, 0, 188, 8, // Skip to: 2260
/* 24 */      MCD_OPC_Decode, 235, 4, 230, 1, // Opcode: DSLLV
/* 29 */      MCD_OPC_FilterValue, 22, 29, 0, // Skip to: 62
/* 33 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 36 */      MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 49
/* 40 */      MCD_OPC_CheckPredicate, 17, 168, 8, // Skip to: 2260
/* 44 */      MCD_OPC_Decode, 241, 4, 230, 1, // Opcode: DSRLV
/* 49 */      MCD_OPC_FilterValue, 1, 159, 8, // Skip to: 2260
/* 53 */      MCD_OPC_CheckPredicate, 37, 155, 8, // Skip to: 2260
/* 57 */      MCD_OPC_Decode, 228, 4, 230, 1, // Opcode: DROTRV
/* 62 */      MCD_OPC_FilterValue, 23, 15, 0, // Skip to: 81
/* 66 */      MCD_OPC_CheckPredicate, 17, 142, 8, // Skip to: 2260
/* 70 */      MCD_OPC_CheckField, 6, 5, 0, 136, 8, // Skip to: 2260
/* 76 */      MCD_OPC_Decode, 238, 4, 230, 1, // Opcode: DSRAV
/* 81 */      MCD_OPC_FilterValue, 28, 15, 0, // Skip to: 100
/* 85 */      MCD_OPC_CheckPredicate, 38, 123, 8, // Skip to: 2260
/* 89 */      MCD_OPC_CheckField, 6, 10, 0, 117, 8, // Skip to: 2260
/* 95 */      MCD_OPC_Decode, 187, 4, 231, 1, // Opcode: DMULT
/* 100 */     MCD_OPC_FilterValue, 29, 15, 0, // Skip to: 119
/* 104 */     MCD_OPC_CheckPredicate, 38, 104, 8, // Skip to: 2260
/* 108 */     MCD_OPC_CheckField, 6, 10, 0, 98, 8, // Skip to: 2260
/* 114 */     MCD_OPC_Decode, 188, 4, 231, 1, // Opcode: DMULTu
/* 119 */     MCD_OPC_FilterValue, 30, 15, 0, // Skip to: 138
/* 123 */     MCD_OPC_CheckPredicate, 38, 85, 8, // Skip to: 2260
/* 127 */     MCD_OPC_CheckField, 6, 10, 0, 79, 8, // Skip to: 2260
/* 133 */     MCD_OPC_Decode, 230, 4, 231, 1, // Opcode: DSDIV
/* 138 */     MCD_OPC_FilterValue, 31, 15, 0, // Skip to: 157
/* 142 */     MCD_OPC_CheckPredicate, 38, 66, 8, // Skip to: 2260
/* 146 */     MCD_OPC_CheckField, 6, 10, 0, 60, 8, // Skip to: 2260
/* 152 */     MCD_OPC_Decode, 244, 4, 231, 1, // Opcode: DUDIV
/* 157 */     MCD_OPC_FilterValue, 44, 15, 0, // Skip to: 176
/* 161 */     MCD_OPC_CheckPredicate, 17, 47, 8, // Skip to: 2260
/* 165 */     MCD_OPC_CheckField, 6, 5, 0, 41, 8, // Skip to: 2260
/* 171 */     MCD_OPC_Decode, 139, 4, 201, 1, // Opcode: DADD
/* 176 */     MCD_OPC_FilterValue, 45, 15, 0, // Skip to: 195
/* 180 */     MCD_OPC_CheckPredicate, 17, 28, 8, // Skip to: 2260
/* 184 */     MCD_OPC_CheckField, 6, 5, 0, 22, 8, // Skip to: 2260
/* 190 */     MCD_OPC_Decode, 142, 4, 201, 1, // Opcode: DADDu
/* 195 */     MCD_OPC_FilterValue, 46, 15, 0, // Skip to: 214
/* 199 */     MCD_OPC_CheckPredicate, 17, 9, 8, // Skip to: 2260
/* 203 */     MCD_OPC_CheckField, 6, 5, 0, 3, 8, // Skip to: 2260
/* 209 */     MCD_OPC_Decode, 242, 4, 201, 1, // Opcode: DSUB
/* 214 */     MCD_OPC_FilterValue, 47, 15, 0, // Skip to: 233
/* 218 */     MCD_OPC_CheckPredicate, 17, 246, 7, // Skip to: 2260
/* 222 */     MCD_OPC_CheckField, 6, 5, 0, 240, 7, // Skip to: 2260
/* 228 */     MCD_OPC_Decode, 243, 4, 201, 1, // Opcode: DSUBu
/* 233 */     MCD_OPC_FilterValue, 56, 15, 0, // Skip to: 252
/* 237 */     MCD_OPC_CheckPredicate, 17, 227, 7, // Skip to: 2260
/* 241 */     MCD_OPC_CheckField, 21, 5, 0, 221, 7, // Skip to: 2260
/* 247 */     MCD_OPC_Decode, 232, 4, 232, 1, // Opcode: DSLL
/* 252 */     MCD_OPC_FilterValue, 58, 29, 0, // Skip to: 285
/* 256 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 259 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 272
/* 263 */     MCD_OPC_CheckPredicate, 17, 201, 7, // Skip to: 2260
/* 267 */     MCD_OPC_Decode, 239, 4, 232, 1, // Opcode: DSRL
/* 272 */     MCD_OPC_FilterValue, 1, 192, 7, // Skip to: 2260
/* 276 */     MCD_OPC_CheckPredicate, 37, 188, 7, // Skip to: 2260
/* 280 */     MCD_OPC_Decode, 226, 4, 232, 1, // Opcode: DROTR
/* 285 */     MCD_OPC_FilterValue, 59, 15, 0, // Skip to: 304
/* 289 */     MCD_OPC_CheckPredicate, 17, 175, 7, // Skip to: 2260
/* 293 */     MCD_OPC_CheckField, 21, 5, 0, 169, 7, // Skip to: 2260
/* 299 */     MCD_OPC_Decode, 236, 4, 232, 1, // Opcode: DSRA
/* 304 */     MCD_OPC_FilterValue, 60, 15, 0, // Skip to: 323
/* 308 */     MCD_OPC_CheckPredicate, 17, 156, 7, // Skip to: 2260
/* 312 */     MCD_OPC_CheckField, 21, 5, 0, 150, 7, // Skip to: 2260
/* 318 */     MCD_OPC_Decode, 233, 4, 232, 1, // Opcode: DSLL32
/* 323 */     MCD_OPC_FilterValue, 62, 29, 0, // Skip to: 356
/* 327 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 330 */     MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 343
/* 334 */     MCD_OPC_CheckPredicate, 17, 130, 7, // Skip to: 2260
/* 338 */     MCD_OPC_Decode, 240, 4, 232, 1, // Opcode: DSRL32
/* 343 */     MCD_OPC_FilterValue, 1, 121, 7, // Skip to: 2260
/* 347 */     MCD_OPC_CheckPredicate, 37, 117, 7, // Skip to: 2260
/* 351 */     MCD_OPC_Decode, 227, 4, 232, 1, // Opcode: DROTR32
/* 356 */     MCD_OPC_FilterValue, 63, 108, 7, // Skip to: 2260
/* 360 */     MCD_OPC_CheckPredicate, 17, 104, 7, // Skip to: 2260
/* 364 */     MCD_OPC_CheckField, 21, 5, 0, 98, 7, // Skip to: 2260
/* 370 */     MCD_OPC_Decode, 237, 4, 232, 1, // Opcode: DSRA32
/* 375 */     MCD_OPC_FilterValue, 16, 41, 0, // Skip to: 420
/* 379 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 382 */     MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 401
/* 386 */     MCD_OPC_CheckPredicate, 39, 78, 7, // Skip to: 2260
/* 390 */     MCD_OPC_CheckField, 3, 8, 0, 72, 7, // Skip to: 2260
/* 396 */     MCD_OPC_Decode, 176, 4, 233, 1, // Opcode: DMFC0
/* 401 */     MCD_OPC_FilterValue, 5, 63, 7, // Skip to: 2260
/* 405 */     MCD_OPC_CheckPredicate, 39, 59, 7, // Skip to: 2260
/* 409 */     MCD_OPC_CheckField, 3, 8, 0, 53, 7, // Skip to: 2260
/* 415 */     MCD_OPC_Decode, 181, 4, 233, 1, // Opcode: DMTC0
/* 420 */     MCD_OPC_FilterValue, 17, 222, 3, // Skip to: 1414
/* 424 */     MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 427 */     MCD_OPC_FilterValue, 0, 54, 0, // Skip to: 485
/* 431 */     MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 434 */     MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 453
/* 438 */     MCD_OPC_CheckPredicate, 40, 26, 7, // Skip to: 2260
/* 442 */     MCD_OPC_CheckField, 6, 5, 0, 20, 7, // Skip to: 2260
/* 448 */     MCD_OPC_Decode, 146, 8, 234, 1, // Opcode: MFHC1_D64
/* 453 */     MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 472
/* 457 */     MCD_OPC_CheckPredicate, 40, 7, 7, // Skip to: 2260
/* 461 */     MCD_OPC_CheckField, 6, 5, 0, 1, 7, // Skip to: 2260
/* 467 */     MCD_OPC_Decode, 135, 9, 235, 1, // Opcode: MTHC1_D64
/* 472 */     MCD_OPC_FilterValue, 17, 248, 6, // Skip to: 2260
/* 476 */     MCD_OPC_CheckPredicate, 41, 244, 6, // Skip to: 2260
/* 480 */     MCD_OPC_Decode, 151, 5, 210, 1, // Opcode: FADD_D64
/* 485 */     MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 504
/* 489 */     MCD_OPC_CheckPredicate, 41, 231, 6, // Skip to: 2260
/* 493 */     MCD_OPC_CheckField, 21, 5, 17, 225, 6, // Skip to: 2260
/* 499 */     MCD_OPC_Decode, 153, 6, 210, 1, // Opcode: FSUB_D64
/* 504 */     MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 523
/* 508 */     MCD_OPC_CheckPredicate, 41, 212, 6, // Skip to: 2260
/* 512 */     MCD_OPC_CheckField, 21, 5, 17, 206, 6, // Skip to: 2260
/* 518 */     MCD_OPC_Decode, 244, 5, 210, 1, // Opcode: FMUL_D64
/* 523 */     MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 542
/* 527 */     MCD_OPC_CheckPredicate, 41, 193, 6, // Skip to: 2260
/* 531 */     MCD_OPC_CheckField, 21, 5, 17, 187, 6, // Skip to: 2260
/* 537 */     MCD_OPC_Decode, 187, 5, 210, 1, // Opcode: FDIV_D64
/* 542 */     MCD_OPC_FilterValue, 4, 15, 0, // Skip to: 561
/* 546 */     MCD_OPC_CheckPredicate, 42, 174, 6, // Skip to: 2260
/* 550 */     MCD_OPC_CheckField, 16, 10, 160, 4, 167, 6, // Skip to: 2260
/* 557 */     MCD_OPC_Decode, 146, 6, 82, // Opcode: FSQRT_D64
/* 561 */     MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 580
/* 565 */     MCD_OPC_CheckPredicate, 41, 155, 6, // Skip to: 2260
/* 569 */     MCD_OPC_CheckField, 16, 10, 160, 4, 148, 6, // Skip to: 2260
/* 576 */     MCD_OPC_Decode, 144, 5, 82, // Opcode: FABS_D64
/* 580 */     MCD_OPC_FilterValue, 6, 15, 0, // Skip to: 599
/* 584 */     MCD_OPC_CheckPredicate, 41, 136, 6, // Skip to: 2260
/* 588 */     MCD_OPC_CheckField, 16, 10, 160, 4, 129, 6, // Skip to: 2260
/* 595 */     MCD_OPC_Decode, 237, 5, 82, // Opcode: FMOV_D64
/* 599 */     MCD_OPC_FilterValue, 7, 15, 0, // Skip to: 618
/* 603 */     MCD_OPC_CheckPredicate, 41, 117, 6, // Skip to: 2260
/* 607 */     MCD_OPC_CheckField, 16, 10, 160, 4, 110, 6, // Skip to: 2260
/* 614 */     MCD_OPC_Decode, 250, 5, 82, // Opcode: FNEG_D64
/* 618 */     MCD_OPC_FilterValue, 8, 29, 0, // Skip to: 651
/* 622 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 625 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 638
/* 630 */     MCD_OPC_CheckPredicate, 41, 90, 6, // Skip to: 2260
/* 634 */     MCD_OPC_Decode, 193, 10, 75, // Opcode: ROUND_L_S
/* 638 */     MCD_OPC_FilterValue, 160, 4, 81, 6, // Skip to: 2260
/* 643 */     MCD_OPC_CheckPredicate, 41, 77, 6, // Skip to: 2260
/* 647 */     MCD_OPC_Decode, 192, 10, 82, // Opcode: ROUND_L_D64
/* 651 */     MCD_OPC_FilterValue, 9, 29, 0, // Skip to: 684
/* 655 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 658 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 671
/* 663 */     MCD_OPC_CheckPredicate, 41, 57, 6, // Skip to: 2260
/* 667 */     MCD_OPC_Decode, 141, 13, 75, // Opcode: TRUNC_L_S
/* 671 */     MCD_OPC_FilterValue, 160, 4, 48, 6, // Skip to: 2260
/* 676 */     MCD_OPC_CheckPredicate, 41, 44, 6, // Skip to: 2260
/* 680 */     MCD_OPC_Decode, 140, 13, 82, // Opcode: TRUNC_L_D64
/* 684 */     MCD_OPC_FilterValue, 10, 29, 0, // Skip to: 717
/* 688 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 691 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 704
/* 696 */     MCD_OPC_CheckPredicate, 41, 24, 6, // Skip to: 2260
/* 700 */     MCD_OPC_Decode, 204, 2, 75, // Opcode: CEIL_L_S
/* 704 */     MCD_OPC_FilterValue, 160, 4, 15, 6, // Skip to: 2260
/* 709 */     MCD_OPC_CheckPredicate, 41, 11, 6, // Skip to: 2260
/* 713 */     MCD_OPC_Decode, 203, 2, 82, // Opcode: CEIL_L_D64
/* 717 */     MCD_OPC_FilterValue, 11, 29, 0, // Skip to: 750
/* 721 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 724 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 737
/* 729 */     MCD_OPC_CheckPredicate, 41, 247, 5, // Skip to: 2260
/* 733 */     MCD_OPC_Decode, 219, 5, 75, // Opcode: FLOOR_L_S
/* 737 */     MCD_OPC_FilterValue, 160, 4, 238, 5, // Skip to: 2260
/* 742 */     MCD_OPC_CheckPredicate, 41, 234, 5, // Skip to: 2260
/* 746 */     MCD_OPC_Decode, 218, 5, 82, // Opcode: FLOOR_L_D64
/* 750 */     MCD_OPC_FilterValue, 12, 16, 0, // Skip to: 770
/* 754 */     MCD_OPC_CheckPredicate, 42, 222, 5, // Skip to: 2260
/* 758 */     MCD_OPC_CheckField, 16, 10, 160, 4, 215, 5, // Skip to: 2260
/* 765 */     MCD_OPC_Decode, 195, 10, 236, 1, // Opcode: ROUND_W_D64
/* 770 */     MCD_OPC_FilterValue, 13, 16, 0, // Skip to: 790
/* 774 */     MCD_OPC_CheckPredicate, 42, 202, 5, // Skip to: 2260
/* 778 */     MCD_OPC_CheckField, 16, 10, 160, 4, 195, 5, // Skip to: 2260
/* 785 */     MCD_OPC_Decode, 143, 13, 236, 1, // Opcode: TRUNC_W_D64
/* 790 */     MCD_OPC_FilterValue, 14, 16, 0, // Skip to: 810
/* 794 */     MCD_OPC_CheckPredicate, 42, 182, 5, // Skip to: 2260
/* 798 */     MCD_OPC_CheckField, 16, 10, 160, 4, 175, 5, // Skip to: 2260
/* 805 */     MCD_OPC_Decode, 206, 2, 236, 1, // Opcode: CEIL_W_D64
/* 810 */     MCD_OPC_FilterValue, 15, 16, 0, // Skip to: 830
/* 814 */     MCD_OPC_CheckPredicate, 42, 162, 5, // Skip to: 2260
/* 818 */     MCD_OPC_CheckField, 16, 10, 160, 4, 155, 5, // Skip to: 2260
/* 825 */     MCD_OPC_Decode, 221, 5, 236, 1, // Opcode: FLOOR_W_D64
/* 830 */     MCD_OPC_FilterValue, 17, 41, 0, // Skip to: 875
/* 834 */     MCD_OPC_ExtractField, 16, 2,  // Inst{17-16} ...
/* 837 */     MCD_OPC_FilterValue, 0, 15, 0, // Skip to: 856
/* 841 */     MCD_OPC_CheckPredicate, 43, 135, 5, // Skip to: 2260
/* 845 */     MCD_OPC_CheckField, 21, 5, 17, 129, 5, // Skip to: 2260
/* 851 */     MCD_OPC_Decode, 199, 8, 237, 1, // Opcode: MOVF_D64
/* 856 */     MCD_OPC_FilterValue, 1, 120, 5, // Skip to: 2260
/* 860 */     MCD_OPC_CheckPredicate, 43, 116, 5, // Skip to: 2260
/* 864 */     MCD_OPC_CheckField, 21, 5, 17, 110, 5, // Skip to: 2260
/* 870 */     MCD_OPC_Decode, 219, 8, 237, 1, // Opcode: MOVT_D64
/* 875 */     MCD_OPC_FilterValue, 18, 15, 0, // Skip to: 894
/* 879 */     MCD_OPC_CheckPredicate, 43, 97, 5, // Skip to: 2260
/* 883 */     MCD_OPC_CheckField, 21, 5, 17, 91, 5, // Skip to: 2260
/* 889 */     MCD_OPC_Decode, 231, 8, 238, 1, // Opcode: MOVZ_I_D64
/* 894 */     MCD_OPC_FilterValue, 19, 15, 0, // Skip to: 913
/* 898 */     MCD_OPC_CheckPredicate, 43, 78, 5, // Skip to: 2260
/* 902 */     MCD_OPC_CheckField, 21, 5, 17, 72, 5, // Skip to: 2260
/* 908 */     MCD_OPC_Decode, 211, 8, 238, 1, // Opcode: MOVN_I_D64
/* 913 */     MCD_OPC_FilterValue, 32, 31, 0, // Skip to: 948
/* 917 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 920 */     MCD_OPC_FilterValue, 160, 4, 9, 0, // Skip to: 934
/* 925 */     MCD_OPC_CheckPredicate, 41, 51, 5, // Skip to: 2260
/* 929 */     MCD_OPC_Decode, 206, 3, 236, 1, // Opcode: CVT_S_D64
/* 934 */     MCD_OPC_FilterValue, 160, 5, 41, 5, // Skip to: 2260
/* 939 */     MCD_OPC_CheckPredicate, 41, 37, 5, // Skip to: 2260
/* 943 */     MCD_OPC_Decode, 207, 3, 236, 1, // Opcode: CVT_S_L
/* 948 */     MCD_OPC_FilterValue, 33, 42, 0, // Skip to: 994
/* 952 */     MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 955 */     MCD_OPC_FilterValue, 128, 4, 8, 0, // Skip to: 968
/* 960 */     MCD_OPC_CheckPredicate, 41, 16, 5, // Skip to: 2260
/* 964 */     MCD_OPC_Decode, 197, 3, 75, // Opcode: CVT_D64_S
/* 968 */     MCD_OPC_FilterValue, 128, 5, 8, 0, // Skip to: 981
/* 973 */     MCD_OPC_CheckPredicate, 41, 3, 5, // Skip to: 2260
/* 977 */     MCD_OPC_Decode, 198, 3, 75, // Opcode: CVT_D64_W
/* 981 */     MCD_OPC_FilterValue, 160, 5, 250, 4, // Skip to: 2260
/* 986 */     MCD_OPC_CheckPredicate, 41, 246, 4, // Skip to: 2260
/* 990 */     MCD_OPC_Decode, 196, 3, 82, // Opcode: CVT_D64_L
/* 994 */     MCD_OPC_FilterValue, 36, 16, 0, // Skip to: 1014
/* 998 */     MCD_OPC_CheckPredicate, 41, 234, 4, // Skip to: 2260
/* 1002 */    MCD_OPC_CheckField, 16, 10, 160, 4, 227, 4, // Skip to: 2260
/* 1009 */    MCD_OPC_Decode, 211, 3, 236, 1, // Opcode: CVT_W_D64
/* 1014 */    MCD_OPC_FilterValue, 48, 21, 0, // Skip to: 1039
/* 1018 */    MCD_OPC_CheckPredicate, 44, 214, 4, // Skip to: 2260
/* 1022 */    MCD_OPC_CheckField, 21, 5, 17, 208, 4, // Skip to: 2260
/* 1028 */    MCD_OPC_CheckField, 6, 5, 0, 202, 4, // Skip to: 2260
/* 1034 */    MCD_OPC_Decode, 219, 3, 239, 1, // Opcode: C_F_D64
/* 1039 */    MCD_OPC_FilterValue, 49, 21, 0, // Skip to: 1064
/* 1043 */    MCD_OPC_CheckPredicate, 44, 189, 4, // Skip to: 2260
/* 1047 */    MCD_OPC_CheckField, 21, 5, 17, 183, 4, // Skip to: 2260
/* 1053 */    MCD_OPC_CheckField, 6, 5, 0, 177, 4, // Skip to: 2260
/* 1059 */    MCD_OPC_Decode, 133, 4, 239, 1, // Opcode: C_UN_D64
/* 1064 */    MCD_OPC_FilterValue, 50, 21, 0, // Skip to: 1089
/* 1068 */    MCD_OPC_CheckPredicate, 44, 164, 4, // Skip to: 2260
/* 1072 */    MCD_OPC_CheckField, 21, 5, 17, 158, 4, // Skip to: 2260
/* 1078 */    MCD_OPC_CheckField, 6, 5, 0, 152, 4, // Skip to: 2260
/* 1084 */    MCD_OPC_Decode, 216, 3, 239, 1, // Opcode: C_EQ_D64
/* 1089 */    MCD_OPC_FilterValue, 51, 21, 0, // Skip to: 1114
/* 1093 */    MCD_OPC_CheckPredicate, 44, 139, 4, // Skip to: 2260
/* 1097 */    MCD_OPC_CheckField, 21, 5, 17, 133, 4, // Skip to: 2260
/* 1103 */    MCD_OPC_CheckField, 6, 5, 0, 127, 4, // Skip to: 2260
/* 1109 */    MCD_OPC_Decode, 252, 3, 239, 1, // Opcode: C_UEQ_D64
/* 1114 */    MCD_OPC_FilterValue, 52, 21, 0, // Skip to: 1139
/* 1118 */    MCD_OPC_CheckPredicate, 44, 114, 4, // Skip to: 2260
/* 1122 */    MCD_OPC_CheckField, 21, 5, 17, 108, 4, // Skip to: 2260
/* 1128 */    MCD_OPC_CheckField, 6, 5, 0, 102, 4, // Skip to: 2260
/* 1134 */    MCD_OPC_Decode, 243, 3, 239, 1, // Opcode: C_OLT_D64
/* 1139 */    MCD_OPC_FilterValue, 53, 21, 0, // Skip to: 1164
/* 1143 */    MCD_OPC_CheckPredicate, 44, 89, 4, // Skip to: 2260
/* 1147 */    MCD_OPC_CheckField, 21, 5, 17, 83, 4, // Skip to: 2260
/* 1153 */    MCD_OPC_CheckField, 6, 5, 0, 77, 4, // Skip to: 2260
/* 1159 */    MCD_OPC_Decode, 130, 4, 239, 1, // Opcode: C_ULT_D64
/* 1164 */    MCD_OPC_FilterValue, 54, 21, 0, // Skip to: 1189
/* 1168 */    MCD_OPC_CheckPredicate, 44, 64, 4, // Skip to: 2260
/* 1172 */    MCD_OPC_CheckField, 21, 5, 17, 58, 4, // Skip to: 2260
/* 1178 */    MCD_OPC_CheckField, 6, 5, 0, 52, 4, // Skip to: 2260
/* 1184 */    MCD_OPC_Decode, 240, 3, 239, 1, // Opcode: C_OLE_D64
/* 1189 */    MCD_OPC_FilterValue, 55, 21, 0, // Skip to: 1214
/* 1193 */    MCD_OPC_CheckPredicate, 44, 39, 4, // Skip to: 2260
/* 1197 */    MCD_OPC_CheckField, 21, 5, 17, 33, 4, // Skip to: 2260
/* 1203 */    MCD_OPC_CheckField, 6, 5, 0, 27, 4, // Skip to: 2260
/* 1209 */    MCD_OPC_Decode, 255, 3, 239, 1, // Opcode: C_ULE_D64
/* 1214 */    MCD_OPC_FilterValue, 56, 21, 0, // Skip to: 1239
/* 1218 */    MCD_OPC_CheckPredicate, 44, 14, 4, // Skip to: 2260
/* 1222 */    MCD_OPC_CheckField, 21, 5, 17, 8, 4, // Skip to: 2260
/* 1228 */    MCD_OPC_CheckField, 6, 5, 0, 2, 4, // Skip to: 2260
/* 1234 */    MCD_OPC_Decode, 249, 3, 239, 1, // Opcode: C_SF_D64
/* 1239 */    MCD_OPC_FilterValue, 57, 21, 0, // Skip to: 1264
/* 1243 */    MCD_OPC_CheckPredicate, 44, 245, 3, // Skip to: 2260
/* 1247 */    MCD_OPC_CheckField, 21, 5, 17, 239, 3, // Skip to: 2260
/* 1253 */    MCD_OPC_CheckField, 6, 5, 0, 233, 3, // Skip to: 2260
/* 1259 */    MCD_OPC_Decode, 231, 3, 239, 1, // Opcode: C_NGLE_D64
/* 1264 */    MCD_OPC_FilterValue, 58, 21, 0, // Skip to: 1289
/* 1268 */    MCD_OPC_CheckPredicate, 44, 220, 3, // Skip to: 2260
/* 1272 */    MCD_OPC_CheckField, 21, 5, 17, 214, 3, // Skip to: 2260
/* 1278 */    MCD_OPC_CheckField, 6, 5, 0, 208, 3, // Skip to: 2260
/* 1284 */    MCD_OPC_Decode, 246, 3, 239, 1, // Opcode: C_SEQ_D64
/* 1289 */    MCD_OPC_FilterValue, 59, 21, 0, // Skip to: 1314
/* 1293 */    MCD_OPC_CheckPredicate, 44, 195, 3, // Skip to: 2260
/* 1297 */    MCD_OPC_CheckField, 21, 5, 17, 189, 3, // Skip to: 2260
/* 1303 */    MCD_OPC_CheckField, 6, 5, 0, 183, 3, // Skip to: 2260
/* 1309 */    MCD_OPC_Decode, 234, 3, 239, 1, // Opcode: C_NGL_D64
/* 1314 */    MCD_OPC_FilterValue, 60, 21, 0, // Skip to: 1339
/* 1318 */    MCD_OPC_CheckPredicate, 44, 170, 3, // Skip to: 2260
/* 1322 */    MCD_OPC_CheckField, 21, 5, 17, 164, 3, // Skip to: 2260
/* 1328 */    MCD_OPC_CheckField, 6, 5, 0, 158, 3, // Skip to: 2260
/* 1334 */    MCD_OPC_Decode, 225, 3, 239, 1, // Opcode: C_LT_D64
/* 1339 */    MCD_OPC_FilterValue, 61, 21, 0, // Skip to: 1364
/* 1343 */    MCD_OPC_CheckPredicate, 44, 145, 3, // Skip to: 2260
/* 1347 */    MCD_OPC_CheckField, 21, 5, 17, 139, 3, // Skip to: 2260
/* 1353 */    MCD_OPC_CheckField, 6, 5, 0, 133, 3, // Skip to: 2260
/* 1359 */    MCD_OPC_Decode, 228, 3, 239, 1, // Opcode: C_NGE_D64
/* 1364 */    MCD_OPC_FilterValue, 62, 21, 0, // Skip to: 1389
/* 1368 */    MCD_OPC_CheckPredicate, 44, 120, 3, // Skip to: 2260
/* 1372 */    MCD_OPC_CheckField, 21, 5, 17, 114, 3, // Skip to: 2260
/* 1378 */    MCD_OPC_CheckField, 6, 5, 0, 108, 3, // Skip to: 2260
/* 1384 */    MCD_OPC_Decode, 222, 3, 239, 1, // Opcode: C_LE_D64
/* 1389 */    MCD_OPC_FilterValue, 63, 99, 3, // Skip to: 2260
/* 1393 */    MCD_OPC_CheckPredicate, 44, 95, 3, // Skip to: 2260
/* 1397 */    MCD_OPC_CheckField, 21, 5, 17, 89, 3, // Skip to: 2260
/* 1403 */    MCD_OPC_CheckField, 6, 5, 0, 83, 3, // Skip to: 2260
/* 1409 */    MCD_OPC_Decode, 237, 3, 239, 1, // Opcode: C_NGT_D64
/* 1414 */    MCD_OPC_FilterValue, 18, 41, 0, // Skip to: 1459
/* 1418 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 1421 */    MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 1440
/* 1425 */    MCD_OPC_CheckPredicate, 39, 63, 3, // Skip to: 2260
/* 1429 */    MCD_OPC_CheckField, 3, 8, 0, 57, 3, // Skip to: 2260
/* 1435 */    MCD_OPC_Decode, 178, 4, 233, 1, // Opcode: DMFC2
/* 1440 */    MCD_OPC_FilterValue, 5, 48, 3, // Skip to: 2260
/* 1444 */    MCD_OPC_CheckPredicate, 39, 44, 3, // Skip to: 2260
/* 1448 */    MCD_OPC_CheckField, 3, 8, 0, 38, 3, // Skip to: 2260
/* 1454 */    MCD_OPC_Decode, 183, 4, 233, 1, // Opcode: DMTC2
/* 1459 */    MCD_OPC_FilterValue, 19, 79, 0, // Skip to: 1542
/* 1463 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1466 */    MCD_OPC_FilterValue, 1, 15, 0, // Skip to: 1485
/* 1470 */    MCD_OPC_CheckPredicate, 45, 18, 3, // Skip to: 2260
/* 1474 */    MCD_OPC_CheckField, 11, 5, 0, 12, 3, // Skip to: 2260
/* 1480 */    MCD_OPC_Decode, 148, 7, 240, 1, // Opcode: LDXC164
/* 1485 */    MCD_OPC_FilterValue, 5, 15, 0, // Skip to: 1504
/* 1489 */    MCD_OPC_CheckPredicate, 46, 255, 2, // Skip to: 2260
/* 1493 */    MCD_OPC_CheckField, 11, 5, 0, 249, 2, // Skip to: 2260
/* 1499 */    MCD_OPC_Decode, 178, 7, 240, 1, // Opcode: LUXC164
/* 1504 */    MCD_OPC_FilterValue, 9, 15, 0, // Skip to: 1523
/* 1508 */    MCD_OPC_CheckPredicate, 45, 236, 2, // Skip to: 2260
/* 1512 */    MCD_OPC_CheckField, 6, 5, 0, 230, 2, // Skip to: 2260
/* 1518 */    MCD_OPC_Decode, 233, 10, 241, 1, // Opcode: SDXC164
/* 1523 */    MCD_OPC_FilterValue, 13, 221, 2, // Skip to: 2260
/* 1527 */    MCD_OPC_CheckPredicate, 46, 217, 2, // Skip to: 2260
/* 1531 */    MCD_OPC_CheckField, 6, 5, 0, 211, 2, // Skip to: 2260
/* 1537 */    MCD_OPC_Decode, 166, 12, 241, 1, // Opcode: SUXC164
/* 1542 */    MCD_OPC_FilterValue, 24, 9, 0, // Skip to: 1555
/* 1546 */    MCD_OPC_CheckPredicate, 38, 198, 2, // Skip to: 2260
/* 1550 */    MCD_OPC_Decode, 140, 4, 242, 1, // Opcode: DADDi
/* 1555 */    MCD_OPC_FilterValue, 25, 9, 0, // Skip to: 1568
/* 1559 */    MCD_OPC_CheckPredicate, 17, 185, 2, // Skip to: 2260
/* 1563 */    MCD_OPC_Decode, 141, 4, 242, 1, // Opcode: DADDiu
/* 1568 */    MCD_OPC_FilterValue, 26, 9, 0, // Skip to: 1581
/* 1572 */    MCD_OPC_CheckPredicate, 38, 172, 2, // Skip to: 2260
/* 1576 */    MCD_OPC_Decode, 144, 7, 194, 1, // Opcode: LDL
/* 1581 */    MCD_OPC_FilterValue, 27, 9, 0, // Skip to: 1594
/* 1585 */    MCD_OPC_CheckPredicate, 38, 159, 2, // Skip to: 2260
/* 1589 */    MCD_OPC_Decode, 146, 7, 194, 1, // Opcode: LDR
/* 1594 */    MCD_OPC_FilterValue, 28, 159, 1, // Skip to: 2013
/* 1598 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 1601 */    MCD_OPC_FilterValue, 3, 15, 0, // Skip to: 1620
/* 1605 */    MCD_OPC_CheckPredicate, 47, 139, 2, // Skip to: 2260
/* 1609 */    MCD_OPC_CheckField, 6, 5, 0, 133, 2, // Skip to: 2260
/* 1615 */    MCD_OPC_Decode, 186, 4, 201, 1, // Opcode: DMUL
/* 1620 */    MCD_OPC_FilterValue, 8, 15, 0, // Skip to: 1639
/* 1624 */    MCD_OPC_CheckPredicate, 47, 120, 2, // Skip to: 2260
/* 1628 */    MCD_OPC_CheckField, 6, 15, 0, 114, 2, // Skip to: 2260
/* 1634 */    MCD_OPC_Decode, 146, 9, 243, 1, // Opcode: MTM0
/* 1639 */    MCD_OPC_FilterValue, 9, 15, 0, // Skip to: 1658
/* 1643 */    MCD_OPC_CheckPredicate, 47, 101, 2, // Skip to: 2260
/* 1647 */    MCD_OPC_CheckField, 6, 15, 0, 95, 2, // Skip to: 2260
/* 1653 */    MCD_OPC_Decode, 149, 9, 243, 1, // Opcode: MTP0
/* 1658 */    MCD_OPC_FilterValue, 10, 15, 0, // Skip to: 1677
/* 1662 */    MCD_OPC_CheckPredicate, 47, 82, 2, // Skip to: 2260
/* 1666 */    MCD_OPC_CheckField, 6, 15, 0, 76, 2, // Skip to: 2260
/* 1672 */    MCD_OPC_Decode, 150, 9, 243, 1, // Opcode: MTP1
/* 1677 */    MCD_OPC_FilterValue, 11, 15, 0, // Skip to: 1696
/* 1681 */    MCD_OPC_CheckPredicate, 47, 63, 2, // Skip to: 2260
/* 1685 */    MCD_OPC_CheckField, 6, 15, 0, 57, 2, // Skip to: 2260
/* 1691 */    MCD_OPC_Decode, 151, 9, 243, 1, // Opcode: MTP2
/* 1696 */    MCD_OPC_FilterValue, 12, 15, 0, // Skip to: 1715
/* 1700 */    MCD_OPC_CheckPredicate, 47, 44, 2, // Skip to: 2260
/* 1704 */    MCD_OPC_CheckField, 6, 15, 0, 38, 2, // Skip to: 2260
/* 1710 */    MCD_OPC_Decode, 147, 9, 243, 1, // Opcode: MTM1
/* 1715 */    MCD_OPC_FilterValue, 13, 15, 0, // Skip to: 1734
/* 1719 */    MCD_OPC_CheckPredicate, 47, 25, 2, // Skip to: 2260
/* 1723 */    MCD_OPC_CheckField, 6, 15, 0, 19, 2, // Skip to: 2260
/* 1729 */    MCD_OPC_Decode, 148, 9, 243, 1, // Opcode: MTM2
/* 1734 */    MCD_OPC_FilterValue, 15, 15, 0, // Skip to: 1753
/* 1738 */    MCD_OPC_CheckPredicate, 47, 6, 2, // Skip to: 2260
/* 1742 */    MCD_OPC_CheckField, 6, 5, 0, 0, 2, // Skip to: 2260
/* 1748 */    MCD_OPC_Decode, 152, 13, 201, 1, // Opcode: VMULU
/* 1753 */    MCD_OPC_FilterValue, 16, 15, 0, // Skip to: 1772
/* 1757 */    MCD_OPC_CheckPredicate, 47, 243, 1, // Skip to: 2260
/* 1761 */    MCD_OPC_CheckField, 6, 5, 0, 237, 1, // Skip to: 2260
/* 1767 */    MCD_OPC_Decode, 151, 13, 201, 1, // Opcode: VMM0
/* 1772 */    MCD_OPC_FilterValue, 17, 15, 0, // Skip to: 1791
/* 1776 */    MCD_OPC_CheckPredicate, 47, 224, 1, // Skip to: 2260
/* 1780 */    MCD_OPC_CheckField, 6, 5, 0, 218, 1, // Skip to: 2260
/* 1786 */    MCD_OPC_Decode, 150, 13, 201, 1, // Opcode: V3MULU
/* 1791 */    MCD_OPC_FilterValue, 36, 15, 0, // Skip to: 1810
/* 1795 */    MCD_OPC_CheckPredicate, 48, 205, 1, // Skip to: 2260
/* 1799 */    MCD_OPC_CheckField, 6, 5, 0, 199, 1, // Skip to: 2260
/* 1805 */    MCD_OPC_Decode, 150, 4, 244, 1, // Opcode: DCLZ
/* 1810 */    MCD_OPC_FilterValue, 37, 15, 0, // Skip to: 1829
/* 1814 */    MCD_OPC_CheckPredicate, 48, 186, 1, // Skip to: 2260
/* 1818 */    MCD_OPC_CheckField, 6, 5, 0, 180, 1, // Skip to: 2260
/* 1824 */    MCD_OPC_Decode, 148, 4, 244, 1, // Opcode: DCLO
/* 1829 */    MCD_OPC_FilterValue, 40, 15, 0, // Skip to: 1848
/* 1833 */    MCD_OPC_CheckPredicate, 47, 167, 1, // Skip to: 2260
/* 1837 */    MCD_OPC_CheckField, 6, 5, 0, 161, 1, // Skip to: 2260
/* 1843 */    MCD_OPC_Decode, 155, 1, 201, 1, // Opcode: BADDu
/* 1848 */    MCD_OPC_FilterValue, 42, 15, 0, // Skip to: 1867
/* 1852 */    MCD_OPC_CheckPredicate, 47, 148, 1, // Skip to: 2260
/* 1856 */    MCD_OPC_CheckField, 6, 5, 0, 142, 1, // Skip to: 2260
/* 1862 */    MCD_OPC_Decode, 250, 10, 201, 1, // Opcode: SEQ
/* 1867 */    MCD_OPC_FilterValue, 43, 15, 0, // Skip to: 1886
/* 1871 */    MCD_OPC_CheckPredicate, 47, 129, 1, // Skip to: 2260
/* 1875 */    MCD_OPC_CheckField, 6, 5, 0, 123, 1, // Skip to: 2260
/* 1881 */    MCD_OPC_Decode, 188, 11, 201, 1, // Opcode: SNE
/* 1886 */    MCD_OPC_FilterValue, 44, 20, 0, // Skip to: 1910
/* 1890 */    MCD_OPC_CheckPredicate, 47, 110, 1, // Skip to: 2260
/* 1894 */    MCD_OPC_CheckField, 16, 5, 0, 104, 1, // Skip to: 2260
/* 1900 */    MCD_OPC_CheckField, 6, 5, 0, 98, 1, // Skip to: 2260
/* 1906 */    MCD_OPC_Decode, 249, 9, 40, // Opcode: POP
/* 1910 */    MCD_OPC_FilterValue, 45, 21, 0, // Skip to: 1935
/* 1914 */    MCD_OPC_CheckPredicate, 47, 86, 1, // Skip to: 2260
/* 1918 */    MCD_OPC_CheckField, 16, 5, 0, 80, 1, // Skip to: 2260
/* 1924 */    MCD_OPC_CheckField, 6, 5, 0, 74, 1, // Skip to: 2260
/* 1930 */    MCD_OPC_Decode, 211, 4, 199, 1, // Opcode: DPOP
/* 1935 */    MCD_OPC_FilterValue, 46, 9, 0, // Skip to: 1948
/* 1939 */    MCD_OPC_CheckPredicate, 47, 61, 1, // Skip to: 2260
/* 1943 */    MCD_OPC_Decode, 251, 10, 245, 1, // Opcode: SEQi
/* 1948 */    MCD_OPC_FilterValue, 47, 9, 0, // Skip to: 1961
/* 1952 */    MCD_OPC_CheckPredicate, 47, 48, 1, // Skip to: 2260
/* 1956 */    MCD_OPC_Decode, 189, 11, 245, 1, // Opcode: SNEi
/* 1961 */    MCD_OPC_FilterValue, 50, 9, 0, // Skip to: 1974
/* 1965 */    MCD_OPC_CheckPredicate, 47, 35, 1, // Skip to: 2260
/* 1969 */    MCD_OPC_Decode, 221, 2, 246, 1, // Opcode: CINS
/* 1974 */    MCD_OPC_FilterValue, 51, 9, 0, // Skip to: 1987
/* 1978 */    MCD_OPC_CheckPredicate, 47, 22, 1, // Skip to: 2260
/* 1982 */    MCD_OPC_Decode, 222, 2, 246, 1, // Opcode: CINS32
/* 1987 */    MCD_OPC_FilterValue, 58, 9, 0, // Skip to: 2000
/* 1991 */    MCD_OPC_CheckPredicate, 47, 9, 1, // Skip to: 2260
/* 1995 */    MCD_OPC_Decode, 137, 5, 246, 1, // Opcode: EXTS
/* 2000 */    MCD_OPC_FilterValue, 59, 0, 1, // Skip to: 2260
/* 2004 */    MCD_OPC_CheckPredicate, 47, 252, 0, // Skip to: 2260
/* 2008 */    MCD_OPC_Decode, 138, 5, 246, 1, // Opcode: EXTS32
/* 2013 */    MCD_OPC_FilterValue, 31, 126, 0, // Skip to: 2143
/* 2017 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 2020 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 2033
/* 2024 */    MCD_OPC_CheckPredicate, 4, 232, 0, // Skip to: 2260
/* 2028 */    MCD_OPC_Decode, 157, 4, 247, 1, // Opcode: DEXTM
/* 2033 */    MCD_OPC_FilterValue, 2, 9, 0, // Skip to: 2046
/* 2037 */    MCD_OPC_CheckPredicate, 4, 219, 0, // Skip to: 2260
/* 2041 */    MCD_OPC_Decode, 158, 4, 247, 1, // Opcode: DEXTU
/* 2046 */    MCD_OPC_FilterValue, 3, 9, 0, // Skip to: 2059
/* 2050 */    MCD_OPC_CheckPredicate, 4, 206, 0, // Skip to: 2260
/* 2054 */    MCD_OPC_Decode, 156, 4, 247, 1, // Opcode: DEXT
/* 2059 */    MCD_OPC_FilterValue, 5, 9, 0, // Skip to: 2072
/* 2063 */    MCD_OPC_CheckPredicate, 4, 193, 0, // Skip to: 2260
/* 2067 */    MCD_OPC_Decode, 161, 4, 248, 1, // Opcode: DINSM
/* 2072 */    MCD_OPC_FilterValue, 6, 9, 0, // Skip to: 2085
/* 2076 */    MCD_OPC_CheckPredicate, 4, 180, 0, // Skip to: 2260
/* 2080 */    MCD_OPC_Decode, 162, 4, 248, 1, // Opcode: DINSU
/* 2085 */    MCD_OPC_FilterValue, 7, 9, 0, // Skip to: 2098
/* 2089 */    MCD_OPC_CheckPredicate, 4, 167, 0, // Skip to: 2260
/* 2093 */    MCD_OPC_Decode, 160, 4, 248, 1, // Opcode: DINS
/* 2098 */    MCD_OPC_FilterValue, 36, 158, 0, // Skip to: 2260
/* 2102 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 2105 */    MCD_OPC_FilterValue, 2, 15, 0, // Skip to: 2124
/* 2109 */    MCD_OPC_CheckPredicate, 37, 147, 0, // Skip to: 2260
/* 2113 */    MCD_OPC_CheckField, 21, 5, 0, 141, 0, // Skip to: 2260
/* 2119 */    MCD_OPC_Decode, 229, 4, 220, 1, // Opcode: DSBH
/* 2124 */    MCD_OPC_FilterValue, 5, 132, 0, // Skip to: 2260
/* 2128 */    MCD_OPC_CheckPredicate, 37, 128, 0, // Skip to: 2260
/* 2132 */    MCD_OPC_CheckField, 21, 5, 0, 122, 0, // Skip to: 2260
/* 2138 */    MCD_OPC_Decode, 231, 4, 220, 1, // Opcode: DSHD
/* 2143 */    MCD_OPC_FilterValue, 39, 9, 0, // Skip to: 2156
/* 2147 */    MCD_OPC_CheckPredicate, 17, 109, 0, // Skip to: 2260
/* 2151 */    MCD_OPC_Decode, 203, 7, 194, 1, // Opcode: LWu
/* 2156 */    MCD_OPC_FilterValue, 44, 9, 0, // Skip to: 2169
/* 2160 */    MCD_OPC_CheckPredicate, 38, 96, 0, // Skip to: 2260
/* 2164 */    MCD_OPC_Decode, 230, 10, 194, 1, // Opcode: SDL
/* 2169 */    MCD_OPC_FilterValue, 45, 9, 0, // Skip to: 2182
/* 2173 */    MCD_OPC_CheckPredicate, 38, 83, 0, // Skip to: 2260
/* 2177 */    MCD_OPC_Decode, 231, 10, 194, 1, // Opcode: SDR
/* 2182 */    MCD_OPC_FilterValue, 52, 9, 0, // Skip to: 2195
/* 2186 */    MCD_OPC_CheckPredicate, 38, 70, 0, // Skip to: 2260
/* 2190 */    MCD_OPC_Decode, 164, 7, 194, 1, // Opcode: LLD
/* 2195 */    MCD_OPC_FilterValue, 53, 9, 0, // Skip to: 2208
/* 2199 */    MCD_OPC_CheckPredicate, 49, 57, 0, // Skip to: 2260
/* 2203 */    MCD_OPC_Decode, 135, 7, 196, 1, // Opcode: LDC164
/* 2208 */    MCD_OPC_FilterValue, 55, 9, 0, // Skip to: 2221
/* 2212 */    MCD_OPC_CheckPredicate, 17, 44, 0, // Skip to: 2260
/* 2216 */    MCD_OPC_Decode, 133, 7, 194, 1, // Opcode: LD
/* 2221 */    MCD_OPC_FilterValue, 60, 9, 0, // Skip to: 2234
/* 2225 */    MCD_OPC_CheckPredicate, 38, 31, 0, // Skip to: 2260
/* 2229 */    MCD_OPC_Decode, 215, 10, 194, 1, // Opcode: SCD
/* 2234 */    MCD_OPC_FilterValue, 61, 9, 0, // Skip to: 2247
/* 2238 */    MCD_OPC_CheckPredicate, 49, 18, 0, // Skip to: 2260
/* 2242 */    MCD_OPC_Decode, 223, 10, 196, 1, // Opcode: SDC164
/* 2247 */    MCD_OPC_FilterValue, 63, 9, 0, // Skip to: 2260
/* 2251 */    MCD_OPC_CheckPredicate, 17, 5, 0, // Skip to: 2260
/* 2255 */    MCD_OPC_Decode, 219, 10, 194, 1, // Opcode: SD
/* 2260 */    MCD_OPC_Fail,
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
    return getbool((Bits & Mips_FeatureMips16));
  case 1:
    return getbool(!(Bits & Mips_FeatureMips16));
  case 2:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips2));
  case 3:
    return getbool((Bits & Mips_FeatureMicroMips));
  case 4:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips32r2));
  case 5:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips4_32) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 6:
    return getbool((Bits & Mips_FeatureMSA));
  case 7:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips32) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 8:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMicroMips));
  case 9:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips32));
  case 10:
    return getbool(!(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6) && !(Bits & Mips_FeatureMicroMips));
  case 11:
    return getbool((Bits & Mips_FeatureDSP));
  case 12:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 13:
    return getbool((Bits & Mips_FeatureMSA) && (Bits & Mips_FeatureMips64));
  case 14:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips2) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 15:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips3_32));
  case 16:
    return getbool(!(Bits & Mips_FeatureMicroMips));
  case 17:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips3));
  case 18:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips32r2) && !(Bits & Mips_FeatureFP64Bit));
  case 19:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureFP64Bit));
  case 20:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips3_32r2));
  case 21:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips2) && !(Bits & Mips_FeatureFP64Bit));
  case 22:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips4_32) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 23:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6) && !(Bits & Mips_FeatureFP64Bit));
  case 24:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips4_32r2) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 25:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips4_32r2) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6) && !(Bits & Mips_FeatureMicroMips));
  case 26:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips5_32r2) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 27:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips32r2) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 28:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips32r2) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 29:
    return getbool((Bits & Mips_FeatureDSPR2));
  case 30:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips3_32) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 31:
    return getbool((Bits & Mips_FeatureMips2) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6) && !(Bits & Mips_FeatureMicroMips));
  case 32:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips2));
  case 33:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips32r6));
  case 34:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips64r6));
  case 35:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureGP64Bit) && (Bits & Mips_FeatureMips32r6));
  case 36:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureGP64Bit) && (Bits & Mips_FeatureMips32r6));
  case 37:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips64r2));
  case 38:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips3) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 39:
    return getbool((Bits & Mips_FeatureMips64));
  case 40:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips32r2) && (Bits & Mips_FeatureFP64Bit));
  case 41:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureFP64Bit));
  case 42:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips2) && (Bits & Mips_FeatureFP64Bit));
  case 43:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips4_32) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 44:
    return getbool(!(Bits & Mips_FeatureMips16) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6) && (Bits & Mips_FeatureFP64Bit));
  case 45:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips4_32r2) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 46:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips5_32r2) && !(Bits & Mips_FeatureMips32r6) && !(Bits & Mips_FeatureMips64r6));
  case 47:
    return getbool((Bits & Mips_FeatureCnMips));
  case 48:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureMips64) && !(Bits & Mips_FeatureMips64r6));
  case 49:
    return getbool(!(Bits & Mips_FeatureMips16) && (Bits & Mips_FeatureFP64Bit) && (Bits & Mips_FeatureMips2));
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
    return S; \
  case 1: \
    tmp = fieldname(insn, 8, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 2: \
    tmp = fieldname(insn, 8, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 3: \
    tmp = 0; \
    tmp |= (fieldname(insn, 3, 2) << 3); \
    tmp |= (fieldname(insn, 5, 3) << 0); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 4: \
    tmp = fieldname(insn, 0, 4); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 5: \
    tmp = fieldname(insn, 2, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 5, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 6: \
    tmp = fieldname(insn, 8, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 5, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 7: \
    tmp = fieldname(insn, 8, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 5, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 8: \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 5) << 0); \
    tmp |= (fieldname(insn, 16, 5) << 11); \
    tmp |= (fieldname(insn, 21, 6) << 5); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 9: \
    tmp = fieldname(insn, 5, 3); \
    if (DecodeCPU16RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 10: \
    if (DecodeCOP3Mem(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 11: \
    tmp = fieldname(insn, 5, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 12: \
    tmp = fieldname(insn, 0, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 13: \
    tmp = fieldname(insn, 0, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 14: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 15: \
    tmp = fieldname(insn, 16, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 6, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 16: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeInsSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 17: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 18: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 19: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 20: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeExtSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 21: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 22: \
    tmp = fieldname(insn, 16, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 23: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 24: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 25: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 26: \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 27: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 28: \
    if (DecodeMemMMImm16(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 29: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTargetMM(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 30: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 31: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 32: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 13, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 33: \
    if (DecodeMemMMImm12(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 34: \
    if (DecodeJumpTargetMM(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 35: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTargetMM(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 36: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 37: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 38: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 2); \
    if (DecodeLSAImm(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 39: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 40: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 41: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 42: \
    tmp = fieldname(insn, 6, 20); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 43: \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 44: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 45: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 46: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeHI32DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 47: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeLO32DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 48: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 2); \
    if (DecodeLSAImm(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 49: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 50: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 51: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 52: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 53: \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 54: \
    if (DecodeJumpTarget(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 55: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 56: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 57: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 58: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 59: \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 60: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 61: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 62: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeCCRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 63: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 64: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 65: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 66: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeCCRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 67: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 68: \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 69: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 70: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 71: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 72: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 73: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 74: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 75: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 76: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 77: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 78: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 79: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 80: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 81: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 82: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 83: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 84: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 85: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 86: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 87: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 88: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 89: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 90: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 91: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 92: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeAFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 93: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 94: \
    tmp = 0; \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 95: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 96: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 97: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 98: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 99: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 100: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 101: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 102: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 103: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 104: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 105: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 106: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 107: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 6); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 108: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 109: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 110: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 6); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 111: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 112: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 113: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 114: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 115: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 116: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 117: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 118: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 119: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 120: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 121: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 122: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 123: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 124: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 125: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 126: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 127: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 128: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 129: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 130: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 131: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 132: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 133: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 134: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 135: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 136: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 137: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 138: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 139: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 140: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSACtrlRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 141: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 142: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 143: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 144: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 145: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSACtrlRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 146: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 147: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 148: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 149: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 150: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 151: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 152: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 153: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 154: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 155: \
    if (DecodeINSVE_DF_4(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 156: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 157: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 158: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128BRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 159: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 160: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 161: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 162: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 163: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 164: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 165: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128HRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 166: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeMSA128DRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeMSA128WRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 167: \
    if (DecodeMSA128Mem(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 168: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeExtSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 169: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeInsSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 170: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 171: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 172: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 173: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 174: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 175: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 176: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 177: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 178: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 179: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 180: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 181: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 182: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 183: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 184: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeDSPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 185: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 186: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 187: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 188: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 189: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 190: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 191: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 20, 6); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 192: \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    if (DecodeACC64DSPRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 193: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeHWRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 194: \
    if (DecodeMem(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 195: \
    if (DecodeCachePref(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 196: \
    if (DecodeFMem(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 197: \
    if (DecodeCOP2Mem(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 198: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 199: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 200: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 201: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 202: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 203: \
    if (DecodeBlezGroupBranch_4(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 204: \
    if (DecodeBgtzGroupBranch_4(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 205: \
    if (DecodeAddiGroupBranch_4(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 206: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 207: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGRCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 208: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 209: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGRCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 210: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 211: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 212: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGRCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 213: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGRCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 214: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeCOP2RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeBranchTarget(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 215: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeCOP2RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 11) << 0); \
    tmp |= (fieldname(insn, 11, 5) << 16); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 216: \
    if (DecodeBlezlGroupBranch_4(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 217: \
    if (DecodeBgtzlGroupBranch_4(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 218: \
    if (DecodeDaddiGroupBranch_4(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 219: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 220: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 221: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 222: \
    tmp = 0; \
    tmp |= (fieldname(insn, 7, 9) << 0); \
    tmp |= (fieldname(insn, 21, 5) << 16); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 16, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 223: \
    if (DecodeSpecial3LlSc(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 224: \
    tmp = fieldname(insn, 0, 26); \
    if (DecodeBranchTarget26(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 225: \
    if (DecodeSimm16(MI, insn, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 226: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 21); \
    if (DecodeBranchTarget21(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 227: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 19); \
    if (DecodeSimm19Lsl2(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 228: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 18); \
    if (DecodeSimm18Lsl3(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 229: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 230: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 231: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 232: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 233: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 3); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 234: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 235: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 236: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 237: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeFCCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 238: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 239: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 240: \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 241: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeFGR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePtrRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 242: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (DecodeSimm16(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 243: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 244: \
    tmp = 0; \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 245: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 10); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 246: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 247: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeExtSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 248: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeInsSize(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
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

FieldFromInstruction(fieldFromInstruction, uint32_t)
DecodeToMCInst(decodeToMCInst, fieldFromInstruction, uint32_t)
DecodeInstruction(decodeInstruction, fieldFromInstruction, decodeToMCInst, uint32_t)
