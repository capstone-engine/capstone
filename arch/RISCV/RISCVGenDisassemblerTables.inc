/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|*  * RISCV Disassembler                                                      *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#include "../../MCInst.h"
#include "../../LEB128.h"

// Helper function for extracting fields from encoded instructions.
#define FieldFromInstruction(fname, InsnType) \
static InsnType fname(InsnType insn, unsigned startBit, unsigned numBits) { \
    InsnType fieldMask; \
    if (numBits == sizeof(InsnType)*8) \
      fieldMask = (InsnType)(-1LL); \
    else \
      fieldMask = (((InsnType)1 << numBits) - 1) << startBit; \
    return (insn & fieldMask) >> startBit; \
}

static const uint8_t DecoderTable32[] = {
						/* 0 */ MCD_OPC_ExtractField, 0, 7,
						// Inst{6-0} ...
						/* 3 */ MCD_OPC_FilterValue, 3, 67, 0,
						// Skip to: 74
						/* 7 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 10 */ MCD_OPC_FilterValue, 0, 4, 0,
						// Skip to: 18
						/* 14 */ MCD_OPC_Decode, 155, 2, 0,
						// Opcode: LB
						/* 18 */ MCD_OPC_FilterValue, 1, 4, 0,
						// Skip to: 26
						/* 22 */ MCD_OPC_Decode, 158, 2, 0,
						// Opcode: LH
						/* 26 */ MCD_OPC_FilterValue, 2, 4, 0,
						// Skip to: 34
						/* 30 */ MCD_OPC_Decode, 169, 2, 0,
						// Opcode: LW
						/* 34 */ MCD_OPC_FilterValue, 3, 8, 0,
						// Skip to: 46
							/* 38 */ MCD_OPC_CheckPredicate, 0, 163, 12,
							// Skip to: 3277
						/* 42 */ MCD_OPC_Decode, 157, 2, 0,
						// Opcode: LD
						/* 46 */ MCD_OPC_FilterValue, 4, 4, 0,
						// Skip to: 54
						/* 50 */ MCD_OPC_Decode, 156, 2, 0,
						// Opcode: LBU
						/* 54 */ MCD_OPC_FilterValue, 5, 4, 0,
						// Skip to: 62
						/* 58 */ MCD_OPC_Decode, 159, 2, 0,
						// Opcode: LHU
							/* 62 */ MCD_OPC_FilterValue, 6, 139, 12,
							// Skip to: 3277
							/* 66 */ MCD_OPC_CheckPredicate, 0, 135, 12,
							// Skip to: 3277
						/* 70 */ MCD_OPC_Decode, 170, 2, 0,
						// Opcode: LWU
						/* 74 */ MCD_OPC_FilterValue, 7, 27, 0,
						// Skip to: 105
						/* 78 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 81 */ MCD_OPC_FilterValue, 2, 8, 0,
						// Skip to: 93
							/* 85 */ MCD_OPC_CheckPredicate, 1, 116, 12,
							// Skip to: 3277
						/* 89 */ MCD_OPC_Decode, 250, 1, 1,
						// Opcode: FLW
							/* 93 */ MCD_OPC_FilterValue, 3, 108, 12,
							// Skip to: 3277
							/* 97 */ MCD_OPC_CheckPredicate, 2, 104, 12,
							// Skip to: 3277
						/* 101 */ MCD_OPC_Decode, 245, 1, 2,
						// Opcode: FLD
							/* 105 */ MCD_OPC_FilterValue, 15, 31, 0,
							// Skip to: 140
						/* 109 */ MCD_OPC_ExtractField, 7, 13,
						// Inst{19-7} ...
							/* 112 */ MCD_OPC_FilterValue, 0, 10, 0,
							// Skip to: 126
							/* 116 */ MCD_OPC_CheckField, 28, 4, 0, 83, 12,
							// Skip to: 3277
						/* 122 */ MCD_OPC_Decode, 241, 1, 3,
						// Opcode: FENCE
							/* 126 */ MCD_OPC_FilterValue, 32, 75, 12,
							// Skip to: 3277
								/* 130 */ MCD_OPC_CheckField, 20, 12, 0, 69, 12,
								// Skip to: 3277
						/* 136 */ MCD_OPC_Decode, 242, 1, 4,
						// Opcode: FENCE_I
							/* 140 */ MCD_OPC_FilterValue, 19, 87, 0,
							// Skip to: 231
						/* 144 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 147 */ MCD_OPC_FilterValue, 0, 3, 0,
						// Skip to: 154
						/* 151 */ MCD_OPC_Decode, 119, 0,
						// Opcode: ADDI
							/* 154 */ MCD_OPC_FilterValue, 1, 10, 0,
							// Skip to: 168
							/* 158 */ MCD_OPC_CheckField, 26, 6, 0, 41, 12,
							// Skip to: 3277
						/* 164 */ MCD_OPC_Decode, 198, 2, 5,
						// Opcode: SLLI
						/* 168 */ MCD_OPC_FilterValue, 2, 4, 0,
						// Skip to: 176
						/* 172 */ MCD_OPC_Decode, 202, 2, 0,
						// Opcode: SLTI
						/* 176 */ MCD_OPC_FilterValue, 3, 4, 0,
						// Skip to: 184
						/* 180 */ MCD_OPC_Decode, 203, 2, 0,
						// Opcode: SLTIU
						/* 184 */ MCD_OPC_FilterValue, 4, 4, 0,
						// Skip to: 192
						/* 188 */ MCD_OPC_Decode, 220, 2, 0,
						// Opcode: XORI
							/* 192 */ MCD_OPC_FilterValue, 5, 19, 0,
							// Skip to: 215
						/* 196 */ MCD_OPC_ExtractField, 26, 6,
						// Inst{31-26} ...
						/* 199 */ MCD_OPC_FilterValue, 0, 4, 0,
						// Skip to: 207
						/* 203 */ MCD_OPC_Decode, 210, 2, 5,
						// Opcode: SRLI
							/* 207 */ MCD_OPC_FilterValue, 16, 250, 11,
							// Skip to: 3277
						/* 211 */ MCD_OPC_Decode, 206, 2, 5,
						// Opcode: SRAI
						/* 215 */ MCD_OPC_FilterValue, 6, 4, 0,
						// Skip to: 223
						/* 219 */ MCD_OPC_Decode, 177, 2, 0,
						// Opcode: ORI
							/* 223 */ MCD_OPC_FilterValue, 7, 234, 11,
							// Skip to: 3277
						/* 227 */ MCD_OPC_Decode, 197, 1, 0,
						// Opcode: ANDI
							/* 231 */ MCD_OPC_FilterValue, 23, 4, 0,
							// Skip to: 239
						/* 235 */ MCD_OPC_Decode, 198, 1, 6,
						// Opcode: AUIPC
							/* 239 */ MCD_OPC_FilterValue, 27, 63, 0,
							// Skip to: 306
						/* 243 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 246 */ MCD_OPC_FilterValue, 0, 7, 0,
						// Skip to: 257
							/* 250 */ MCD_OPC_CheckPredicate, 0, 207, 11,
							// Skip to: 3277
						/* 254 */ MCD_OPC_Decode, 120, 0,
						// Opcode: ADDIW
							/* 257 */ MCD_OPC_FilterValue, 1, 14, 0,
							// Skip to: 275
							/* 261 */ MCD_OPC_CheckPredicate, 0, 196, 11,
							// Skip to: 3277
								/* 265 */ MCD_OPC_CheckField, 25, 7, 0, 190, 11,
								// Skip to: 3277
						/* 271 */ MCD_OPC_Decode, 199, 2, 7,
						// Opcode: SLLIW
							/* 275 */ MCD_OPC_FilterValue, 5, 182, 11,
							// Skip to: 3277
						/* 279 */ MCD_OPC_ExtractField, 25, 7,
						// Inst{31-25} ...
						/* 282 */ MCD_OPC_FilterValue, 0, 8, 0,
						// Skip to: 294
							/* 286 */ MCD_OPC_CheckPredicate, 0, 171, 11,
							// Skip to: 3277
						/* 290 */ MCD_OPC_Decode, 211, 2, 7,
						// Opcode: SRLIW
							/* 294 */ MCD_OPC_FilterValue, 32, 163, 11,
							// Skip to: 3277
							/* 298 */ MCD_OPC_CheckPredicate, 0, 159, 11,
							// Skip to: 3277
						/* 302 */ MCD_OPC_Decode, 207, 2, 7,
						// Opcode: SRAIW
							/* 306 */ MCD_OPC_FilterValue, 35, 39, 0,
							// Skip to: 349
						/* 310 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 313 */ MCD_OPC_FilterValue, 0, 4, 0,
						// Skip to: 321
						/* 317 */ MCD_OPC_Decode, 186, 2, 8,
						// Opcode: SB
						/* 321 */ MCD_OPC_FilterValue, 1, 4, 0,
						// Skip to: 329
						/* 325 */ MCD_OPC_Decode, 196, 2, 8,
						// Opcode: SH
						/* 329 */ MCD_OPC_FilterValue, 2, 4, 0,
						// Skip to: 337
						/* 333 */ MCD_OPC_Decode, 215, 2, 8,
						// Opcode: SW
							/* 337 */ MCD_OPC_FilterValue, 3, 120, 11,
							// Skip to: 3277
							/* 341 */ MCD_OPC_CheckPredicate, 0, 116, 11,
							// Skip to: 3277
						/* 345 */ MCD_OPC_Decode, 195, 2, 8,
						// Opcode: SD
							/* 349 */ MCD_OPC_FilterValue, 39, 27, 0,
							// Skip to: 380
						/* 353 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 356 */ MCD_OPC_FilterValue, 2, 8, 0,
						// Skip to: 368
							/* 360 */ MCD_OPC_CheckPredicate, 1, 97, 11,
							// Skip to: 3277
						/* 364 */ MCD_OPC_Decode, 152, 2, 9,
						// Opcode: FSW
							/* 368 */ MCD_OPC_FilterValue, 3, 89, 11,
							// Skip to: 3277
							/* 372 */ MCD_OPC_CheckPredicate, 2, 85, 11,
							// Skip to: 3277
						/* 376 */ MCD_OPC_Decode, 141, 2, 10,
						// Opcode: FSD
							/* 380 */ MCD_OPC_FilterValue, 47, 131, 5,
							// Skip to: 1795
						/* 384 */ MCD_OPC_ExtractField, 25, 7,
						// Inst{31-25} ...
							/* 387 */ MCD_OPC_FilterValue, 0, 26, 0,
							// Skip to: 417
						/* 391 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 394 */ MCD_OPC_FilterValue, 2, 8, 0,
						// Skip to: 406
							/* 398 */ MCD_OPC_CheckPredicate, 3, 59, 11,
							// Skip to: 3277
						/* 402 */ MCD_OPC_Decode, 128, 1, 11,
						// Opcode: AMOADD_W
							/* 406 */ MCD_OPC_FilterValue, 3, 51, 11,
							// Skip to: 3277
							/* 410 */ MCD_OPC_CheckPredicate, 4, 47, 11,
							// Skip to: 3277
						/* 414 */ MCD_OPC_Decode, 124, 11,
						// Opcode: AMOADD_D
							/* 417 */ MCD_OPC_FilterValue, 1, 26, 0,
							// Skip to: 447
						/* 421 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 424 */ MCD_OPC_FilterValue, 2, 8, 0,
						// Skip to: 436
							/* 428 */ MCD_OPC_CheckPredicate, 3, 29, 11,
							// Skip to: 3277
						/* 432 */ MCD_OPC_Decode, 131, 1, 11,
						// Opcode: AMOADD_W_RL
							/* 436 */ MCD_OPC_FilterValue, 3, 21, 11,
							// Skip to: 3277
							/* 440 */ MCD_OPC_CheckPredicate, 4, 17, 11,
							// Skip to: 3277
						/* 444 */ MCD_OPC_Decode, 127, 11,
						// Opcode: AMOADD_D_RL
							/* 447 */ MCD_OPC_FilterValue, 2, 26, 0,
							// Skip to: 477
						/* 451 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 454 */ MCD_OPC_FilterValue, 2, 8, 0,
						// Skip to: 466
							/* 458 */ MCD_OPC_CheckPredicate, 3, 255, 10,
							// Skip to: 3277
						/* 462 */ MCD_OPC_Decode, 129, 1, 11,
						// Opcode: AMOADD_W_AQ
							/* 466 */ MCD_OPC_FilterValue, 3, 247, 10,
							// Skip to: 3277
							/* 470 */ MCD_OPC_CheckPredicate, 4, 243, 10,
							// Skip to: 3277
						/* 474 */ MCD_OPC_Decode, 125, 11,
						// Opcode: AMOADD_D_AQ
							/* 477 */ MCD_OPC_FilterValue, 3, 26, 0,
							// Skip to: 507
						/* 481 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 484 */ MCD_OPC_FilterValue, 2, 8, 0,
						// Skip to: 496
							/* 488 */ MCD_OPC_CheckPredicate, 3, 225, 10,
							// Skip to: 3277
						/* 492 */ MCD_OPC_Decode, 130, 1, 11,
						// Opcode: AMOADD_W_AQ_RL
							/* 496 */ MCD_OPC_FilterValue, 3, 217, 10,
							// Skip to: 3277
							/* 500 */ MCD_OPC_CheckPredicate, 4, 213, 10,
							// Skip to: 3277
						/* 504 */ MCD_OPC_Decode, 126, 11,
						// Opcode: AMOADD_D_AQ_RL
							/* 507 */ MCD_OPC_FilterValue, 4, 27, 0,
							// Skip to: 538
						/* 511 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 514 */ MCD_OPC_FilterValue, 2, 8, 0,
						// Skip to: 526
							/* 518 */ MCD_OPC_CheckPredicate, 3, 195, 10,
							// Skip to: 3277
						/* 522 */ MCD_OPC_Decode, 184, 1, 11,
						// Opcode: AMOSWAP_W
							/* 526 */ MCD_OPC_FilterValue, 3, 187, 10,
							// Skip to: 3277
							/* 530 */ MCD_OPC_CheckPredicate, 4, 183, 10,
							// Skip to: 3277
						/* 534 */ MCD_OPC_Decode, 180, 1, 11,
						// Opcode: AMOSWAP_D
							/* 538 */ MCD_OPC_FilterValue, 5, 27, 0,
							// Skip to: 569
						/* 542 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 545 */ MCD_OPC_FilterValue, 2, 8, 0,
						// Skip to: 557
							/* 549 */ MCD_OPC_CheckPredicate, 3, 164, 10,
							// Skip to: 3277
						/* 553 */ MCD_OPC_Decode, 187, 1, 11,
						// Opcode: AMOSWAP_W_RL
							/* 557 */ MCD_OPC_FilterValue, 3, 156, 10,
							// Skip to: 3277
							/* 561 */ MCD_OPC_CheckPredicate, 4, 152, 10,
							// Skip to: 3277
						/* 565 */ MCD_OPC_Decode, 183, 1, 11,
						// Opcode: AMOSWAP_D_RL
							/* 569 */ MCD_OPC_FilterValue, 6, 27, 0,
							// Skip to: 600
						/* 573 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 576 */ MCD_OPC_FilterValue, 2, 8, 0,
						// Skip to: 588
							/* 580 */ MCD_OPC_CheckPredicate, 3, 133, 10,
							// Skip to: 3277
						/* 584 */ MCD_OPC_Decode, 185, 1, 11,
						// Opcode: AMOSWAP_W_AQ
							/* 588 */ MCD_OPC_FilterValue, 3, 125, 10,
							// Skip to: 3277
							/* 592 */ MCD_OPC_CheckPredicate, 4, 121, 10,
							// Skip to: 3277
						/* 596 */ MCD_OPC_Decode, 181, 1, 11,
						// Opcode: AMOSWAP_D_AQ
							/* 600 */ MCD_OPC_FilterValue, 7, 27, 0,
							// Skip to: 631
						/* 604 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 607 */ MCD_OPC_FilterValue, 2, 8, 0,
						// Skip to: 619
							/* 611 */ MCD_OPC_CheckPredicate, 3, 102, 10,
							// Skip to: 3277
						/* 615 */ MCD_OPC_Decode, 186, 1, 11,
						// Opcode: AMOSWAP_W_AQ_RL
							/* 619 */ MCD_OPC_FilterValue, 3, 94, 10,
							// Skip to: 3277
							/* 623 */ MCD_OPC_CheckPredicate, 4, 90, 10,
							// Skip to: 3277
						/* 627 */ MCD_OPC_Decode, 182, 1, 11,
						// Opcode: AMOSWAP_D_AQ_RL
							/* 631 */ MCD_OPC_FilterValue, 8, 39, 0,
							// Skip to: 674
						/* 635 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 638 */ MCD_OPC_FilterValue, 2, 14, 0,
							// Skip to: 656
							/* 642 */ MCD_OPC_CheckPredicate, 3, 71, 10,
							// Skip to: 3277
							/* 646 */ MCD_OPC_CheckField, 20, 5, 0, 65, 10,
							// Skip to: 3277
						/* 652 */ MCD_OPC_Decode, 164, 2, 12,
						// Opcode: LR_W
							/* 656 */ MCD_OPC_FilterValue, 3, 57, 10,
							// Skip to: 3277
							/* 660 */ MCD_OPC_CheckPredicate, 4, 53, 10,
							// Skip to: 3277
							/* 664 */ MCD_OPC_CheckField, 20, 5, 0, 47, 10,
							// Skip to: 3277
						/* 670 */ MCD_OPC_Decode, 160, 2, 12,
						// Opcode: LR_D
							/* 674 */ MCD_OPC_FilterValue, 9, 39, 0,
							// Skip to: 717
						/* 678 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 681 */ MCD_OPC_FilterValue, 2, 14, 0,
							// Skip to: 699
							/* 685 */ MCD_OPC_CheckPredicate, 3, 28, 10,
							// Skip to: 3277
							/* 689 */ MCD_OPC_CheckField, 20, 5, 0, 22, 10,
							// Skip to: 3277
						/* 695 */ MCD_OPC_Decode, 167, 2, 12,
						// Opcode: LR_W_RL
							/* 699 */ MCD_OPC_FilterValue, 3, 14, 10,
							// Skip to: 3277
							/* 703 */ MCD_OPC_CheckPredicate, 4, 10, 10,
							// Skip to: 3277
							/* 707 */ MCD_OPC_CheckField, 20, 5, 0, 4, 10,
							// Skip to: 3277
						/* 713 */ MCD_OPC_Decode, 163, 2, 12,
						// Opcode: LR_D_RL
							/* 717 */ MCD_OPC_FilterValue, 10, 39, 0,
							// Skip to: 760
						/* 721 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 724 */ MCD_OPC_FilterValue, 2, 14, 0,
							// Skip to: 742
							/* 728 */ MCD_OPC_CheckPredicate, 3, 241, 9,
							// Skip to: 3277
							/* 732 */ MCD_OPC_CheckField, 20, 5, 0, 235, 9,
							// Skip to: 3277
						/* 738 */ MCD_OPC_Decode, 165, 2, 12,
						// Opcode: LR_W_AQ
							/* 742 */ MCD_OPC_FilterValue, 3, 227, 9,
							// Skip to: 3277
							/* 746 */ MCD_OPC_CheckPredicate, 4, 223, 9,
							// Skip to: 3277
							/* 750 */ MCD_OPC_CheckField, 20, 5, 0, 217, 9,
							// Skip to: 3277
						/* 756 */ MCD_OPC_Decode, 161, 2, 12,
						// Opcode: LR_D_AQ
							/* 760 */ MCD_OPC_FilterValue, 11, 39, 0,
							// Skip to: 803
						/* 764 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 767 */ MCD_OPC_FilterValue, 2, 14, 0,
							// Skip to: 785
							/* 771 */ MCD_OPC_CheckPredicate, 3, 198, 9,
							// Skip to: 3277
							/* 775 */ MCD_OPC_CheckField, 20, 5, 0, 192, 9,
							// Skip to: 3277
						/* 781 */ MCD_OPC_Decode, 166, 2, 12,
						// Opcode: LR_W_AQ_RL
							/* 785 */ MCD_OPC_FilterValue, 3, 184, 9,
							// Skip to: 3277
							/* 789 */ MCD_OPC_CheckPredicate, 4, 180, 9,
							// Skip to: 3277
							/* 793 */ MCD_OPC_CheckField, 20, 5, 0, 174, 9,
							// Skip to: 3277
						/* 799 */ MCD_OPC_Decode, 162, 2, 12,
						// Opcode: LR_D_AQ_RL
							/* 803 */ MCD_OPC_FilterValue, 12, 27, 0,
							// Skip to: 834
						/* 807 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 810 */ MCD_OPC_FilterValue, 2, 8, 0,
						// Skip to: 822
							/* 814 */ MCD_OPC_CheckPredicate, 3, 155, 9,
							// Skip to: 3277
						/* 818 */ MCD_OPC_Decode, 191, 2, 11,
						// Opcode: SC_W
							/* 822 */ MCD_OPC_FilterValue, 3, 147, 9,
							// Skip to: 3277
							/* 826 */ MCD_OPC_CheckPredicate, 4, 143, 9,
							// Skip to: 3277
						/* 830 */ MCD_OPC_Decode, 187, 2, 11,
						// Opcode: SC_D
							/* 834 */ MCD_OPC_FilterValue, 13, 27, 0,
							// Skip to: 865
						/* 838 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 841 */ MCD_OPC_FilterValue, 2, 8, 0,
						// Skip to: 853
							/* 845 */ MCD_OPC_CheckPredicate, 3, 124, 9,
							// Skip to: 3277
						/* 849 */ MCD_OPC_Decode, 194, 2, 11,
						// Opcode: SC_W_RL
							/* 853 */ MCD_OPC_FilterValue, 3, 116, 9,
							// Skip to: 3277
							/* 857 */ MCD_OPC_CheckPredicate, 4, 112, 9,
							// Skip to: 3277
						/* 861 */ MCD_OPC_Decode, 190, 2, 11,
						// Opcode: SC_D_RL
							/* 865 */ MCD_OPC_FilterValue, 14, 27, 0,
							// Skip to: 896
						/* 869 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 872 */ MCD_OPC_FilterValue, 2, 8, 0,
						// Skip to: 884
							/* 876 */ MCD_OPC_CheckPredicate, 3, 93, 9,
							// Skip to: 3277
						/* 880 */ MCD_OPC_Decode, 192, 2, 11,
						// Opcode: SC_W_AQ
							/* 884 */ MCD_OPC_FilterValue, 3, 85, 9,
							// Skip to: 3277
							/* 888 */ MCD_OPC_CheckPredicate, 4, 81, 9,
							// Skip to: 3277
						/* 892 */ MCD_OPC_Decode, 188, 2, 11,
						// Opcode: SC_D_AQ
							/* 896 */ MCD_OPC_FilterValue, 15, 27, 0,
							// Skip to: 927
						/* 900 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 903 */ MCD_OPC_FilterValue, 2, 8, 0,
						// Skip to: 915
							/* 907 */ MCD_OPC_CheckPredicate, 3, 62, 9,
							// Skip to: 3277
						/* 911 */ MCD_OPC_Decode, 193, 2, 11,
						// Opcode: SC_W_AQ_RL
							/* 915 */ MCD_OPC_FilterValue, 3, 54, 9,
							// Skip to: 3277
							/* 919 */ MCD_OPC_CheckPredicate, 4, 50, 9,
							// Skip to: 3277
						/* 923 */ MCD_OPC_Decode, 189, 2, 11,
						// Opcode: SC_D_AQ_RL
							/* 927 */ MCD_OPC_FilterValue, 16, 27, 0,
							// Skip to: 958
						/* 931 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 934 */ MCD_OPC_FilterValue, 2, 8, 0,
						// Skip to: 946
							/* 938 */ MCD_OPC_CheckPredicate, 3, 31, 9,
							// Skip to: 3277
						/* 942 */ MCD_OPC_Decode, 192, 1, 11,
						// Opcode: AMOXOR_W
							/* 946 */ MCD_OPC_FilterValue, 3, 23, 9,
							// Skip to: 3277
							/* 950 */ MCD_OPC_CheckPredicate, 4, 19, 9,
							// Skip to: 3277
						/* 954 */ MCD_OPC_Decode, 188, 1, 11,
						// Opcode: AMOXOR_D
							/* 958 */ MCD_OPC_FilterValue, 17, 27, 0,
							// Skip to: 989
						/* 962 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 965 */ MCD_OPC_FilterValue, 2, 8, 0,
						// Skip to: 977
							/* 969 */ MCD_OPC_CheckPredicate, 3, 0, 9,
							// Skip to: 3277
						/* 973 */ MCD_OPC_Decode, 195, 1, 11,
						// Opcode: AMOXOR_W_RL
							/* 977 */ MCD_OPC_FilterValue, 3, 248, 8,
							// Skip to: 3277
							/* 981 */ MCD_OPC_CheckPredicate, 4, 244, 8,
							// Skip to: 3277
						/* 985 */ MCD_OPC_Decode, 191, 1, 11,
						// Opcode: AMOXOR_D_RL
							/* 989 */ MCD_OPC_FilterValue, 18, 27, 0,
							// Skip to: 1020
						/* 993 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
						/* 996 */ MCD_OPC_FilterValue, 2, 8, 0,
						// Skip to: 1008
							/* 1000 */ MCD_OPC_CheckPredicate, 3, 225, 8,
							// Skip to: 3277
						/* 1004 */ MCD_OPC_Decode, 193, 1, 11,
						// Opcode: AMOXOR_W_AQ
							/* 1008 */ MCD_OPC_FilterValue, 3, 217, 8,
							// Skip to: 3277
							/* 1012 */ MCD_OPC_CheckPredicate, 4, 213, 8,
							// Skip to: 3277
						/* 1016 */ MCD_OPC_Decode, 189, 1, 11,
						// Opcode: AMOXOR_D_AQ
							/* 1020 */ MCD_OPC_FilterValue, 19, 27, 0,
							// Skip to: 1051
						/* 1024 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1027 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1039
							/* 1031 */ MCD_OPC_CheckPredicate, 3, 194, 8,
							// Skip to: 3277
						/* 1035 */ MCD_OPC_Decode, 194, 1, 11,
						// Opcode: AMOXOR_W_AQ_RL
							/* 1039 */ MCD_OPC_FilterValue, 3, 186, 8,
							// Skip to: 3277
							/* 1043 */ MCD_OPC_CheckPredicate, 4, 182, 8,
							// Skip to: 3277
						/* 1047 */ MCD_OPC_Decode, 190, 1, 11,
						// Opcode: AMOXOR_D_AQ_RL
							/* 1051 */ MCD_OPC_FilterValue, 32, 27, 0,
							// Skip to: 1082
						/* 1055 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1058 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1070
							/* 1062 */ MCD_OPC_CheckPredicate, 3, 163, 8,
							// Skip to: 3277
						/* 1066 */ MCD_OPC_Decode, 176, 1, 11,
						// Opcode: AMOOR_W
							/* 1070 */ MCD_OPC_FilterValue, 3, 155, 8,
							// Skip to: 3277
							/* 1074 */ MCD_OPC_CheckPredicate, 4, 151, 8,
							// Skip to: 3277
						/* 1078 */ MCD_OPC_Decode, 172, 1, 11,
						// Opcode: AMOOR_D
							/* 1082 */ MCD_OPC_FilterValue, 33, 27, 0,
							// Skip to: 1113
						/* 1086 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1089 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1101
							/* 1093 */ MCD_OPC_CheckPredicate, 3, 132, 8,
							// Skip to: 3277
						/* 1097 */ MCD_OPC_Decode, 179, 1, 11,
						// Opcode: AMOOR_W_RL
							/* 1101 */ MCD_OPC_FilterValue, 3, 124, 8,
							// Skip to: 3277
							/* 1105 */ MCD_OPC_CheckPredicate, 4, 120, 8,
							// Skip to: 3277
						/* 1109 */ MCD_OPC_Decode, 175, 1, 11,
						// Opcode: AMOOR_D_RL
							/* 1113 */ MCD_OPC_FilterValue, 34, 27, 0,
							// Skip to: 1144
						/* 1117 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1120 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1132
							/* 1124 */ MCD_OPC_CheckPredicate, 3, 101, 8,
							// Skip to: 3277
						/* 1128 */ MCD_OPC_Decode, 177, 1, 11,
						// Opcode: AMOOR_W_AQ
							/* 1132 */ MCD_OPC_FilterValue, 3, 93, 8,
							// Skip to: 3277
							/* 1136 */ MCD_OPC_CheckPredicate, 4, 89, 8,
							// Skip to: 3277
						/* 1140 */ MCD_OPC_Decode, 173, 1, 11,
						// Opcode: AMOOR_D_AQ
							/* 1144 */ MCD_OPC_FilterValue, 35, 27, 0,
							// Skip to: 1175
						/* 1148 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1151 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1163
							/* 1155 */ MCD_OPC_CheckPredicate, 3, 70, 8,
							// Skip to: 3277
						/* 1159 */ MCD_OPC_Decode, 178, 1, 11,
						// Opcode: AMOOR_W_AQ_RL
							/* 1163 */ MCD_OPC_FilterValue, 3, 62, 8,
							// Skip to: 3277
							/* 1167 */ MCD_OPC_CheckPredicate, 4, 58, 8,
							// Skip to: 3277
						/* 1171 */ MCD_OPC_Decode, 174, 1, 11,
						// Opcode: AMOOR_D_AQ_RL
							/* 1175 */ MCD_OPC_FilterValue, 48, 27, 0,
							// Skip to: 1206
						/* 1179 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1182 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1194
							/* 1186 */ MCD_OPC_CheckPredicate, 3, 39, 8,
							// Skip to: 3277
						/* 1190 */ MCD_OPC_Decode, 136, 1, 11,
						// Opcode: AMOAND_W
							/* 1194 */ MCD_OPC_FilterValue, 3, 31, 8,
							// Skip to: 3277
							/* 1198 */ MCD_OPC_CheckPredicate, 4, 27, 8,
							// Skip to: 3277
						/* 1202 */ MCD_OPC_Decode, 132, 1, 11,
						// Opcode: AMOAND_D
							/* 1206 */ MCD_OPC_FilterValue, 49, 27, 0,
							// Skip to: 1237
						/* 1210 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1213 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1225
							/* 1217 */ MCD_OPC_CheckPredicate, 3, 8, 8,
							// Skip to: 3277
						/* 1221 */ MCD_OPC_Decode, 139, 1, 11,
						// Opcode: AMOAND_W_RL
							/* 1225 */ MCD_OPC_FilterValue, 3, 0, 8,
							// Skip to: 3277
							/* 1229 */ MCD_OPC_CheckPredicate, 4, 252, 7,
							// Skip to: 3277
						/* 1233 */ MCD_OPC_Decode, 135, 1, 11,
						// Opcode: AMOAND_D_RL
							/* 1237 */ MCD_OPC_FilterValue, 50, 27, 0,
							// Skip to: 1268
						/* 1241 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1244 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1256
							/* 1248 */ MCD_OPC_CheckPredicate, 3, 233, 7,
							// Skip to: 3277
						/* 1252 */ MCD_OPC_Decode, 137, 1, 11,
						// Opcode: AMOAND_W_AQ
							/* 1256 */ MCD_OPC_FilterValue, 3, 225, 7,
							// Skip to: 3277
							/* 1260 */ MCD_OPC_CheckPredicate, 4, 221, 7,
							// Skip to: 3277
						/* 1264 */ MCD_OPC_Decode, 133, 1, 11,
						// Opcode: AMOAND_D_AQ
							/* 1268 */ MCD_OPC_FilterValue, 51, 27, 0,
							// Skip to: 1299
						/* 1272 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1275 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1287
							/* 1279 */ MCD_OPC_CheckPredicate, 3, 202, 7,
							// Skip to: 3277
						/* 1283 */ MCD_OPC_Decode, 138, 1, 11,
						// Opcode: AMOAND_W_AQ_RL
							/* 1287 */ MCD_OPC_FilterValue, 3, 194, 7,
							// Skip to: 3277
							/* 1291 */ MCD_OPC_CheckPredicate, 4, 190, 7,
							// Skip to: 3277
						/* 1295 */ MCD_OPC_Decode, 134, 1, 11,
						// Opcode: AMOAND_D_AQ_RL
							/* 1299 */ MCD_OPC_FilterValue, 64, 27, 0,
							// Skip to: 1330
						/* 1303 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1306 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1318
							/* 1310 */ MCD_OPC_CheckPredicate, 3, 171, 7,
							// Skip to: 3277
						/* 1314 */ MCD_OPC_Decode, 168, 1, 11,
						// Opcode: AMOMIN_W
							/* 1318 */ MCD_OPC_FilterValue, 3, 163, 7,
							// Skip to: 3277
							/* 1322 */ MCD_OPC_CheckPredicate, 4, 159, 7,
							// Skip to: 3277
						/* 1326 */ MCD_OPC_Decode, 164, 1, 11,
						// Opcode: AMOMIN_D
							/* 1330 */ MCD_OPC_FilterValue, 65, 27, 0,
							// Skip to: 1361
						/* 1334 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1337 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1349
							/* 1341 */ MCD_OPC_CheckPredicate, 3, 140, 7,
							// Skip to: 3277
						/* 1345 */ MCD_OPC_Decode, 171, 1, 11,
						// Opcode: AMOMIN_W_RL
							/* 1349 */ MCD_OPC_FilterValue, 3, 132, 7,
							// Skip to: 3277
							/* 1353 */ MCD_OPC_CheckPredicate, 4, 128, 7,
							// Skip to: 3277
						/* 1357 */ MCD_OPC_Decode, 167, 1, 11,
						// Opcode: AMOMIN_D_RL
							/* 1361 */ MCD_OPC_FilterValue, 66, 27, 0,
							// Skip to: 1392
						/* 1365 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1368 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1380
							/* 1372 */ MCD_OPC_CheckPredicate, 3, 109, 7,
							// Skip to: 3277
						/* 1376 */ MCD_OPC_Decode, 169, 1, 11,
						// Opcode: AMOMIN_W_AQ
							/* 1380 */ MCD_OPC_FilterValue, 3, 101, 7,
							// Skip to: 3277
							/* 1384 */ MCD_OPC_CheckPredicate, 4, 97, 7,
							// Skip to: 3277
						/* 1388 */ MCD_OPC_Decode, 165, 1, 11,
						// Opcode: AMOMIN_D_AQ
							/* 1392 */ MCD_OPC_FilterValue, 67, 27, 0,
							// Skip to: 1423
						/* 1396 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1399 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1411
							/* 1403 */ MCD_OPC_CheckPredicate, 3, 78, 7,
							// Skip to: 3277
						/* 1407 */ MCD_OPC_Decode, 170, 1, 11,
						// Opcode: AMOMIN_W_AQ_RL
							/* 1411 */ MCD_OPC_FilterValue, 3, 70, 7,
							// Skip to: 3277
							/* 1415 */ MCD_OPC_CheckPredicate, 4, 66, 7,
							// Skip to: 3277
						/* 1419 */ MCD_OPC_Decode, 166, 1, 11,
						// Opcode: AMOMIN_D_AQ_RL
							/* 1423 */ MCD_OPC_FilterValue, 80, 27, 0,
							// Skip to: 1454
						/* 1427 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1430 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1442
							/* 1434 */ MCD_OPC_CheckPredicate, 3, 47, 7,
							// Skip to: 3277
						/* 1438 */ MCD_OPC_Decode, 152, 1, 11,
						// Opcode: AMOMAX_W
							/* 1442 */ MCD_OPC_FilterValue, 3, 39, 7,
							// Skip to: 3277
							/* 1446 */ MCD_OPC_CheckPredicate, 4, 35, 7,
							// Skip to: 3277
						/* 1450 */ MCD_OPC_Decode, 148, 1, 11,
						// Opcode: AMOMAX_D
							/* 1454 */ MCD_OPC_FilterValue, 81, 27, 0,
							// Skip to: 1485
						/* 1458 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1461 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1473
							/* 1465 */ MCD_OPC_CheckPredicate, 3, 16, 7,
							// Skip to: 3277
						/* 1469 */ MCD_OPC_Decode, 155, 1, 11,
						// Opcode: AMOMAX_W_RL
							/* 1473 */ MCD_OPC_FilterValue, 3, 8, 7,
							// Skip to: 3277
							/* 1477 */ MCD_OPC_CheckPredicate, 4, 4, 7,
							// Skip to: 3277
						/* 1481 */ MCD_OPC_Decode, 151, 1, 11,
						// Opcode: AMOMAX_D_RL
							/* 1485 */ MCD_OPC_FilterValue, 82, 27, 0,
							// Skip to: 1516
						/* 1489 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1492 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1504
							/* 1496 */ MCD_OPC_CheckPredicate, 3, 241, 6,
							// Skip to: 3277
						/* 1500 */ MCD_OPC_Decode, 153, 1, 11,
						// Opcode: AMOMAX_W_AQ
							/* 1504 */ MCD_OPC_FilterValue, 3, 233, 6,
							// Skip to: 3277
							/* 1508 */ MCD_OPC_CheckPredicate, 4, 229, 6,
							// Skip to: 3277
						/* 1512 */ MCD_OPC_Decode, 149, 1, 11,
						// Opcode: AMOMAX_D_AQ
							/* 1516 */ MCD_OPC_FilterValue, 83, 27, 0,
							// Skip to: 1547
						/* 1520 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1523 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1535
							/* 1527 */ MCD_OPC_CheckPredicate, 3, 210, 6,
							// Skip to: 3277
						/* 1531 */ MCD_OPC_Decode, 154, 1, 11,
						// Opcode: AMOMAX_W_AQ_RL
							/* 1535 */ MCD_OPC_FilterValue, 3, 202, 6,
							// Skip to: 3277
							/* 1539 */ MCD_OPC_CheckPredicate, 4, 198, 6,
							// Skip to: 3277
						/* 1543 */ MCD_OPC_Decode, 150, 1, 11,
						// Opcode: AMOMAX_D_AQ_RL
							/* 1547 */ MCD_OPC_FilterValue, 96, 27, 0,
							// Skip to: 1578
						/* 1551 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1554 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1566
							/* 1558 */ MCD_OPC_CheckPredicate, 3, 179, 6,
							// Skip to: 3277
						/* 1562 */ MCD_OPC_Decode, 160, 1, 11,
						// Opcode: AMOMINU_W
							/* 1566 */ MCD_OPC_FilterValue, 3, 171, 6,
							// Skip to: 3277
							/* 1570 */ MCD_OPC_CheckPredicate, 4, 167, 6,
							// Skip to: 3277
						/* 1574 */ MCD_OPC_Decode, 156, 1, 11,
						// Opcode: AMOMINU_D
							/* 1578 */ MCD_OPC_FilterValue, 97, 27, 0,
							// Skip to: 1609
						/* 1582 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1585 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1597
							/* 1589 */ MCD_OPC_CheckPredicate, 3, 148, 6,
							// Skip to: 3277
						/* 1593 */ MCD_OPC_Decode, 163, 1, 11,
						// Opcode: AMOMINU_W_RL
							/* 1597 */ MCD_OPC_FilterValue, 3, 140, 6,
							// Skip to: 3277
							/* 1601 */ MCD_OPC_CheckPredicate, 4, 136, 6,
							// Skip to: 3277
						/* 1605 */ MCD_OPC_Decode, 159, 1, 11,
						// Opcode: AMOMINU_D_RL
							/* 1609 */ MCD_OPC_FilterValue, 98, 27, 0,
							// Skip to: 1640
						/* 1613 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1616 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1628
							/* 1620 */ MCD_OPC_CheckPredicate, 3, 117, 6,
							// Skip to: 3277
						/* 1624 */ MCD_OPC_Decode, 161, 1, 11,
						// Opcode: AMOMINU_W_AQ
							/* 1628 */ MCD_OPC_FilterValue, 3, 109, 6,
							// Skip to: 3277
							/* 1632 */ MCD_OPC_CheckPredicate, 4, 105, 6,
							// Skip to: 3277
						/* 1636 */ MCD_OPC_Decode, 157, 1, 11,
						// Opcode: AMOMINU_D_AQ
							/* 1640 */ MCD_OPC_FilterValue, 99, 27, 0,
							// Skip to: 1671
						/* 1644 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1647 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1659
							/* 1651 */ MCD_OPC_CheckPredicate, 3, 86, 6,
							// Skip to: 3277
						/* 1655 */ MCD_OPC_Decode, 162, 1, 11,
						// Opcode: AMOMINU_W_AQ_RL
							/* 1659 */ MCD_OPC_FilterValue, 3, 78, 6,
							// Skip to: 3277
							/* 1663 */ MCD_OPC_CheckPredicate, 4, 74, 6,
							// Skip to: 3277
						/* 1667 */ MCD_OPC_Decode, 158, 1, 11,
						// Opcode: AMOMINU_D_AQ_RL
							/* 1671 */ MCD_OPC_FilterValue, 112, 27, 0,
							// Skip to: 1702
						/* 1675 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1678 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1690
							/* 1682 */ MCD_OPC_CheckPredicate, 3, 55, 6,
							// Skip to: 3277
						/* 1686 */ MCD_OPC_Decode, 144, 1, 11,
						// Opcode: AMOMAXU_W
							/* 1690 */ MCD_OPC_FilterValue, 3, 47, 6,
							// Skip to: 3277
							/* 1694 */ MCD_OPC_CheckPredicate, 4, 43, 6,
							// Skip to: 3277
						/* 1698 */ MCD_OPC_Decode, 140, 1, 11,
						// Opcode: AMOMAXU_D
							/* 1702 */ MCD_OPC_FilterValue, 113, 27, 0,
							// Skip to: 1733
						/* 1706 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1709 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1721
							/* 1713 */ MCD_OPC_CheckPredicate, 3, 24, 6,
							// Skip to: 3277
						/* 1717 */ MCD_OPC_Decode, 147, 1, 11,
						// Opcode: AMOMAXU_W_RL
							/* 1721 */ MCD_OPC_FilterValue, 3, 16, 6,
							// Skip to: 3277
							/* 1725 */ MCD_OPC_CheckPredicate, 4, 12, 6,
							// Skip to: 3277
						/* 1729 */ MCD_OPC_Decode, 143, 1, 11,
						// Opcode: AMOMAXU_D_RL
							/* 1733 */ MCD_OPC_FilterValue, 114, 27, 0,
							// Skip to: 1764
						/* 1737 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1740 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1752
							/* 1744 */ MCD_OPC_CheckPredicate, 3, 249, 5,
							// Skip to: 3277
						/* 1748 */ MCD_OPC_Decode, 145, 1, 11,
						// Opcode: AMOMAXU_W_AQ
							/* 1752 */ MCD_OPC_FilterValue, 3, 241, 5,
							// Skip to: 3277
							/* 1756 */ MCD_OPC_CheckPredicate, 4, 237, 5,
							// Skip to: 3277
						/* 1760 */ MCD_OPC_Decode, 141, 1, 11,
						// Opcode: AMOMAXU_D_AQ
							/* 1764 */ MCD_OPC_FilterValue, 115, 229, 5,
							// Skip to: 3277
						/* 1768 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1771 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 1783
							/* 1775 */ MCD_OPC_CheckPredicate, 3, 218, 5,
							// Skip to: 3277
						/* 1779 */ MCD_OPC_Decode, 146, 1, 11,
						// Opcode: AMOMAXU_W_AQ_RL
							/* 1783 */ MCD_OPC_FilterValue, 3, 210, 5,
							// Skip to: 3277
							/* 1787 */ MCD_OPC_CheckPredicate, 4, 206, 5,
							// Skip to: 3277
						/* 1791 */ MCD_OPC_Decode, 142, 1, 11,
						// Opcode: AMOMAXU_D_AQ_RL
							/* 1795 */ MCD_OPC_FilterValue, 51, 234, 0,
							// Skip to: 2033
						/* 1799 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 1802 */ MCD_OPC_FilterValue, 0, 30, 0,
							// Skip to: 1836
						/* 1806 */ MCD_OPC_ExtractField, 25, 7,
						// Inst{31-25} ...
							/* 1809 */ MCD_OPC_FilterValue, 0, 3, 0,
							// Skip to: 1816
						/* 1813 */ MCD_OPC_Decode, 118, 11,
						// Opcode: ADD
							/* 1816 */ MCD_OPC_FilterValue, 1, 8, 0,
							// Skip to: 1828
							/* 1820 */ MCD_OPC_CheckPredicate, 5, 173, 5,
							// Skip to: 3277
						/* 1824 */ MCD_OPC_Decode, 171, 2, 11,
						// Opcode: MUL
							/* 1828 */ MCD_OPC_FilterValue, 32, 165, 5,
							// Skip to: 3277
						/* 1832 */ MCD_OPC_Decode, 213, 2, 11,
						// Opcode: SUB
							/* 1836 */ MCD_OPC_FilterValue, 1, 23, 0,
							// Skip to: 1863
						/* 1840 */ MCD_OPC_ExtractField, 25, 7,
						// Inst{31-25} ...
							/* 1843 */ MCD_OPC_FilterValue, 0, 4, 0,
							// Skip to: 1851
						/* 1847 */ MCD_OPC_Decode, 197, 2, 11,
						// Opcode: SLL
							/* 1851 */ MCD_OPC_FilterValue, 1, 142, 5,
							// Skip to: 3277
							/* 1855 */ MCD_OPC_CheckPredicate, 5, 138, 5,
							// Skip to: 3277
						/* 1859 */ MCD_OPC_Decode, 172, 2, 11,
						// Opcode: MULH
							/* 1863 */ MCD_OPC_FilterValue, 2, 23, 0,
							// Skip to: 1890
						/* 1867 */ MCD_OPC_ExtractField, 25, 7,
						// Inst{31-25} ...
							/* 1870 */ MCD_OPC_FilterValue, 0, 4, 0,
							// Skip to: 1878
						/* 1874 */ MCD_OPC_Decode, 201, 2, 11,
						// Opcode: SLT
							/* 1878 */ MCD_OPC_FilterValue, 1, 115, 5,
							// Skip to: 3277
							/* 1882 */ MCD_OPC_CheckPredicate, 5, 111, 5,
							// Skip to: 3277
						/* 1886 */ MCD_OPC_Decode, 173, 2, 11,
						// Opcode: MULHSU
							/* 1890 */ MCD_OPC_FilterValue, 3, 23, 0,
							// Skip to: 1917
						/* 1894 */ MCD_OPC_ExtractField, 25, 7,
						// Inst{31-25} ...
							/* 1897 */ MCD_OPC_FilterValue, 0, 4, 0,
							// Skip to: 1905
						/* 1901 */ MCD_OPC_Decode, 204, 2, 11,
						// Opcode: SLTU
							/* 1905 */ MCD_OPC_FilterValue, 1, 88, 5,
							// Skip to: 3277
							/* 1909 */ MCD_OPC_CheckPredicate, 5, 84, 5,
							// Skip to: 3277
						/* 1913 */ MCD_OPC_Decode, 174, 2, 11,
						// Opcode: MULHU
							/* 1917 */ MCD_OPC_FilterValue, 4, 23, 0,
							// Skip to: 1944
						/* 1921 */ MCD_OPC_ExtractField, 25, 7,
						// Inst{31-25} ...
							/* 1924 */ MCD_OPC_FilterValue, 0, 4, 0,
							// Skip to: 1932
						/* 1928 */ MCD_OPC_Decode, 219, 2, 11,
						// Opcode: XOR
							/* 1932 */ MCD_OPC_FilterValue, 1, 61, 5,
							// Skip to: 3277
							/* 1936 */ MCD_OPC_CheckPredicate, 5, 57, 5,
							// Skip to: 3277
						/* 1940 */ MCD_OPC_Decode, 211, 1, 11,
						// Opcode: DIV
							/* 1944 */ MCD_OPC_FilterValue, 5, 31, 0,
							// Skip to: 1979
						/* 1948 */ MCD_OPC_ExtractField, 25, 7,
						// Inst{31-25} ...
							/* 1951 */ MCD_OPC_FilterValue, 0, 4, 0,
							// Skip to: 1959
						/* 1955 */ MCD_OPC_Decode, 209, 2, 11,
						// Opcode: SRL
							/* 1959 */ MCD_OPC_FilterValue, 1, 8, 0,
							// Skip to: 1971
							/* 1963 */ MCD_OPC_CheckPredicate, 5, 30, 5,
							// Skip to: 3277
						/* 1967 */ MCD_OPC_Decode, 212, 1, 11,
						// Opcode: DIVU
							/* 1971 */ MCD_OPC_FilterValue, 32, 22, 5,
							// Skip to: 3277
						/* 1975 */ MCD_OPC_Decode, 205, 2, 11,
						// Opcode: SRA
							/* 1979 */ MCD_OPC_FilterValue, 6, 23, 0,
							// Skip to: 2006
						/* 1983 */ MCD_OPC_ExtractField, 25, 7,
						// Inst{31-25} ...
							/* 1986 */ MCD_OPC_FilterValue, 0, 4, 0,
							// Skip to: 1994
						/* 1990 */ MCD_OPC_Decode, 176, 2, 11,
						// Opcode: OR
							/* 1994 */ MCD_OPC_FilterValue, 1, 255, 4,
							// Skip to: 3277
							/* 1998 */ MCD_OPC_CheckPredicate, 5, 251, 4,
							// Skip to: 3277
						/* 2002 */ MCD_OPC_Decode, 182, 2, 11,
						// Opcode: REM
							/* 2006 */ MCD_OPC_FilterValue, 7, 243, 4,
							// Skip to: 3277
						/* 2010 */ MCD_OPC_ExtractField, 25, 7,
						// Inst{31-25} ...
							/* 2013 */ MCD_OPC_FilterValue, 0, 4, 0,
							// Skip to: 2021
						/* 2017 */ MCD_OPC_Decode, 196, 1, 11,
						// Opcode: AND
							/* 2021 */ MCD_OPC_FilterValue, 1, 228, 4,
							// Skip to: 3277
							/* 2025 */ MCD_OPC_CheckPredicate, 5, 224, 4,
							// Skip to: 3277
						/* 2029 */ MCD_OPC_Decode, 183, 2, 11,
						// Opcode: REMU
							/* 2033 */ MCD_OPC_FilterValue, 55, 4, 0,
							// Skip to: 2041
						/* 2037 */ MCD_OPC_Decode, 168, 2, 6,
						// Opcode: LUI
							/* 2041 */ MCD_OPC_FilterValue, 59, 160, 0,
							// Skip to: 2205
						/* 2045 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 2048 */ MCD_OPC_FilterValue, 0, 38, 0,
							// Skip to: 2090
						/* 2052 */ MCD_OPC_ExtractField, 25, 7,
						// Inst{31-25} ...
							/* 2055 */ MCD_OPC_FilterValue, 0, 7, 0,
							// Skip to: 2066
							/* 2059 */ MCD_OPC_CheckPredicate, 0, 190, 4,
							// Skip to: 3277
						/* 2063 */ MCD_OPC_Decode, 121, 11,
						// Opcode: ADDW
							/* 2066 */ MCD_OPC_FilterValue, 1, 8, 0,
							// Skip to: 2078
							/* 2070 */ MCD_OPC_CheckPredicate, 6, 179, 4,
							// Skip to: 3277
						/* 2074 */ MCD_OPC_Decode, 175, 2, 11,
						// Opcode: MULW
							/* 2078 */ MCD_OPC_FilterValue, 32, 171, 4,
							// Skip to: 3277
							/* 2082 */ MCD_OPC_CheckPredicate, 0, 167, 4,
							// Skip to: 3277
						/* 2086 */ MCD_OPC_Decode, 214, 2, 11,
						// Opcode: SUBW
							/* 2090 */ MCD_OPC_FilterValue, 1, 14, 0,
							// Skip to: 2108
							/* 2094 */ MCD_OPC_CheckPredicate, 0, 155, 4,
							// Skip to: 3277
								/* 2098 */ MCD_OPC_CheckField, 25, 7, 0, 149, 4,
								// Skip to: 3277
						/* 2104 */ MCD_OPC_Decode, 200, 2, 11,
						// Opcode: SLLW
							/* 2108 */ MCD_OPC_FilterValue, 4, 14, 0,
							// Skip to: 2126
							/* 2112 */ MCD_OPC_CheckPredicate, 6, 137, 4,
							// Skip to: 3277
								/* 2116 */ MCD_OPC_CheckField, 25, 7, 1, 131, 4,
								// Skip to: 3277
						/* 2122 */ MCD_OPC_Decode, 214, 1, 11,
						// Opcode: DIVW
							/* 2126 */ MCD_OPC_FilterValue, 5, 39, 0,
							// Skip to: 2169
						/* 2130 */ MCD_OPC_ExtractField, 25, 7,
						// Inst{31-25} ...
							/* 2133 */ MCD_OPC_FilterValue, 0, 8, 0,
							// Skip to: 2145
							/* 2137 */ MCD_OPC_CheckPredicate, 0, 112, 4,
							// Skip to: 3277
						/* 2141 */ MCD_OPC_Decode, 212, 2, 11,
						// Opcode: SRLW
							/* 2145 */ MCD_OPC_FilterValue, 1, 8, 0,
							// Skip to: 2157
							/* 2149 */ MCD_OPC_CheckPredicate, 6, 100, 4,
							// Skip to: 3277
						/* 2153 */ MCD_OPC_Decode, 213, 1, 11,
						// Opcode: DIVUW
							/* 2157 */ MCD_OPC_FilterValue, 32, 92, 4,
							// Skip to: 3277
							/* 2161 */ MCD_OPC_CheckPredicate, 0, 88, 4,
							// Skip to: 3277
						/* 2165 */ MCD_OPC_Decode, 208, 2, 11,
						// Opcode: SRAW
							/* 2169 */ MCD_OPC_FilterValue, 6, 14, 0,
							// Skip to: 2187
							/* 2173 */ MCD_OPC_CheckPredicate, 6, 76, 4,
							// Skip to: 3277
							/* 2177 */ MCD_OPC_CheckField, 25, 7, 1, 70, 4,
							// Skip to: 3277
						/* 2183 */ MCD_OPC_Decode, 185, 2, 11,
						// Opcode: REMW
							/* 2187 */ MCD_OPC_FilterValue, 7, 62, 4,
							// Skip to: 3277
							/* 2191 */ MCD_OPC_CheckPredicate, 6, 58, 4,
							// Skip to: 3277
							/* 2195 */ MCD_OPC_CheckField, 25, 7, 1, 52, 4,
							// Skip to: 3277
						/* 2201 */ MCD_OPC_Decode, 184, 2, 11,
						// Opcode: REMUW
							/* 2205 */ MCD_OPC_FilterValue, 67, 27, 0,
							// Skip to: 2236
						/* 2209 */ MCD_OPC_ExtractField, 25, 2,
						// Inst{26-25} ...
							/* 2212 */ MCD_OPC_FilterValue, 0, 8, 0,
							// Skip to: 2224
							/* 2216 */ MCD_OPC_CheckPredicate, 1, 33, 4,
							// Skip to: 3277
						/* 2220 */ MCD_OPC_Decode, 252, 1, 13,
						// Opcode: FMADD_S
							/* 2224 */ MCD_OPC_FilterValue, 1, 25, 4,
							// Skip to: 3277
							/* 2228 */ MCD_OPC_CheckPredicate, 2, 21, 4,
							// Skip to: 3277
						/* 2232 */ MCD_OPC_Decode, 251, 1, 14,
						// Opcode: FMADD_D
							/* 2236 */ MCD_OPC_FilterValue, 71, 27, 0,
							// Skip to: 2267
						/* 2240 */ MCD_OPC_ExtractField, 25, 2,
						// Inst{26-25} ...
							/* 2243 */ MCD_OPC_FilterValue, 0, 8, 0,
							// Skip to: 2255
							/* 2247 */ MCD_OPC_CheckPredicate, 1, 2, 4,
							// Skip to: 3277
						/* 2251 */ MCD_OPC_Decode, 130, 2, 13,
						// Opcode: FMSUB_S
							/* 2255 */ MCD_OPC_FilterValue, 1, 250, 3,
							// Skip to: 3277
							/* 2259 */ MCD_OPC_CheckPredicate, 2, 246, 3,
							// Skip to: 3277
						/* 2263 */ MCD_OPC_Decode, 129, 2, 14,
						// Opcode: FMSUB_D
							/* 2267 */ MCD_OPC_FilterValue, 75, 27, 0,
							// Skip to: 2298
						/* 2271 */ MCD_OPC_ExtractField, 25, 2,
						// Inst{26-25} ...
							/* 2274 */ MCD_OPC_FilterValue, 0, 8, 0,
							// Skip to: 2286
							/* 2278 */ MCD_OPC_CheckPredicate, 1, 227, 3,
							// Skip to: 3277
						/* 2282 */ MCD_OPC_Decode, 140, 2, 13,
						// Opcode: FNMSUB_S
							/* 2286 */ MCD_OPC_FilterValue, 1, 219, 3,
							// Skip to: 3277
							/* 2290 */ MCD_OPC_CheckPredicate, 2, 215, 3,
							// Skip to: 3277
						/* 2294 */ MCD_OPC_Decode, 139, 2, 14,
						// Opcode: FNMSUB_D
							/* 2298 */ MCD_OPC_FilterValue, 79, 27, 0,
							// Skip to: 2329
						/* 2302 */ MCD_OPC_ExtractField, 25, 2,
						// Inst{26-25} ...
							/* 2305 */ MCD_OPC_FilterValue, 0, 8, 0,
							// Skip to: 2317
							/* 2309 */ MCD_OPC_CheckPredicate, 1, 196, 3,
							// Skip to: 3277
						/* 2313 */ MCD_OPC_Decode, 138, 2, 13,
						// Opcode: FNMADD_S
							/* 2317 */ MCD_OPC_FilterValue, 1, 188, 3,
							// Skip to: 3277
							/* 2321 */ MCD_OPC_CheckPredicate, 2, 184, 3,
							// Skip to: 3277
						/* 2325 */ MCD_OPC_Decode, 137, 2, 14,
						// Opcode: FNMADD_D
							/* 2329 */ MCD_OPC_FilterValue, 83, 9, 3,
							// Skip to: 3110
						/* 2333 */ MCD_OPC_ExtractField, 25, 7,
						// Inst{31-25} ...
							/* 2336 */ MCD_OPC_FilterValue, 0, 8, 0,
							// Skip to: 2348
							/* 2340 */ MCD_OPC_CheckPredicate, 1, 165, 3,
							// Skip to: 3277
						/* 2344 */ MCD_OPC_Decode, 218, 1, 15,
						// Opcode: FADD_S
							/* 2348 */ MCD_OPC_FilterValue, 1, 8, 0,
							// Skip to: 2360
							/* 2352 */ MCD_OPC_CheckPredicate, 2, 153, 3,
							// Skip to: 3277
						/* 2356 */ MCD_OPC_Decode, 217, 1, 16,
						// Opcode: FADD_D
							/* 2360 */ MCD_OPC_FilterValue, 4, 8, 0,
							// Skip to: 2372
							/* 2364 */ MCD_OPC_CheckPredicate, 1, 141, 3,
							// Skip to: 3277
						/* 2368 */ MCD_OPC_Decode, 151, 2, 15,
						// Opcode: FSUB_S
							/* 2372 */ MCD_OPC_FilterValue, 5, 8, 0,
							// Skip to: 2384
							/* 2376 */ MCD_OPC_CheckPredicate, 2, 129, 3,
							// Skip to: 3277
						/* 2380 */ MCD_OPC_Decode, 150, 2, 16,
						// Opcode: FSUB_D
							/* 2384 */ MCD_OPC_FilterValue, 8, 8, 0,
							// Skip to: 2396
							/* 2388 */ MCD_OPC_CheckPredicate, 1, 117, 3,
							// Skip to: 3277
						/* 2392 */ MCD_OPC_Decode, 132, 2, 15,
						// Opcode: FMUL_S
							/* 2396 */ MCD_OPC_FilterValue, 9, 8, 0,
							// Skip to: 2408
							/* 2400 */ MCD_OPC_CheckPredicate, 2, 105, 3,
							// Skip to: 3277
						/* 2404 */ MCD_OPC_Decode, 131, 2, 16,
						// Opcode: FMUL_D
							/* 2408 */ MCD_OPC_FilterValue, 12, 8, 0,
							// Skip to: 2420
							/* 2412 */ MCD_OPC_CheckPredicate, 1, 93, 3,
							// Skip to: 3277
						/* 2416 */ MCD_OPC_Decode, 240, 1, 15,
						// Opcode: FDIV_S
							/* 2420 */ MCD_OPC_FilterValue, 13, 8, 0,
							// Skip to: 2432
							/* 2424 */ MCD_OPC_CheckPredicate, 2, 81, 3,
							// Skip to: 3277
						/* 2428 */ MCD_OPC_Decode, 239, 1, 16,
						// Opcode: FDIV_D
							/* 2432 */ MCD_OPC_FilterValue, 16, 39, 0,
							// Skip to: 2475
						/* 2436 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 2439 */ MCD_OPC_FilterValue, 0, 8, 0,
							// Skip to: 2451
							/* 2443 */ MCD_OPC_CheckPredicate, 1, 62, 3,
							// Skip to: 3277
						/* 2447 */ MCD_OPC_Decode, 147, 2, 17,
						// Opcode: FSGNJ_S
							/* 2451 */ MCD_OPC_FilterValue, 1, 8, 0,
							// Skip to: 2463
							/* 2455 */ MCD_OPC_CheckPredicate, 1, 50, 3,
							// Skip to: 3277
						/* 2459 */ MCD_OPC_Decode, 143, 2, 17,
						// Opcode: FSGNJN_S
							/* 2463 */ MCD_OPC_FilterValue, 2, 42, 3,
							// Skip to: 3277
							/* 2467 */ MCD_OPC_CheckPredicate, 1, 38, 3,
							// Skip to: 3277
						/* 2471 */ MCD_OPC_Decode, 145, 2, 17,
						// Opcode: FSGNJX_S
							/* 2475 */ MCD_OPC_FilterValue, 17, 39, 0,
							// Skip to: 2518
						/* 2479 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 2482 */ MCD_OPC_FilterValue, 0, 8, 0,
							// Skip to: 2494
							/* 2486 */ MCD_OPC_CheckPredicate, 2, 19, 3,
							// Skip to: 3277
						/* 2490 */ MCD_OPC_Decode, 146, 2, 18,
						// Opcode: FSGNJ_D
							/* 2494 */ MCD_OPC_FilterValue, 1, 8, 0,
							// Skip to: 2506
							/* 2498 */ MCD_OPC_CheckPredicate, 2, 7, 3,
							// Skip to: 3277
						/* 2502 */ MCD_OPC_Decode, 142, 2, 18,
						// Opcode: FSGNJN_D
							/* 2506 */ MCD_OPC_FilterValue, 2, 255, 2,
							// Skip to: 3277
							/* 2510 */ MCD_OPC_CheckPredicate, 2, 251, 2,
							// Skip to: 3277
						/* 2514 */ MCD_OPC_Decode, 144, 2, 18,
						// Opcode: FSGNJX_D
							/* 2518 */ MCD_OPC_FilterValue, 20, 27, 0,
							// Skip to: 2549
						/* 2522 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 2525 */ MCD_OPC_FilterValue, 0, 8, 0,
							// Skip to: 2537
							/* 2529 */ MCD_OPC_CheckPredicate, 1, 232, 2,
							// Skip to: 3277
						/* 2533 */ MCD_OPC_Decode, 128, 2, 17,
						// Opcode: FMIN_S
							/* 2537 */ MCD_OPC_FilterValue, 1, 224, 2,
							// Skip to: 3277
							/* 2541 */ MCD_OPC_CheckPredicate, 1, 220, 2,
							// Skip to: 3277
						/* 2545 */ MCD_OPC_Decode, 254, 1, 17,
						// Opcode: FMAX_S
							/* 2549 */ MCD_OPC_FilterValue, 21, 27, 0,
							// Skip to: 2580
						/* 2553 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 2556 */ MCD_OPC_FilterValue, 0, 8, 0,
							// Skip to: 2568
							/* 2560 */ MCD_OPC_CheckPredicate, 2, 201, 2,
							// Skip to: 3277
						/* 2564 */ MCD_OPC_Decode, 255, 1, 18,
						// Opcode: FMIN_D
							/* 2568 */ MCD_OPC_FilterValue, 1, 193, 2,
							// Skip to: 3277
							/* 2572 */ MCD_OPC_CheckPredicate, 2, 189, 2,
							// Skip to: 3277
						/* 2576 */ MCD_OPC_Decode, 253, 1, 18,
						// Opcode: FMAX_D
							/* 2580 */ MCD_OPC_FilterValue, 32, 14, 0,
							// Skip to: 2598
							/* 2584 */ MCD_OPC_CheckPredicate, 2, 177, 2,
							// Skip to: 3277
								/* 2588 */ MCD_OPC_CheckField, 20, 5, 1, 171, 2,
								// Skip to: 3277
						/* 2594 */ MCD_OPC_Decode, 230, 1, 19,
						// Opcode: FCVT_S_D
							/* 2598 */ MCD_OPC_FilterValue, 33, 20, 0,
							// Skip to: 2622
							/* 2602 */ MCD_OPC_CheckPredicate, 2, 159, 2,
							// Skip to: 3277
								/* 2606 */ MCD_OPC_CheckField, 20, 5, 0, 153, 2,
								// Skip to: 3277
								/* 2612 */ MCD_OPC_CheckField, 12, 3, 0, 147, 2,
								// Skip to: 3277
						/* 2618 */ MCD_OPC_Decode, 223, 1, 20,
						// Opcode: FCVT_D_S
							/* 2622 */ MCD_OPC_FilterValue, 44, 14, 0,
							// Skip to: 2640
							/* 2626 */ MCD_OPC_CheckPredicate, 1, 135, 2,
							// Skip to: 3277
								/* 2630 */ MCD_OPC_CheckField, 20, 5, 0, 129, 2,
								// Skip to: 3277
						/* 2636 */ MCD_OPC_Decode, 149, 2, 21,
						// Opcode: FSQRT_S
							/* 2640 */ MCD_OPC_FilterValue, 45, 14, 0,
							// Skip to: 2658
							/* 2644 */ MCD_OPC_CheckPredicate, 2, 117, 2,
							// Skip to: 3277
								/* 2648 */ MCD_OPC_CheckField, 20, 5, 0, 111, 2,
								// Skip to: 3277
						/* 2654 */ MCD_OPC_Decode, 148, 2, 22,
						// Opcode: FSQRT_D
							/* 2658 */ MCD_OPC_FilterValue, 80, 39, 0,
							// Skip to: 2701
						/* 2662 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 2665 */ MCD_OPC_FilterValue, 0, 8, 0,
							// Skip to: 2677
							/* 2669 */ MCD_OPC_CheckPredicate, 1, 92, 2,
							// Skip to: 3277
						/* 2673 */ MCD_OPC_Decode, 247, 1, 23,
						// Opcode: FLE_S
							/* 2677 */ MCD_OPC_FilterValue, 1, 8, 0,
							// Skip to: 2689
							/* 2681 */ MCD_OPC_CheckPredicate, 1, 80, 2,
							// Skip to: 3277
						/* 2685 */ MCD_OPC_Decode, 249, 1, 23,
						// Opcode: FLT_S
							/* 2689 */ MCD_OPC_FilterValue, 2, 72, 2,
							// Skip to: 3277
							/* 2693 */ MCD_OPC_CheckPredicate, 1, 68, 2,
							// Skip to: 3277
						/* 2697 */ MCD_OPC_Decode, 244, 1, 23,
						// Opcode: FEQ_S
							/* 2701 */ MCD_OPC_FilterValue, 81, 39, 0,
							// Skip to: 2744
						/* 2705 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 2708 */ MCD_OPC_FilterValue, 0, 8, 0,
							// Skip to: 2720
							/* 2712 */ MCD_OPC_CheckPredicate, 2, 49, 2,
							// Skip to: 3277
						/* 2716 */ MCD_OPC_Decode, 246, 1, 24,
						// Opcode: FLE_D
							/* 2720 */ MCD_OPC_FilterValue, 1, 8, 0,
							// Skip to: 2732
							/* 2724 */ MCD_OPC_CheckPredicate, 2, 37, 2,
							// Skip to: 3277
						/* 2728 */ MCD_OPC_Decode, 248, 1, 24,
						// Opcode: FLT_D
							/* 2732 */ MCD_OPC_FilterValue, 2, 29, 2,
							// Skip to: 3277
							/* 2736 */ MCD_OPC_CheckPredicate, 2, 25, 2,
							// Skip to: 3277
						/* 2740 */ MCD_OPC_Decode, 243, 1, 24,
						// Opcode: FEQ_D
							/* 2744 */ MCD_OPC_FilterValue, 96, 51, 0,
							// Skip to: 2799
						/* 2748 */ MCD_OPC_ExtractField, 20, 5,
						// Inst{24-20} ...
							/* 2751 */ MCD_OPC_FilterValue, 0, 8, 0,
							// Skip to: 2763
							/* 2755 */ MCD_OPC_CheckPredicate, 1, 6, 2,
							// Skip to: 3277
						/* 2759 */ MCD_OPC_Decode, 238, 1, 25,
						// Opcode: FCVT_W_S
							/* 2763 */ MCD_OPC_FilterValue, 1, 8, 0,
							// Skip to: 2775
							/* 2767 */ MCD_OPC_CheckPredicate, 1, 250, 1,
							// Skip to: 3277
						/* 2771 */ MCD_OPC_Decode, 236, 1, 25,
						// Opcode: FCVT_WU_S
							/* 2775 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 2787
							/* 2779 */ MCD_OPC_CheckPredicate, 7, 238, 1,
							// Skip to: 3277
						/* 2783 */ MCD_OPC_Decode, 229, 1, 25,
						// Opcode: FCVT_L_S
							/* 2787 */ MCD_OPC_FilterValue, 3, 230, 1,
							// Skip to: 3277
							/* 2791 */ MCD_OPC_CheckPredicate, 7, 226, 1,
							// Skip to: 3277
						/* 2795 */ MCD_OPC_Decode, 227, 1, 25,
						// Opcode: FCVT_LU_S
							/* 2799 */ MCD_OPC_FilterValue, 97, 51, 0,
							// Skip to: 2854
						/* 2803 */ MCD_OPC_ExtractField, 20, 5,
						// Inst{24-20} ...
							/* 2806 */ MCD_OPC_FilterValue, 0, 8, 0,
							// Skip to: 2818
							/* 2810 */ MCD_OPC_CheckPredicate, 2, 207, 1,
							// Skip to: 3277
						/* 2814 */ MCD_OPC_Decode, 237, 1, 26,
						// Opcode: FCVT_W_D
							/* 2818 */ MCD_OPC_FilterValue, 1, 8, 0,
							// Skip to: 2830
							/* 2822 */ MCD_OPC_CheckPredicate, 2, 195, 1,
							// Skip to: 3277
						/* 2826 */ MCD_OPC_Decode, 235, 1, 26,
						// Opcode: FCVT_WU_D
							/* 2830 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 2842
							/* 2834 */ MCD_OPC_CheckPredicate, 8, 183, 1,
							// Skip to: 3277
						/* 2838 */ MCD_OPC_Decode, 228, 1, 26,
						// Opcode: FCVT_L_D
							/* 2842 */ MCD_OPC_FilterValue, 3, 175, 1,
							// Skip to: 3277
							/* 2846 */ MCD_OPC_CheckPredicate, 8, 171, 1,
							// Skip to: 3277
						/* 2850 */ MCD_OPC_Decode, 226, 1, 26,
						// Opcode: FCVT_LU_D
							/* 2854 */ MCD_OPC_FilterValue, 104, 51, 0,
							// Skip to: 2909
						/* 2858 */ MCD_OPC_ExtractField, 20, 5,
						// Inst{24-20} ...
							/* 2861 */ MCD_OPC_FilterValue, 0, 8, 0,
							// Skip to: 2873
							/* 2865 */ MCD_OPC_CheckPredicate, 1, 152, 1,
							// Skip to: 3277
						/* 2869 */ MCD_OPC_Decode, 233, 1, 27,
						// Opcode: FCVT_S_W
							/* 2873 */ MCD_OPC_FilterValue, 1, 8, 0,
							// Skip to: 2885
							/* 2877 */ MCD_OPC_CheckPredicate, 1, 140, 1,
							// Skip to: 3277
						/* 2881 */ MCD_OPC_Decode, 234, 1, 27,
						// Opcode: FCVT_S_WU
							/* 2885 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 2897
							/* 2889 */ MCD_OPC_CheckPredicate, 7, 128, 1,
							// Skip to: 3277
						/* 2893 */ MCD_OPC_Decode, 231, 1, 27,
						// Opcode: FCVT_S_L
							/* 2897 */ MCD_OPC_FilterValue, 3, 120, 1,
							// Skip to: 3277
							/* 2901 */ MCD_OPC_CheckPredicate, 7, 116, 1,
							// Skip to: 3277
						/* 2905 */ MCD_OPC_Decode, 232, 1, 27,
						// Opcode: FCVT_S_LU
							/* 2909 */ MCD_OPC_FilterValue, 105, 63, 0,
							// Skip to: 2976
						/* 2913 */ MCD_OPC_ExtractField, 20, 5,
						// Inst{24-20} ...
							/* 2916 */ MCD_OPC_FilterValue, 0, 14, 0,
							// Skip to: 2934
							/* 2920 */ MCD_OPC_CheckPredicate, 2, 97, 1,
							// Skip to: 3277
							/* 2924 */ MCD_OPC_CheckField, 12, 3, 0, 91, 1,
							// Skip to: 3277
						/* 2930 */ MCD_OPC_Decode, 224, 1, 28,
						// Opcode: FCVT_D_W
							/* 2934 */ MCD_OPC_FilterValue, 1, 14, 0,
							// Skip to: 2952
							/* 2938 */ MCD_OPC_CheckPredicate, 2, 79, 1,
							// Skip to: 3277
							/* 2942 */ MCD_OPC_CheckField, 12, 3, 0, 73, 1,
							// Skip to: 3277
						/* 2948 */ MCD_OPC_Decode, 225, 1, 28,
						// Opcode: FCVT_D_WU
							/* 2952 */ MCD_OPC_FilterValue, 2, 8, 0,
							// Skip to: 2964
							/* 2956 */ MCD_OPC_CheckPredicate, 8, 61, 1,
							// Skip to: 3277
						/* 2960 */ MCD_OPC_Decode, 221, 1, 29,
						// Opcode: FCVT_D_L
							/* 2964 */ MCD_OPC_FilterValue, 3, 53, 1,
							// Skip to: 3277
							/* 2968 */ MCD_OPC_CheckPredicate, 8, 49, 1,
							// Skip to: 3277
						/* 2972 */ MCD_OPC_Decode, 222, 1, 29,
						// Opcode: FCVT_D_LU
							/* 2976 */ MCD_OPC_FilterValue, 112, 39, 0,
							// Skip to: 3019
						/* 2980 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 2983 */ MCD_OPC_FilterValue, 0, 14, 0,
							// Skip to: 3001
							/* 2987 */ MCD_OPC_CheckPredicate, 1, 30, 1,
							// Skip to: 3277
							/* 2991 */ MCD_OPC_CheckField, 20, 5, 0, 24, 1,
							// Skip to: 3277
						/* 2997 */ MCD_OPC_Decode, 136, 2, 30,
						// Opcode: FMV_X_W
							/* 3001 */ MCD_OPC_FilterValue, 1, 16, 1,
							// Skip to: 3277
							/* 3005 */ MCD_OPC_CheckPredicate, 1, 12, 1,
							// Skip to: 3277
							/* 3009 */ MCD_OPC_CheckField, 20, 5, 0, 6, 1,
							// Skip to: 3277
						/* 3015 */ MCD_OPC_Decode, 220, 1, 30,
						// Opcode: FCLASS_S
							/* 3019 */ MCD_OPC_FilterValue, 113, 39, 0,
							// Skip to: 3062
						/* 3023 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 3026 */ MCD_OPC_FilterValue, 0, 14, 0,
							// Skip to: 3044
							/* 3030 */ MCD_OPC_CheckPredicate, 8, 243, 0,
							// Skip to: 3277
								/* 3034 */ MCD_OPC_CheckField, 20, 5, 0, 237, 0,
								// Skip to: 3277
						/* 3040 */ MCD_OPC_Decode, 135, 2, 31,
						// Opcode: FMV_X_D
							/* 3044 */ MCD_OPC_FilterValue, 1, 229, 0,
							// Skip to: 3277
							/* 3048 */ MCD_OPC_CheckPredicate, 2, 225, 0,
							// Skip to: 3277
								/* 3052 */ MCD_OPC_CheckField, 20, 5, 0, 219, 0,
								// Skip to: 3277
						/* 3058 */ MCD_OPC_Decode, 219, 1, 31,
						// Opcode: FCLASS_D
							/* 3062 */ MCD_OPC_FilterValue, 120, 20, 0,
							// Skip to: 3086
							/* 3066 */ MCD_OPC_CheckPredicate, 1, 207, 0,
							// Skip to: 3277
								/* 3070 */ MCD_OPC_CheckField, 20, 5, 0, 201, 0,
								// Skip to: 3277
								/* 3076 */ MCD_OPC_CheckField, 12, 3, 0, 195, 0,
								// Skip to: 3277
						/* 3082 */ MCD_OPC_Decode, 134, 2, 32,
						// Opcode: FMV_W_X
							/* 3086 */ MCD_OPC_FilterValue, 121, 187, 0,
							// Skip to: 3277
							/* 3090 */ MCD_OPC_CheckPredicate, 8, 183, 0,
							// Skip to: 3277
								/* 3094 */ MCD_OPC_CheckField, 20, 5, 0, 177, 0,
								// Skip to: 3277
								/* 3100 */ MCD_OPC_CheckField, 12, 3, 0, 171, 0,
								// Skip to: 3277
						/* 3106 */ MCD_OPC_Decode, 133, 2, 28,
						// Opcode: FMV_D_X
							/* 3110 */ MCD_OPC_FilterValue, 99, 51, 0,
							// Skip to: 3165
						/* 3114 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 3117 */ MCD_OPC_FilterValue, 0, 4, 0,
							// Skip to: 3125
						/* 3121 */ MCD_OPC_Decode, 199, 1, 33,
						// Opcode: BEQ
							/* 3125 */ MCD_OPC_FilterValue, 1, 4, 0,
							// Skip to: 3133
						/* 3129 */ MCD_OPC_Decode, 204, 1, 33,
						// Opcode: BNE
							/* 3133 */ MCD_OPC_FilterValue, 4, 4, 0,
							// Skip to: 3141
						/* 3137 */ MCD_OPC_Decode, 202, 1, 33,
						// Opcode: BLT
							/* 3141 */ MCD_OPC_FilterValue, 5, 4, 0,
							// Skip to: 3149
						/* 3145 */ MCD_OPC_Decode, 200, 1, 33,
						// Opcode: BGE
							/* 3149 */ MCD_OPC_FilterValue, 6, 4, 0,
							// Skip to: 3157
						/* 3153 */ MCD_OPC_Decode, 203, 1, 33,
						// Opcode: BLTU
							/* 3157 */ MCD_OPC_FilterValue, 7, 116, 0,
							// Skip to: 3277
						/* 3161 */ MCD_OPC_Decode, 201, 1, 33,
						// Opcode: BGEU
							/* 3165 */ MCD_OPC_FilterValue, 103, 10, 0,
							// Skip to: 3179
								/* 3169 */ MCD_OPC_CheckField, 12, 3, 0, 102, 0,
								// Skip to: 3277
						/* 3175 */ MCD_OPC_Decode, 154, 2, 0,
						// Opcode: JALR
							/* 3179 */ MCD_OPC_FilterValue, 111, 4, 0,
							// Skip to: 3187
						/* 3183 */ MCD_OPC_Decode, 153, 2, 34,
						// Opcode: JAL
							/* 3187 */ MCD_OPC_FilterValue, 115, 86, 0,
							// Skip to: 3277
						/* 3191 */ MCD_OPC_ExtractField, 12, 3,
						// Inst{14-12} ...
							/* 3194 */ MCD_OPC_FilterValue, 0, 31, 0,
							// Skip to: 3229
							/* 3198 */ MCD_OPC_ExtractField, 15, 17,
							// Inst{31-15} ...
							/* 3201 */ MCD_OPC_FilterValue, 0, 10, 0,
							// Skip to: 3215
							/* 3205 */ MCD_OPC_CheckField, 7, 5, 0, 66, 0,
							// Skip to: 3277
						/* 3211 */ MCD_OPC_Decode, 216, 1, 4,
						// Opcode: ECALL
							/* 3215 */ MCD_OPC_FilterValue, 32, 58, 0,
							// Skip to: 3277
							/* 3219 */ MCD_OPC_CheckField, 7, 5, 0, 52, 0,
							// Skip to: 3277
						/* 3225 */ MCD_OPC_Decode, 215, 1, 4,
						// Opcode: EBREAK
							/* 3229 */ MCD_OPC_FilterValue, 1, 4, 0,
							// Skip to: 3237
						/* 3233 */ MCD_OPC_Decode, 209, 1, 35,
						// Opcode: CSRRW
							/* 3237 */ MCD_OPC_FilterValue, 2, 4, 0,
							// Skip to: 3245
						/* 3241 */ MCD_OPC_Decode, 207, 1, 35,
						// Opcode: CSRRS
							/* 3245 */ MCD_OPC_FilterValue, 3, 4, 0,
							// Skip to: 3253
						/* 3249 */ MCD_OPC_Decode, 205, 1, 35,
						// Opcode: CSRRC
							/* 3253 */ MCD_OPC_FilterValue, 5, 4, 0,
							// Skip to: 3261
						/* 3257 */ MCD_OPC_Decode, 210, 1, 36,
						// Opcode: CSRRWI
							/* 3261 */ MCD_OPC_FilterValue, 6, 4, 0,
							// Skip to: 3269
						/* 3265 */ MCD_OPC_Decode, 208, 1, 36,
						// Opcode: CSRRSI
							/* 3269 */ MCD_OPC_FilterValue, 7, 4, 0,
							// Skip to: 3277
						/* 3273 */ MCD_OPC_Decode, 206, 1, 36,
						// Opcode: CSRRCI
/* 3277 */ MCD_OPC_Fail,
	0
};

static bool
getbool (uint64_t b)
{
	return b != 0;
}

static bool
checkDecoderPredicate (unsigned Idx, uint64_t Bits)
{
	switch (Idx)
	  {
	  default:		//llvm_unreachable("Invalid index!");
	  case 0:
		  return getbool ((Bits & RISCV_Feature64Bit));
	  case 1:
		  return getbool ((Bits & RISCV_FeatureStdExtF));
	  case 2:
		  return getbool ((Bits & RISCV_FeatureStdExtD));
	  case 3:
		  return getbool ((Bits & RISCV_FeatureStdExtA));
	  case 4:
		  return getbool ((Bits & RISCV_FeatureStdExtA
				   && Bits & RISCV_Feature64Bit));
	  case 5:
		  return getbool ((Bits & RISCV_FeatureStdExtM));
	  case 6:
		  return getbool ((Bits & RISCV_FeatureStdExtM
				   && Bits & RISCV_Feature64Bit));
	  case 7:
		  return getbool ((Bits & RISCV_FeatureStdExtF
				   && Bits & RISCV_Feature64Bit));
	  case 8:
		  return getbool ((Bits & RISCV_FeatureStdExtD
				   && Bits & RISCV_Feature64Bit));
	  }
}

#define DecodeToMCInst(fname,fieldname, InsnType) \
static DecodeStatus fname(DecodeStatus S, unsigned Idx, InsnType insn, MCInst *MI, \
                                   uint64_t Address, const void *Decoder) { \
  InsnType tmp; \
  switch (Idx) { \
  default:  \
  case 0: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 12); \
    if (decodeSImmOperand(MI, tmp, Address, Decoder, 12) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 1: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 12); \
    if (decodeSImmOperand(MI, tmp, Address, Decoder, 12) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 2: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 12); \
    if (decodeSImmOperand(MI, tmp, Address, Decoder, 12) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 3: \
    tmp = fieldname(insn, 24, 4); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 4) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 4); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 4) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 4: \
    return S; \
  case 5: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 6); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 6) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 6: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 12, 20); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 20) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 7: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 8: \
    tmp = fieldname(insn, 20, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = 0; \
    tmp |= fieldname(insn, 7, 5) << 0; \
    tmp |= fieldname(insn, 25, 7) << 5; \
    if (decodeSImmOperand(MI, tmp, Address, Decoder, 12) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 9: \
    tmp = fieldname(insn, 20, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = 0; \
    tmp |= fieldname(insn, 7, 5) << 0; \
    tmp |= fieldname(insn, 25, 7) << 5; \
    if (decodeSImmOperand(MI, tmp, Address, Decoder, 12) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 10: \
    tmp = fieldname(insn, 20, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = 0; \
    tmp |= fieldname(insn, 7, 5) << 0; \
    tmp |= fieldname(insn, 25, 7) << 5; \
    if (decodeSImmOperand(MI, tmp, Address, Decoder, 12) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 11: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 12: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 13: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 27, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 12, 3); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 3) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 14: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 27, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 12, 3); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 3) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 15: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 12, 3); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 3) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 16: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 12, 3); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 3) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 17: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 18: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 19: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 12, 3); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 3) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 20: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 21: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 12, 3); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 3) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 22: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 12, 3); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 3) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 23: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 24: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 25: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 12, 3); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 3) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 26: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 12, 3); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 3) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 27: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 12, 3); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 3) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 28: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 29: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 12, 3); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 3) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 30: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 31: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeFPR64RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 32: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeFPR32RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 33: \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = 0; \
    tmp |= fieldname(insn, 7, 1) << 10; \
    tmp |= fieldname(insn, 8, 4) << 0; \
    tmp |= fieldname(insn, 25, 6) << 4; \
    tmp |= fieldname(insn, 31, 1) << 11; \
    if (decodeSImmOperandAndLsl1(MI, tmp, Address, Decoder, 13) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 34: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = 0; \
    tmp |= fieldname(insn, 12, 8) << 11; \
    tmp |= fieldname(insn, 20, 1) << 10; \
    tmp |= fieldname(insn, 21, 10) << 0; \
    tmp |= fieldname(insn, 31, 1) << 19; \
    if (decodeSImmOperandAndLsl1(MI, tmp, Address, Decoder, 21) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 35: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 12); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 12) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  case 36: \
    tmp = fieldname(insn, 7, 5); \
    if (DecodeGPRRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 20, 12); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 12) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    tmp = fieldname(insn, 15, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) { return MCDisassembler_Fail; } \
    return S; \
  } \
}


#define DecodeInstruction(fname, fieldname, decoder, InsnType) \
static DecodeStatus fname( const uint8_t DecodeTable[], MCInst *MI, \
           InsnType insn, uint64_t Address, const MCRegisterInfo *MRI, int feature) { \
  uint64_t Bits = getFeatureBits(feature); \
  const uint8_t *Ptr = DecodeTable; \
  uint32_t CurFieldValue = 0; \
  DecodeStatus S = MCDisassembler_Success; \
  while (true) { \
    switch (*Ptr) { \
    default: \
      return MCDisassembler_Fail; \
    case MCD_OPC_ExtractField: { \
      unsigned Start = *++Ptr; \
      unsigned Len = *++Ptr; \
      ++Ptr; \
      CurFieldValue = (uint32_t)fieldname(insn, Start, Len); \
      break; \
    } \
    case MCD_OPC_FilterValue: { \
      unsigned Len; \
      InsnType Val = (InsnType)decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      unsigned NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      if (Val != CurFieldValue) \
        Ptr += NumToSkip; \
      break; \
    } \
    case MCD_OPC_CheckField: { \
      unsigned Start = *++Ptr; \
      unsigned Len = *++Ptr; \
      InsnType FieldValue = fieldname(insn, Start, Len); \
      uint32_t ExpectedValue = (uint32_t)decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      unsigned NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      if (ExpectedValue != FieldValue) \
        Ptr += NumToSkip; \
      break; \
    } \
    case MCD_OPC_CheckPredicate: { \
      unsigned Len; \
      unsigned PIdx = (unsigned)decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      unsigned NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      bool Pred; \
      if (!(Pred = checkDecoderPredicate(PIdx, Bits))) \
        Ptr += NumToSkip; \
      (void)Pred; \
      break; \
    } \
    case MCD_OPC_Decode: { \
      unsigned Len; \
      unsigned Opc = (unsigned)decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      unsigned DecodeIdx = (unsigned)decodeULEB128(Ptr, &Len); \
      Ptr += Len; \
      MCInst_clear(MI); \
      MCInst_setOpcode(MI, Opc); \
      return decoder(S, DecodeIdx, insn, MI, Address, MRI); \
    } \
    case MCD_OPC_SoftFail: { \
      unsigned Len; \
      InsnType PositiveMask = (InsnType)decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      InsnType NegativeMask = (InsnType)decodeULEB128(Ptr, &Len); \
      Ptr += Len; \
      bool Fail = (insn & PositiveMask) || (~insn & NegativeMask); \
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

FieldFromInstruction (fieldFromInstruction, uint32_t)
DecodeToMCInst (decodeToMCInst, fieldFromInstruction, uint32_t)
DecodeInstruction (decodeInstruction, fieldFromInstruction, decodeToMCInst,
		   uint32_t)
