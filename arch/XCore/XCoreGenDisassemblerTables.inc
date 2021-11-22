#include "../../MCInst.h"
#include "../../LEB128.h"


#ifdef MIPS_GET_DISASSEMBLER
#undef MIPS_GET_DISASSEMBLER

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

static const uint8_t DecoderTable16[] = {
/* 0 */       MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 3 */       MCD_OPC_FilterValue, 0, 129, 0, 0, // Skip to: 137
/* 8 */       MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 11 */      MCD_OPC_FilterValue, 236, 15, 4, 0, 0, // Skip to: 21
/* 17 */      MCD_OPC_Decode, 207, 3, 0, // Opcode: WAITEU_0R
/* 21 */      MCD_OPC_FilterValue, 237, 15, 4, 0, 0, // Skip to: 31
/* 27 */      MCD_OPC_Decode, 158, 2, 0, // Opcode: CLRE_0R
/* 31 */      MCD_OPC_FilterValue, 238, 15, 4, 0, 0, // Skip to: 41
/* 37 */      MCD_OPC_Decode, 183, 3, 0, // Opcode: SSYNC_0r
/* 41 */      MCD_OPC_FilterValue, 239, 15, 4, 0, 0, // Skip to: 51
/* 47 */      MCD_OPC_Decode, 190, 2, 0, // Opcode: FREET_0R
/* 51 */      MCD_OPC_FilterValue, 252, 15, 4, 0, 0, // Skip to: 61
/* 57 */      MCD_OPC_Decode, 167, 2, 0, // Opcode: DCALL_0R
/* 61 */      MCD_OPC_FilterValue, 253, 15, 4, 0, 0, // Skip to: 71
/* 67 */      MCD_OPC_Decode, 221, 2, 0, // Opcode: KRET_0R
/* 71 */      MCD_OPC_FilterValue, 254, 15, 4, 0, 0, // Skip to: 81
/* 77 */      MCD_OPC_Decode, 173, 2, 0, // Opcode: DRET_0R
/* 81 */      MCD_OPC_FilterValue, 255, 15, 4, 0, 0, // Skip to: 91
/* 87 */      MCD_OPC_Decode, 164, 3, 0, // Opcode: SETKEP_0R
/* 91 */      MCD_OPC_ExtractField, 4, 7,  // Inst{10-4} ...
/* 94 */      MCD_OPC_FilterValue, 126, 4, 0, 0, // Skip to: 103
/* 99 */      MCD_OPC_Decode, 176, 2, 1, // Opcode: EDU_1r
/* 103 */     MCD_OPC_FilterValue, 127, 4, 0, 0, // Skip to: 112
/* 108 */     MCD_OPC_Decode, 179, 2, 1, // Opcode: EEU_1r
/* 112 */     MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 115 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 124
/* 120 */     MCD_OPC_Decode, 208, 2, 2, // Opcode: INITPC_2r
/* 124 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 133
/* 129 */     MCD_OPC_Decode, 202, 2, 2, // Opcode: GETST_2r
/* 133 */     MCD_OPC_Decode, 194, 3, 3, // Opcode: STW_2rus
/* 137 */     MCD_OPC_FilterValue, 1, 129, 0, 0, // Skip to: 271
/* 142 */     MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 145 */     MCD_OPC_FilterValue, 236, 15, 4, 0, 0, // Skip to: 155
/* 151 */     MCD_OPC_Decode, 247, 2, 0, // Opcode: LDSPC_0R
/* 155 */     MCD_OPC_FilterValue, 237, 15, 4, 0, 0, // Skip to: 165
/* 161 */     MCD_OPC_Decode, 188, 3, 0, // Opcode: STSPC_0R
/* 165 */     MCD_OPC_FilterValue, 238, 15, 4, 0, 0, // Skip to: 175
/* 171 */     MCD_OPC_Decode, 248, 2, 0, // Opcode: LDSSR_0R
/* 175 */     MCD_OPC_FilterValue, 239, 15, 4, 0, 0, // Skip to: 185
/* 181 */     MCD_OPC_Decode, 189, 3, 0, // Opcode: STSSR_0R
/* 185 */     MCD_OPC_FilterValue, 252, 15, 4, 0, 0, // Skip to: 195
/* 191 */     MCD_OPC_Decode, 187, 3, 0, // Opcode: STSED_0R
/* 195 */     MCD_OPC_FilterValue, 253, 15, 4, 0, 0, // Skip to: 205
/* 201 */     MCD_OPC_Decode, 186, 3, 0, // Opcode: STET_0R
/* 205 */     MCD_OPC_FilterValue, 254, 15, 4, 0, 0, // Skip to: 215
/* 211 */     MCD_OPC_Decode, 192, 2, 0, // Opcode: GETED_0R
/* 215 */     MCD_OPC_FilterValue, 255, 15, 4, 0, 0, // Skip to: 225
/* 221 */     MCD_OPC_Decode, 193, 2, 0, // Opcode: GETET_0R
/* 225 */     MCD_OPC_ExtractField, 4, 7,  // Inst{10-4} ...
/* 228 */     MCD_OPC_FilterValue, 126, 4, 0, 0, // Skip to: 237
/* 233 */     MCD_OPC_Decode, 206, 3, 1, // Opcode: WAITET_1R
/* 237 */     MCD_OPC_FilterValue, 127, 4, 0, 0, // Skip to: 246
/* 242 */     MCD_OPC_Decode, 205, 3, 1, // Opcode: WAITEF_1R
/* 246 */     MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 249 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 258
/* 254 */     MCD_OPC_Decode, 206, 2, 2, // Opcode: INITDP_2r
/* 258 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 267
/* 263 */     MCD_OPC_Decode, 149, 3, 4, // Opcode: OUTT_2r
/* 267 */     MCD_OPC_Decode, 129, 3, 3, // Opcode: LDW_2rus
/* 271 */     MCD_OPC_FilterValue, 2, 119, 0, 0, // Skip to: 395
/* 276 */     MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 279 */     MCD_OPC_FilterValue, 236, 15, 4, 0, 0, // Skip to: 289
/* 285 */     MCD_OPC_Decode, 168, 2, 0, // Opcode: DENTSP_0R
/* 289 */     MCD_OPC_FilterValue, 237, 15, 4, 0, 0, // Skip to: 299
/* 295 */     MCD_OPC_Decode, 172, 2, 0, // Opcode: DRESTSP_0R
/* 299 */     MCD_OPC_FilterValue, 238, 15, 4, 0, 0, // Skip to: 309
/* 305 */     MCD_OPC_Decode, 194, 2, 0, // Opcode: GETID_0R
/* 309 */     MCD_OPC_FilterValue, 239, 15, 4, 0, 0, // Skip to: 319
/* 315 */     MCD_OPC_Decode, 195, 2, 0, // Opcode: GETKEP_0R
/* 319 */     MCD_OPC_FilterValue, 252, 15, 4, 0, 0, // Skip to: 329
/* 325 */     MCD_OPC_Decode, 196, 2, 0, // Opcode: GETKSP_0R
/* 329 */     MCD_OPC_FilterValue, 253, 15, 4, 0, 0, // Skip to: 339
/* 335 */     MCD_OPC_Decode, 246, 2, 0, // Opcode: LDSED_0R
/* 339 */     MCD_OPC_FilterValue, 254, 15, 4, 0, 0, // Skip to: 349
/* 345 */     MCD_OPC_Decode, 244, 2, 0, // Opcode: LDET_0R
/* 349 */     MCD_OPC_ExtractField, 4, 7,  // Inst{10-4} ...
/* 352 */     MCD_OPC_FilterValue, 126, 4, 0, 0, // Skip to: 361
/* 357 */     MCD_OPC_Decode, 189, 2, 1, // Opcode: FREER_1r
/* 361 */     MCD_OPC_FilterValue, 127, 4, 0, 0, // Skip to: 370
/* 366 */     MCD_OPC_Decode, 137, 3, 1, // Opcode: MJOIN_1r
/* 370 */     MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 373 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 382
/* 378 */     MCD_OPC_Decode, 209, 2, 2, // Opcode: INITSP_2r
/* 382 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 391
/* 387 */     MCD_OPC_Decode, 162, 3, 4, // Opcode: SETD_2r
/* 391 */     MCD_OPC_Decode, 254, 1, 5, // Opcode: ADD_3r
/* 395 */     MCD_OPC_FilterValue, 3, 46, 0, 0, // Skip to: 446
/* 400 */     MCD_OPC_ExtractField, 4, 7,  // Inst{10-4} ...
/* 403 */     MCD_OPC_FilterValue, 126, 4, 0, 0, // Skip to: 412
/* 408 */     MCD_OPC_Decode, 204, 3, 1, // Opcode: TSTART_1R
/* 412 */     MCD_OPC_FilterValue, 127, 4, 0, 0, // Skip to: 421
/* 417 */     MCD_OPC_Decode, 140, 3, 1, // Opcode: MSYNC_1r
/* 421 */     MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 424 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 433
/* 429 */     MCD_OPC_Decode, 205, 2, 2, // Opcode: INITCP_2r
/* 433 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 442
/* 438 */     MCD_OPC_Decode, 202, 3, 6, // Opcode: TSETMR_2r
/* 442 */     MCD_OPC_Decode, 197, 3, 5, // Opcode: SUB_3r
/* 446 */     MCD_OPC_FilterValue, 4, 36, 0, 0, // Skip to: 487
/* 451 */     MCD_OPC_ExtractField, 4, 7,  // Inst{10-4} ...
/* 454 */     MCD_OPC_FilterValue, 126, 4, 0, 0, // Skip to: 463
/* 459 */     MCD_OPC_Decode, 137, 2, 1, // Opcode: BLA_1r
/* 463 */     MCD_OPC_FilterValue, 127, 4, 0, 0, // Skip to: 472
/* 468 */     MCD_OPC_Decode, 131, 2, 1, // Opcode: BAU_1r
/* 472 */     MCD_OPC_CheckField, 4, 1, 1, 4, 0, 0, // Skip to: 483
/* 479 */     MCD_OPC_Decode, 178, 2, 2, // Opcode: EET_2r
/* 483 */     MCD_OPC_Decode, 180, 3, 5, // Opcode: SHL_3r
/* 487 */     MCD_OPC_FilterValue, 5, 46, 0, 0, // Skip to: 538
/* 492 */     MCD_OPC_ExtractField, 4, 7,  // Inst{10-4} ...
/* 495 */     MCD_OPC_FilterValue, 126, 4, 0, 0, // Skip to: 504
/* 500 */     MCD_OPC_Decode, 154, 2, 1, // Opcode: BRU_1r
/* 504 */     MCD_OPC_FilterValue, 127, 4, 0, 0, // Skip to: 513
/* 509 */     MCD_OPC_Decode, 170, 3, 1, // Opcode: SETSP_1r
/* 513 */     MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 516 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 525
/* 521 */     MCD_OPC_Decode, 255, 1, 7, // Opcode: ANDNOT_2r
/* 525 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 534
/* 530 */     MCD_OPC_Decode, 177, 2, 2, // Opcode: EEF_2r
/* 534 */     MCD_OPC_Decode, 182, 3, 5, // Opcode: SHR_3r
/* 538 */     MCD_OPC_FilterValue, 6, 46, 0, 0, // Skip to: 589
/* 543 */     MCD_OPC_ExtractField, 4, 7,  // Inst{10-4} ...
/* 546 */     MCD_OPC_FilterValue, 126, 4, 0, 0, // Skip to: 555
/* 551 */     MCD_OPC_Decode, 161, 3, 1, // Opcode: SETDP_1r
/* 555 */     MCD_OPC_FilterValue, 127, 4, 0, 0, // Skip to: 564
/* 560 */     MCD_OPC_Decode, 157, 3, 1, // Opcode: SETCP_1r
/* 564 */     MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 567 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 576
/* 572 */     MCD_OPC_Decode, 177, 3, 7, // Opcode: SEXT_2r
/* 576 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 585
/* 581 */     MCD_OPC_Decode, 178, 3, 8, // Opcode: SEXT_rus
/* 585 */     MCD_OPC_Decode, 184, 2, 5, // Opcode: EQ_3r
/* 589 */     MCD_OPC_FilterValue, 7, 46, 0, 0, // Skip to: 640
/* 594 */     MCD_OPC_ExtractField, 4, 7,  // Inst{10-4} ...
/* 597 */     MCD_OPC_FilterValue, 126, 4, 0, 0, // Skip to: 606
/* 602 */     MCD_OPC_Decode, 169, 2, 1, // Opcode: DGETREG_1r
/* 606 */     MCD_OPC_FilterValue, 127, 4, 0, 0, // Skip to: 615
/* 611 */     MCD_OPC_Decode, 163, 3, 1, // Opcode: SETEV_1r
/* 615 */     MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 618 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 627
/* 623 */     MCD_OPC_Decode, 203, 2, 2, // Opcode: GETTS_2r
/* 627 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 636
/* 632 */     MCD_OPC_Decode, 168, 3, 4, // Opcode: SETPT_2r
/* 636 */     MCD_OPC_Decode, 128, 2, 5, // Opcode: AND_3r
/* 640 */     MCD_OPC_FilterValue, 8, 46, 0, 0, // Skip to: 691
/* 645 */     MCD_OPC_ExtractField, 4, 7,  // Inst{10-4} ...
/* 648 */     MCD_OPC_FilterValue, 126, 4, 0, 0, // Skip to: 657
/* 653 */     MCD_OPC_Decode, 214, 2, 1, // Opcode: KCALL_1r
/* 657 */     MCD_OPC_FilterValue, 127, 4, 0, 0, // Skip to: 666
/* 662 */     MCD_OPC_Decode, 176, 3, 1, // Opcode: SETV_1r
/* 666 */     MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 669 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 678
/* 674 */     MCD_OPC_Decode, 209, 3, 7, // Opcode: ZEXT_2r
/* 678 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 687
/* 683 */     MCD_OPC_Decode, 210, 3, 8, // Opcode: ZEXT_rus
/* 687 */     MCD_OPC_Decode, 144, 3, 5, // Opcode: OR_3r
/* 691 */     MCD_OPC_FilterValue, 9, 46, 0, 0, // Skip to: 742
/* 696 */     MCD_OPC_ExtractField, 4, 7,  // Inst{10-4} ...
/* 699 */     MCD_OPC_FilterValue, 126, 4, 0, 0, // Skip to: 708
/* 704 */     MCD_OPC_Decode, 174, 2, 1, // Opcode: ECALLF_1r
/* 708 */     MCD_OPC_FilterValue, 127, 4, 0, 0, // Skip to: 717
/* 713 */     MCD_OPC_Decode, 175, 2, 1, // Opcode: ECALLT_1r
/* 717 */     MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 720 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 729
/* 725 */     MCD_OPC_Decode, 145, 3, 2, // Opcode: OUTCT_2r
/* 729 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 738
/* 734 */     MCD_OPC_Decode, 146, 3, 9, // Opcode: OUTCT_rus
/* 738 */     MCD_OPC_Decode, 130, 3, 5, // Opcode: LDW_3r
/* 742 */     MCD_OPC_FilterValue, 10, 21, 0, 0, // Skip to: 768
/* 747 */     MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 750 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 759
/* 755 */     MCD_OPC_Decode, 191, 3, 10, // Opcode: STWDP_ru6
/* 759 */     MCD_OPC_FilterValue, 1, 154, 2, 0, // Skip to: 1430
/* 764 */     MCD_OPC_Decode, 193, 3, 10, // Opcode: STWSP_ru6
/* 768 */     MCD_OPC_FilterValue, 11, 21, 0, 0, // Skip to: 794
/* 773 */     MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 776 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 785
/* 781 */     MCD_OPC_Decode, 254, 2, 10, // Opcode: LDWDP_ru6
/* 785 */     MCD_OPC_FilterValue, 1, 128, 2, 0, // Skip to: 1430
/* 790 */     MCD_OPC_Decode, 128, 3, 10, // Opcode: LDWSP_ru6
/* 794 */     MCD_OPC_FilterValue, 12, 21, 0, 0, // Skip to: 820
/* 799 */     MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 802 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 811
/* 807 */     MCD_OPC_Decode, 237, 2, 10, // Opcode: LDAWDP_ru6
/* 811 */     MCD_OPC_FilterValue, 1, 102, 2, 0, // Skip to: 1430
/* 816 */     MCD_OPC_Decode, 241, 2, 10, // Opcode: LDAWSP_ru6
/* 820 */     MCD_OPC_FilterValue, 13, 21, 0, 0, // Skip to: 846
/* 825 */     MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 828 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 837
/* 833 */     MCD_OPC_Decode, 243, 2, 10, // Opcode: LDC_ru6
/* 837 */     MCD_OPC_FilterValue, 1, 76, 2, 0, // Skip to: 1430
/* 842 */     MCD_OPC_Decode, 251, 2, 10, // Opcode: LDWCP_ru6
/* 846 */     MCD_OPC_FilterValue, 14, 99, 0, 0, // Skip to: 950
/* 851 */     MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 854 */     MCD_OPC_FilterValue, 0, 43, 0, 0, // Skip to: 902
/* 859 */     MCD_OPC_ExtractField, 6, 4,  // Inst{9-6} ...
/* 862 */     MCD_OPC_FilterValue, 12, 4, 0, 0, // Skip to: 871
/* 867 */     MCD_OPC_Decode, 153, 2, 11, // Opcode: BRFU_u6
/* 871 */     MCD_OPC_FilterValue, 13, 4, 0, 0, // Skip to: 880
/* 876 */     MCD_OPC_Decode, 136, 2, 11, // Opcode: BLAT_u6
/* 880 */     MCD_OPC_FilterValue, 14, 4, 0, 0, // Skip to: 889
/* 885 */     MCD_OPC_Decode, 186, 2, 11, // Opcode: EXTDP_u6
/* 889 */     MCD_OPC_FilterValue, 15, 4, 0, 0, // Skip to: 898
/* 894 */     MCD_OPC_Decode, 216, 2, 11, // Opcode: KCALL_u6
/* 898 */     MCD_OPC_Decode, 151, 2, 12, // Opcode: BRFT_ru6
/* 902 */     MCD_OPC_FilterValue, 1, 11, 2, 0, // Skip to: 1430
/* 907 */     MCD_OPC_ExtractField, 6, 4,  // Inst{9-6} ...
/* 910 */     MCD_OPC_FilterValue, 12, 4, 0, 0, // Skip to: 919
/* 915 */     MCD_OPC_Decode, 147, 2, 13, // Opcode: BRBU_u6
/* 919 */     MCD_OPC_FilterValue, 13, 4, 0, 0, // Skip to: 928
/* 924 */     MCD_OPC_Decode, 182, 2, 11, // Opcode: ENTSP_u6
/* 928 */     MCD_OPC_FilterValue, 14, 4, 0, 0, // Skip to: 937
/* 933 */     MCD_OPC_Decode, 188, 2, 11, // Opcode: EXTSP_u6
/* 937 */     MCD_OPC_FilterValue, 15, 4, 0, 0, // Skip to: 946
/* 942 */     MCD_OPC_Decode, 155, 3, 11, // Opcode: RETSP_u6
/* 946 */     MCD_OPC_Decode, 145, 2, 14, // Opcode: BRBT_ru6
/* 950 */     MCD_OPC_FilterValue, 15, 81, 0, 0, // Skip to: 1036
/* 955 */     MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 958 */     MCD_OPC_FilterValue, 0, 43, 0, 0, // Skip to: 1006
/* 963 */     MCD_OPC_ExtractField, 6, 4,  // Inst{9-6} ...
/* 966 */     MCD_OPC_FilterValue, 12, 4, 0, 0, // Skip to: 975
/* 971 */     MCD_OPC_Decode, 163, 2, 11, // Opcode: CLRSR_u6
/* 975 */     MCD_OPC_FilterValue, 13, 4, 0, 0, // Skip to: 984
/* 980 */     MCD_OPC_Decode, 174, 3, 11, // Opcode: SETSR_u6
/* 984 */     MCD_OPC_FilterValue, 14, 4, 0, 0, // Skip to: 993
/* 989 */     MCD_OPC_Decode, 218, 2, 11, // Opcode: KENTSP_u6
/* 993 */     MCD_OPC_FilterValue, 15, 4, 0, 0, // Skip to: 1002
/* 998 */     MCD_OPC_Decode, 220, 2, 11, // Opcode: KRESTSP_u6
/* 1002 */    MCD_OPC_Decode, 149, 2, 12, // Opcode: BRFF_ru6
/* 1006 */    MCD_OPC_FilterValue, 1, 163, 1, 0, // Skip to: 1430
/* 1011 */    MCD_OPC_ExtractField, 6, 4,  // Inst{9-6} ...
/* 1014 */    MCD_OPC_FilterValue, 12, 4, 0, 0, // Skip to: 1023
/* 1019 */    MCD_OPC_Decode, 201, 2, 11, // Opcode: GETSR_u6
/* 1023 */    MCD_OPC_FilterValue, 13, 4, 0, 0, // Skip to: 1032
/* 1028 */    MCD_OPC_Decode, 235, 2, 11, // Opcode: LDAWCP_u6
/* 1032 */    MCD_OPC_Decode, 143, 2, 14, // Opcode: BRBF_ru6
/* 1036 */    MCD_OPC_FilterValue, 16, 46, 0, 0, // Skip to: 1087
/* 1041 */    MCD_OPC_ExtractField, 4, 7,  // Inst{10-4} ...
/* 1044 */    MCD_OPC_FilterValue, 126, 4, 0, 0, // Skip to: 1053
/* 1049 */    MCD_OPC_Decode, 159, 2, 1, // Opcode: CLRPT_1R
/* 1053 */    MCD_OPC_FilterValue, 127, 4, 0, 0, // Skip to: 1062
/* 1058 */    MCD_OPC_Decode, 198, 3, 1, // Opcode: SYNCR_1r
/* 1062 */    MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 1065 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1074
/* 1070 */    MCD_OPC_Decode, 199, 2, 9, // Opcode: GETR_rus
/* 1074 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1083
/* 1079 */    MCD_OPC_Decode, 204, 2, 2, // Opcode: INCT_2r
/* 1083 */    MCD_OPC_Decode, 223, 2, 5, // Opcode: LD16S_3r
/* 1087 */    MCD_OPC_FilterValue, 17, 25, 0, 0, // Skip to: 1117
/* 1092 */    MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 1095 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1104
/* 1100 */    MCD_OPC_Decode, 143, 3, 2, // Opcode: NOT
/* 1104 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1113
/* 1109 */    MCD_OPC_Decode, 212, 2, 2, // Opcode: INT_2r
/* 1113 */    MCD_OPC_Decode, 224, 2, 5, // Opcode: LD8U_3r
/* 1117 */    MCD_OPC_FilterValue, 18, 25, 0, 0, // Skip to: 1147
/* 1122 */    MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 1125 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1134
/* 1130 */    MCD_OPC_Decode, 142, 3, 2, // Opcode: NEG
/* 1134 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1143
/* 1139 */    MCD_OPC_Decode, 180, 2, 2, // Opcode: ENDIN_2r
/* 1143 */    MCD_OPC_Decode, 253, 1, 3, // Opcode: ADD_2rus
/* 1147 */    MCD_OPC_FilterValue, 19, 4, 0, 0, // Skip to: 1156
/* 1152 */    MCD_OPC_Decode, 196, 3, 3, // Opcode: SUB_2rus
/* 1156 */    MCD_OPC_FilterValue, 20, 25, 0, 0, // Skip to: 1186
/* 1161 */    MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 1164 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1173
/* 1169 */    MCD_OPC_Decode, 138, 3, 2, // Opcode: MKMSK_2r
/* 1173 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1182
/* 1178 */    MCD_OPC_Decode, 139, 3, 15, // Opcode: MKMSK_rus
/* 1182 */    MCD_OPC_Decode, 179, 3, 16, // Opcode: SHL_2rus
/* 1186 */    MCD_OPC_FilterValue, 21, 25, 0, 0, // Skip to: 1216
/* 1191 */    MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 1194 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1203
/* 1199 */    MCD_OPC_Decode, 150, 3, 4, // Opcode: OUT_2r
/* 1203 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1212
/* 1208 */    MCD_OPC_Decode, 148, 3, 7, // Opcode: OUTSHR_2r
/* 1212 */    MCD_OPC_Decode, 181, 3, 16, // Opcode: SHR_2rus
/* 1216 */    MCD_OPC_FilterValue, 22, 25, 0, 0, // Skip to: 1246
/* 1221 */    MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 1224 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1233
/* 1229 */    MCD_OPC_Decode, 213, 2, 2, // Opcode: IN_2r
/* 1233 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1242
/* 1238 */    MCD_OPC_Decode, 211, 2, 7, // Opcode: INSHR_2r
/* 1242 */    MCD_OPC_Decode, 183, 2, 3, // Opcode: EQ_2rus
/* 1246 */    MCD_OPC_FilterValue, 23, 25, 0, 0, // Skip to: 1276
/* 1251 */    MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 1254 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1263
/* 1259 */    MCD_OPC_Decode, 151, 3, 2, // Opcode: PEEK_2r
/* 1263 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1272
/* 1268 */    MCD_OPC_Decode, 199, 3, 2, // Opcode: TESTCT_2r
/* 1272 */    MCD_OPC_Decode, 203, 3, 17, // Opcode: TSETR_3r
/* 1276 */    MCD_OPC_FilterValue, 24, 25, 0, 0, // Skip to: 1306
/* 1281 */    MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 1284 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1293
/* 1289 */    MCD_OPC_Decode, 166, 3, 4, // Opcode: SETPSC_2r
/* 1293 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1302
/* 1298 */    MCD_OPC_Decode, 201, 3, 2, // Opcode: TESTWCT_2r
/* 1302 */    MCD_OPC_Decode, 132, 3, 5, // Opcode: LSS_3r
/* 1306 */    MCD_OPC_FilterValue, 25, 25, 0, 0, // Skip to: 1336
/* 1311 */    MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 1314 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1323
/* 1319 */    MCD_OPC_Decode, 156, 2, 2, // Opcode: CHKCT_2r
/* 1323 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1332
/* 1328 */    MCD_OPC_Decode, 157, 2, 15, // Opcode: CHKCT_rus
/* 1332 */    MCD_OPC_Decode, 134, 3, 5, // Opcode: LSU_3r
/* 1336 */    MCD_OPC_FilterValue, 26, 21, 0, 0, // Skip to: 1362
/* 1341 */    MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 1344 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1353
/* 1349 */    MCD_OPC_Decode, 141, 2, 18, // Opcode: BLRF_u10
/* 1353 */    MCD_OPC_FilterValue, 1, 72, 0, 0, // Skip to: 1430
/* 1358 */    MCD_OPC_Decode, 139, 2, 19, // Opcode: BLRB_u10
/* 1362 */    MCD_OPC_FilterValue, 27, 21, 0, 0, // Skip to: 1388
/* 1367 */    MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 1370 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1379
/* 1375 */    MCD_OPC_Decode, 231, 2, 18, // Opcode: LDAPF_u10
/* 1379 */    MCD_OPC_FilterValue, 1, 46, 0, 0, // Skip to: 1430
/* 1384 */    MCD_OPC_Decode, 228, 2, 19, // Opcode: LDAPB_u10
/* 1388 */    MCD_OPC_FilterValue, 28, 21, 0, 0, // Skip to: 1414
/* 1393 */    MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 1396 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1405
/* 1401 */    MCD_OPC_Decode, 134, 2, 18, // Opcode: BLACP_u10
/* 1405 */    MCD_OPC_FilterValue, 1, 20, 0, 0, // Skip to: 1430
/* 1410 */    MCD_OPC_Decode, 252, 2, 18, // Opcode: LDWCP_u10
/* 1414 */    MCD_OPC_FilterValue, 29, 11, 0, 0, // Skip to: 1430
/* 1419 */    MCD_OPC_CheckField, 10, 1, 0, 4, 0, 0, // Skip to: 1430
/* 1426 */    MCD_OPC_Decode, 160, 3, 12, // Opcode: SETC_ru6
/* 1430 */    MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTable32[] = {
/* 0 */       MCD_OPC_ExtractField, 27, 5,  // Inst{31-27} ...
/* 3 */       MCD_OPC_FilterValue, 0, 103, 0, 0, // Skip to: 111
/* 8 */       MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 11 */      MCD_OPC_FilterValue, 31, 120, 4, 0, // Skip to: 1160
/* 16 */      MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 19 */      MCD_OPC_FilterValue, 0, 12, 0, 0, // Skip to: 36
/* 24 */      MCD_OPC_CheckField, 16, 11, 236, 15, 21, 0, 0, // Skip to: 53
/* 32 */      MCD_OPC_Decode, 132, 2, 20, // Opcode: BITREV_l2r
/* 36 */      MCD_OPC_FilterValue, 1, 12, 0, 0, // Skip to: 53
/* 41 */      MCD_OPC_CheckField, 16, 11, 236, 15, 4, 0, 0, // Skip to: 53
/* 49 */      MCD_OPC_Decode, 155, 2, 20, // Opcode: BYTEREV_l2r
/* 53 */      MCD_OPC_CheckField, 16, 11, 236, 15, 4, 0, 0, // Skip to: 65
/* 61 */      MCD_OPC_Decode, 195, 3, 21, // Opcode: STW_l3r
/* 65 */      MCD_OPC_ExtractField, 20, 7,  // Inst{26-20} ...
/* 68 */      MCD_OPC_FilterValue, 126, 4, 0, 0, // Skip to: 77
/* 73 */      MCD_OPC_Decode, 165, 2, 22, // Opcode: CRC8_l4r
/* 77 */      MCD_OPC_FilterValue, 127, 4, 0, 0, // Skip to: 86
/* 82 */      MCD_OPC_Decode, 136, 3, 23, // Opcode: MACCU_l4r
/* 86 */      MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 89 */      MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 98
/* 94 */      MCD_OPC_Decode, 245, 2, 24, // Opcode: LDIVU_l5r
/* 98 */      MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 107
/* 103 */     MCD_OPC_Decode, 222, 2, 24, // Opcode: LADD_l5r
/* 107 */     MCD_OPC_Decode, 131, 3, 25, // Opcode: LMUL_l6r
/* 111 */     MCD_OPC_FilterValue, 1, 98, 0, 0, // Skip to: 214
/* 116 */     MCD_OPC_ExtractField, 11, 5,  // Inst{15-11} ...
/* 119 */     MCD_OPC_FilterValue, 31, 12, 4, 0, // Skip to: 1160
/* 124 */     MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 127 */     MCD_OPC_FilterValue, 0, 4, 4, 0, // Skip to: 1160
/* 132 */     MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 135 */     MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 158
/* 140 */     MCD_OPC_CheckField, 21, 6, 63, 34, 0, 0, // Skip to: 181
/* 147 */     MCD_OPC_CheckField, 16, 4, 12, 27, 0, 0, // Skip to: 181
/* 154 */     MCD_OPC_Decode, 164, 2, 20, // Opcode: CLZ_l2r
/* 158 */     MCD_OPC_FilterValue, 1, 18, 0, 0, // Skip to: 181
/* 163 */     MCD_OPC_CheckField, 21, 6, 63, 11, 0, 0, // Skip to: 181
/* 170 */     MCD_OPC_CheckField, 16, 4, 12, 4, 0, 0, // Skip to: 181
/* 177 */     MCD_OPC_Decode, 156, 3, 26, // Opcode: SETCLK_l2r
/* 181 */     MCD_OPC_CheckField, 21, 6, 63, 11, 0, 0, // Skip to: 199
/* 188 */     MCD_OPC_CheckField, 16, 4, 12, 4, 0, 0, // Skip to: 199
/* 195 */     MCD_OPC_Decode, 208, 3, 21, // Opcode: XOR_l3r
/* 199 */     MCD_OPC_CheckField, 21, 6, 63, 4, 0, 0, // Skip to: 210
/* 206 */     MCD_OPC_Decode, 135, 3, 23, // Opcode: MACCS_l4r
/* 210 */     MCD_OPC_Decode, 133, 3, 24, // Opcode: LSUB_l5r
/* 214 */     MCD_OPC_FilterValue, 2, 35, 0, 0, // Skip to: 254
/* 219 */     MCD_OPC_ExtractField, 11, 16,  // Inst{26-11} ...
/* 222 */     MCD_OPC_FilterValue, 159, 251, 3, 163, 3, 0, // Skip to: 1160
/* 229 */     MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 232 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 241
/* 237 */     MCD_OPC_Decode, 207, 2, 20, // Opcode: INITLR_l2r
/* 241 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 250
/* 246 */     MCD_OPC_Decode, 198, 2, 20, // Opcode: GETPS_l2r
/* 250 */     MCD_OPC_Decode, 130, 2, 21, // Opcode: ASHR_l3r
/* 254 */     MCD_OPC_FilterValue, 3, 35, 0, 0, // Skip to: 294
/* 259 */     MCD_OPC_ExtractField, 11, 16,  // Inst{26-11} ...
/* 262 */     MCD_OPC_FilterValue, 159, 251, 3, 123, 3, 0, // Skip to: 1160
/* 269 */     MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 272 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 281
/* 277 */     MCD_OPC_Decode, 167, 3, 26, // Opcode: SETPS_l2r
/* 281 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 290
/* 286 */     MCD_OPC_Decode, 191, 2, 20, // Opcode: GETD_l2r
/* 290 */     MCD_OPC_Decode, 239, 2, 21, // Opcode: LDAWF_l3r
/* 294 */     MCD_OPC_FilterValue, 4, 35, 0, 0, // Skip to: 334
/* 299 */     MCD_OPC_ExtractField, 11, 16,  // Inst{26-11} ...
/* 302 */     MCD_OPC_FilterValue, 159, 251, 3, 83, 3, 0, // Skip to: 1160
/* 309 */     MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 312 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 321
/* 317 */     MCD_OPC_Decode, 200, 3, 20, // Opcode: TESTLCL_l2r
/* 321 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 330
/* 326 */     MCD_OPC_Decode, 175, 3, 26, // Opcode: SETTW_l2r
/* 330 */     MCD_OPC_Decode, 233, 2, 21, // Opcode: LDAWB_l3r
/* 334 */     MCD_OPC_FilterValue, 5, 35, 0, 0, // Skip to: 374
/* 339 */     MCD_OPC_ExtractField, 11, 16,  // Inst{26-11} ...
/* 342 */     MCD_OPC_FilterValue, 159, 251, 3, 43, 3, 0, // Skip to: 1160
/* 349 */     MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 352 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 361
/* 357 */     MCD_OPC_Decode, 169, 3, 26, // Opcode: SETRDY_l2r
/* 361 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 370
/* 366 */     MCD_OPC_Decode, 158, 3, 20, // Opcode: SETC_l2r
/* 370 */     MCD_OPC_Decode, 226, 2, 21, // Opcode: LDA16F_l3r
/* 374 */     MCD_OPC_FilterValue, 6, 35, 0, 0, // Skip to: 414
/* 379 */     MCD_OPC_ExtractField, 11, 16,  // Inst{26-11} ...
/* 382 */     MCD_OPC_FilterValue, 159, 251, 3, 3, 3, 0, // Skip to: 1160
/* 389 */     MCD_OPC_ExtractField, 4, 1,  // Inst{4} ...
/* 392 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 401
/* 397 */     MCD_OPC_Decode, 165, 3, 26, // Opcode: SETN_l2r
/* 401 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 410
/* 406 */     MCD_OPC_Decode, 197, 2, 20, // Opcode: GETN_l2r
/* 410 */     MCD_OPC_Decode, 225, 2, 21, // Opcode: LDA16B_l3r
/* 414 */     MCD_OPC_FilterValue, 7, 13, 0, 0, // Skip to: 432
/* 419 */     MCD_OPC_CheckField, 11, 16, 159, 251, 3, 220, 2, 0, // Skip to: 1160
/* 428 */     MCD_OPC_Decode, 141, 3, 21, // Opcode: MUL_l3r
/* 432 */     MCD_OPC_FilterValue, 8, 13, 0, 0, // Skip to: 450
/* 437 */     MCD_OPC_CheckField, 11, 16, 159, 251, 3, 202, 2, 0, // Skip to: 1160
/* 446 */     MCD_OPC_Decode, 170, 2, 21, // Opcode: DIVS_l3r
/* 450 */     MCD_OPC_FilterValue, 9, 13, 0, 0, // Skip to: 468
/* 455 */     MCD_OPC_CheckField, 11, 16, 159, 251, 3, 184, 2, 0, // Skip to: 1160
/* 464 */     MCD_OPC_Decode, 171, 2, 21, // Opcode: DIVU_l3r
/* 468 */     MCD_OPC_FilterValue, 10, 35, 0, 0, // Skip to: 508
/* 473 */     MCD_OPC_ExtractField, 26, 1,  // Inst{26} ...
/* 476 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 492
/* 481 */     MCD_OPC_CheckField, 10, 6, 60, 160, 2, 0, // Skip to: 1160
/* 488 */     MCD_OPC_Decode, 190, 3, 27, // Opcode: STWDP_lru6
/* 492 */     MCD_OPC_FilterValue, 1, 151, 2, 0, // Skip to: 1160
/* 497 */     MCD_OPC_CheckField, 10, 6, 60, 144, 2, 0, // Skip to: 1160
/* 504 */     MCD_OPC_Decode, 192, 3, 27, // Opcode: STWSP_lru6
/* 508 */     MCD_OPC_FilterValue, 11, 35, 0, 0, // Skip to: 548
/* 513 */     MCD_OPC_ExtractField, 26, 1,  // Inst{26} ...
/* 516 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 532
/* 521 */     MCD_OPC_CheckField, 10, 6, 60, 120, 2, 0, // Skip to: 1160
/* 528 */     MCD_OPC_Decode, 253, 2, 27, // Opcode: LDWDP_lru6
/* 532 */     MCD_OPC_FilterValue, 1, 111, 2, 0, // Skip to: 1160
/* 537 */     MCD_OPC_CheckField, 10, 6, 60, 104, 2, 0, // Skip to: 1160
/* 544 */     MCD_OPC_Decode, 255, 2, 27, // Opcode: LDWSP_lru6
/* 548 */     MCD_OPC_FilterValue, 12, 35, 0, 0, // Skip to: 588
/* 553 */     MCD_OPC_ExtractField, 26, 1,  // Inst{26} ...
/* 556 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 572
/* 561 */     MCD_OPC_CheckField, 10, 6, 60, 80, 2, 0, // Skip to: 1160
/* 568 */     MCD_OPC_Decode, 236, 2, 27, // Opcode: LDAWDP_lru6
/* 572 */     MCD_OPC_FilterValue, 1, 71, 2, 0, // Skip to: 1160
/* 577 */     MCD_OPC_CheckField, 10, 6, 60, 64, 2, 0, // Skip to: 1160
/* 584 */     MCD_OPC_Decode, 240, 2, 27, // Opcode: LDAWSP_lru6
/* 588 */     MCD_OPC_FilterValue, 13, 35, 0, 0, // Skip to: 628
/* 593 */     MCD_OPC_ExtractField, 26, 1,  // Inst{26} ...
/* 596 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 612
/* 601 */     MCD_OPC_CheckField, 10, 6, 60, 40, 2, 0, // Skip to: 1160
/* 608 */     MCD_OPC_Decode, 242, 2, 27, // Opcode: LDC_lru6
/* 612 */     MCD_OPC_FilterValue, 1, 31, 2, 0, // Skip to: 1160
/* 617 */     MCD_OPC_CheckField, 10, 6, 60, 24, 2, 0, // Skip to: 1160
/* 624 */     MCD_OPC_Decode, 249, 2, 27, // Opcode: LDWCP_lru6
/* 628 */     MCD_OPC_FilterValue, 14, 115, 0, 0, // Skip to: 748
/* 633 */     MCD_OPC_ExtractField, 26, 1,  // Inst{26} ...
/* 636 */     MCD_OPC_FilterValue, 0, 51, 0, 0, // Skip to: 692
/* 641 */     MCD_OPC_ExtractField, 10, 6,  // Inst{15-10} ...
/* 644 */     MCD_OPC_FilterValue, 60, 255, 1, 0, // Skip to: 1160
/* 649 */     MCD_OPC_ExtractField, 22, 4,  // Inst{25-22} ...
/* 652 */     MCD_OPC_FilterValue, 12, 4, 0, 0, // Skip to: 661
/* 657 */     MCD_OPC_Decode, 152, 2, 28, // Opcode: BRFU_lu6
/* 661 */     MCD_OPC_FilterValue, 13, 4, 0, 0, // Skip to: 670
/* 666 */     MCD_OPC_Decode, 135, 2, 28, // Opcode: BLAT_lu6
/* 670 */     MCD_OPC_FilterValue, 14, 4, 0, 0, // Skip to: 679
/* 675 */     MCD_OPC_Decode, 185, 2, 28, // Opcode: EXTDP_lu6
/* 679 */     MCD_OPC_FilterValue, 15, 4, 0, 0, // Skip to: 688
/* 684 */     MCD_OPC_Decode, 215, 2, 28, // Opcode: KCALL_lu6
/* 688 */     MCD_OPC_Decode, 150, 2, 29, // Opcode: BRFT_lru6
/* 692 */     MCD_OPC_FilterValue, 1, 207, 1, 0, // Skip to: 1160
/* 697 */     MCD_OPC_ExtractField, 10, 6,  // Inst{15-10} ...
/* 700 */     MCD_OPC_FilterValue, 60, 199, 1, 0, // Skip to: 1160
/* 705 */     MCD_OPC_ExtractField, 22, 4,  // Inst{25-22} ...
/* 708 */     MCD_OPC_FilterValue, 12, 4, 0, 0, // Skip to: 717
/* 713 */     MCD_OPC_Decode, 146, 2, 30, // Opcode: BRBU_lu6
/* 717 */     MCD_OPC_FilterValue, 13, 4, 0, 0, // Skip to: 726
/* 722 */     MCD_OPC_Decode, 181, 2, 28, // Opcode: ENTSP_lu6
/* 726 */     MCD_OPC_FilterValue, 14, 4, 0, 0, // Skip to: 735
/* 731 */     MCD_OPC_Decode, 187, 2, 28, // Opcode: EXTSP_lu6
/* 735 */     MCD_OPC_FilterValue, 15, 4, 0, 0, // Skip to: 744
/* 740 */     MCD_OPC_Decode, 154, 3, 28, // Opcode: RETSP_lu6
/* 744 */     MCD_OPC_Decode, 144, 2, 31, // Opcode: BRBT_lru6
/* 748 */     MCD_OPC_FilterValue, 15, 97, 0, 0, // Skip to: 850
/* 753 */     MCD_OPC_ExtractField, 26, 1,  // Inst{26} ...
/* 756 */     MCD_OPC_FilterValue, 0, 51, 0, 0, // Skip to: 812
/* 761 */     MCD_OPC_ExtractField, 10, 6,  // Inst{15-10} ...
/* 764 */     MCD_OPC_FilterValue, 60, 135, 1, 0, // Skip to: 1160
/* 769 */     MCD_OPC_ExtractField, 22, 4,  // Inst{25-22} ...
/* 772 */     MCD_OPC_FilterValue, 12, 4, 0, 0, // Skip to: 781
/* 777 */     MCD_OPC_Decode, 162, 2, 28, // Opcode: CLRSR_lu6
/* 781 */     MCD_OPC_FilterValue, 13, 4, 0, 0, // Skip to: 790
/* 786 */     MCD_OPC_Decode, 173, 3, 28, // Opcode: SETSR_lu6
/* 790 */     MCD_OPC_FilterValue, 14, 4, 0, 0, // Skip to: 799
/* 795 */     MCD_OPC_Decode, 217, 2, 28, // Opcode: KENTSP_lu6
/* 799 */     MCD_OPC_FilterValue, 15, 4, 0, 0, // Skip to: 808
/* 804 */     MCD_OPC_Decode, 219, 2, 28, // Opcode: KRESTSP_lu6
/* 808 */     MCD_OPC_Decode, 148, 2, 29, // Opcode: BRFF_lru6
/* 812 */     MCD_OPC_FilterValue, 1, 87, 1, 0, // Skip to: 1160
/* 817 */     MCD_OPC_ExtractField, 10, 6,  // Inst{15-10} ...
/* 820 */     MCD_OPC_FilterValue, 60, 79, 1, 0, // Skip to: 1160
/* 825 */     MCD_OPC_ExtractField, 22, 4,  // Inst{25-22} ...
/* 828 */     MCD_OPC_FilterValue, 12, 4, 0, 0, // Skip to: 837
/* 833 */     MCD_OPC_Decode, 200, 2, 28, // Opcode: GETSR_lu6
/* 837 */     MCD_OPC_FilterValue, 13, 4, 0, 0, // Skip to: 846
/* 842 */     MCD_OPC_Decode, 234, 2, 28, // Opcode: LDAWCP_lu6
/* 846 */     MCD_OPC_Decode, 142, 2, 31, // Opcode: BRBF_lru6
/* 850 */     MCD_OPC_FilterValue, 16, 13, 0, 0, // Skip to: 868
/* 855 */     MCD_OPC_CheckField, 11, 16, 159, 251, 3, 40, 1, 0, // Skip to: 1160
/* 864 */     MCD_OPC_Decode, 184, 3, 21, // Opcode: ST16_l3r
/* 868 */     MCD_OPC_FilterValue, 17, 13, 0, 0, // Skip to: 886
/* 873 */     MCD_OPC_CheckField, 11, 16, 159, 251, 3, 22, 1, 0, // Skip to: 1160
/* 882 */     MCD_OPC_Decode, 185, 3, 21, // Opcode: ST8_l3r
/* 886 */     MCD_OPC_FilterValue, 18, 36, 0, 0, // Skip to: 927
/* 891 */     MCD_OPC_ExtractField, 11, 16,  // Inst{26-11} ...
/* 894 */     MCD_OPC_FilterValue, 159, 251, 3, 4, 0, 0, // Skip to: 905
/* 901 */     MCD_OPC_Decode, 129, 2, 32, // Opcode: ASHR_l2rus
/* 905 */     MCD_OPC_FilterValue, 191, 251, 3, 4, 0, 0, // Skip to: 916
/* 912 */     MCD_OPC_Decode, 147, 3, 32, // Opcode: OUTPW_l2rus
/* 916 */     MCD_OPC_FilterValue, 223, 251, 3, 237, 0, 0, // Skip to: 1160
/* 923 */     MCD_OPC_Decode, 210, 2, 32, // Opcode: INPW_l2rus
/* 927 */     MCD_OPC_FilterValue, 19, 13, 0, 0, // Skip to: 945
/* 932 */     MCD_OPC_CheckField, 11, 16, 159, 251, 3, 219, 0, 0, // Skip to: 1160
/* 941 */     MCD_OPC_Decode, 238, 2, 33, // Opcode: LDAWF_l2rus
/* 945 */     MCD_OPC_FilterValue, 20, 13, 0, 0, // Skip to: 963
/* 950 */     MCD_OPC_CheckField, 11, 16, 159, 251, 3, 201, 0, 0, // Skip to: 1160
/* 959 */     MCD_OPC_Decode, 232, 2, 33, // Opcode: LDAWB_l2rus
/* 963 */     MCD_OPC_FilterValue, 21, 13, 0, 0, // Skip to: 981
/* 968 */     MCD_OPC_CheckField, 11, 16, 159, 251, 3, 183, 0, 0, // Skip to: 1160
/* 977 */     MCD_OPC_Decode, 166, 2, 34, // Opcode: CRC_l3r
/* 981 */     MCD_OPC_FilterValue, 24, 13, 0, 0, // Skip to: 999
/* 986 */     MCD_OPC_CheckField, 11, 16, 159, 251, 3, 165, 0, 0, // Skip to: 1160
/* 995 */     MCD_OPC_Decode, 152, 3, 21, // Opcode: REMS_l3r
/* 999 */     MCD_OPC_FilterValue, 25, 13, 0, 0, // Skip to: 1017
/* 1004 */    MCD_OPC_CheckField, 11, 16, 159, 251, 3, 147, 0, 0, // Skip to: 1160
/* 1013 */    MCD_OPC_Decode, 153, 3, 21, // Opcode: REMU_l3r
/* 1017 */    MCD_OPC_FilterValue, 26, 35, 0, 0, // Skip to: 1057
/* 1022 */    MCD_OPC_ExtractField, 26, 1,  // Inst{26} ...
/* 1025 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1041
/* 1030 */    MCD_OPC_CheckField, 10, 6, 60, 123, 0, 0, // Skip to: 1160
/* 1037 */    MCD_OPC_Decode, 140, 2, 35, // Opcode: BLRF_lu10
/* 1041 */    MCD_OPC_FilterValue, 1, 114, 0, 0, // Skip to: 1160
/* 1046 */    MCD_OPC_CheckField, 10, 6, 60, 107, 0, 0, // Skip to: 1160
/* 1053 */    MCD_OPC_Decode, 138, 2, 36, // Opcode: BLRB_lu10
/* 1057 */    MCD_OPC_FilterValue, 27, 35, 0, 0, // Skip to: 1097
/* 1062 */    MCD_OPC_ExtractField, 26, 1,  // Inst{26} ...
/* 1065 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1081
/* 1070 */    MCD_OPC_CheckField, 10, 6, 60, 83, 0, 0, // Skip to: 1160
/* 1077 */    MCD_OPC_Decode, 229, 2, 35, // Opcode: LDAPF_lu10
/* 1081 */    MCD_OPC_FilterValue, 1, 74, 0, 0, // Skip to: 1160
/* 1086 */    MCD_OPC_CheckField, 10, 6, 60, 67, 0, 0, // Skip to: 1160
/* 1093 */    MCD_OPC_Decode, 227, 2, 36, // Opcode: LDAPB_lu10
/* 1097 */    MCD_OPC_FilterValue, 28, 35, 0, 0, // Skip to: 1137
/* 1102 */    MCD_OPC_ExtractField, 26, 1,  // Inst{26} ...
/* 1105 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1121
/* 1110 */    MCD_OPC_CheckField, 10, 6, 60, 43, 0, 0, // Skip to: 1160
/* 1117 */    MCD_OPC_Decode, 133, 2, 35, // Opcode: BLACP_lu10
/* 1121 */    MCD_OPC_FilterValue, 1, 34, 0, 0, // Skip to: 1160
/* 1126 */    MCD_OPC_CheckField, 10, 6, 60, 27, 0, 0, // Skip to: 1160
/* 1133 */    MCD_OPC_Decode, 250, 2, 35, // Opcode: LDWCP_lu10
/* 1137 */    MCD_OPC_FilterValue, 29, 18, 0, 0, // Skip to: 1160
/* 1142 */    MCD_OPC_CheckField, 26, 1, 0, 11, 0, 0, // Skip to: 1160
/* 1149 */    MCD_OPC_CheckField, 10, 6, 60, 4, 0, 0, // Skip to: 1160
/* 1156 */    MCD_OPC_Decode, 159, 3, 29, // Opcode: SETC_lru6
/* 1160 */    MCD_OPC_Fail,
  0
};

static bool getbool(uint64_t b)
{
	return b != 0;
}
static bool checkDecoderPredicate(unsigned Idx, uint64_t Bits) {
  llvm_unreachable("Invalid index!");
}

#define DecodeToMCInst(fname, fieldname, InsnType) \
static DecodeStatus fname(DecodeStatus S, unsigned Idx, InsnType insn, MCInst *MI, \
                uint64_t Address, bool *Decoder) {\
  InsnType tmp;\
  switch (Idx) {\
  default: llvm_unreachable("Invalid index!");\
  case 0:\
    return S;\
  case 1:\
    tmp = fieldFromInstruction(insn, 0, 4);\
    if (DecodeGRRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 2:\
    if (Decode2RInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 3:\
    if (Decode2RUSInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 4:\
    if (DecodeR2RInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 5:\
    if (Decode3RInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 6:\
    if (Decode2RImmInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 7:\
    if (Decode2RSrcDstInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 8:\
    if (DecodeRUSSrcDstBitpInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 9:\
    if (DecodeRUSInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 10:\
    tmp = fieldFromInstruction(insn, 6, 4);\
    if (DecodeRRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 6);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 11:\
    tmp = fieldFromInstruction(insn, 0, 6);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 12:\
    tmp = fieldFromInstruction(insn, 6, 4);\
    if (DecodeGRRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 6);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 13:\
    tmp = fieldFromInstruction(insn, 0, 6);\
    if (DecodeNegImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 14:\
    tmp = fieldFromInstruction(insn, 6, 4);\
    if (DecodeGRRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 6);\
    if (DecodeNegImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 15:\
    if (DecodeRUSBitpInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 16:\
    if (Decode2RUSBitpInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 17:\
    if (Decode3RImmInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 18:\
    tmp = fieldFromInstruction(insn, 0, 10);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 19:\
    tmp = fieldFromInstruction(insn, 0, 10);\
    if (DecodeNegImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 20:\
    if (DecodeL2RInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 21:\
    if (DecodeL3RInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 22:\
    if (DecodeL4RSrcDstInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 23:\
    if (DecodeL4RSrcDstSrcDstInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 24:\
    if (DecodeL5RInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 25:\
    if (DecodeL6RInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 26:\
    if (DecodeLR2RInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 27:\
    tmp = fieldFromInstruction(insn, 22, 4);\
    if (DecodeRRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = 0x0;\
    tmp |= fieldFromInstruction(insn, 0, 10) << 6;\
    tmp |= fieldFromInstruction(insn, 16, 6) << 0;\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 28:\
    tmp = 0x0;\
    tmp |= fieldFromInstruction(insn, 0, 10) << 6;\
    tmp |= fieldFromInstruction(insn, 16, 6) << 0;\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 29:\
    tmp = fieldFromInstruction(insn, 22, 4);\
    if (DecodeGRRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = 0x0;\
    tmp |= fieldFromInstruction(insn, 0, 10) << 6;\
    tmp |= fieldFromInstruction(insn, 16, 6) << 0;\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 30:\
    tmp = 0x0;\
    tmp |= fieldFromInstruction(insn, 0, 10) << 6;\
    tmp |= fieldFromInstruction(insn, 16, 6) << 0;\
    if (DecodeNegImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 31:\
    tmp = fieldFromInstruction(insn, 22, 4);\
    if (DecodeGRRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = 0x0;\
    tmp |= fieldFromInstruction(insn, 0, 10) << 6;\
    tmp |= fieldFromInstruction(insn, 16, 6) << 0;\
    if (DecodeNegImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 32:\
    if (DecodeL2RUSBitpInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 33:\
    if (DecodeL2RUSInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 34:\
    if (DecodeL3RSrcDstInstruction(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 35:\
    tmp = 0x0;\
    tmp |= fieldFromInstruction(insn, 0, 10) << 10;\
    tmp |= fieldFromInstruction(insn, 16, 10) << 0;\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 36:\
    tmp = 0x0;\
    tmp |= fieldFromInstruction(insn, 0, 10) << 10;\
    tmp |= fieldFromInstruction(insn, 16, 10) << 0;\
    if (DecodeNegImmOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  }\
}\

#define DecodeInstruction(fname, fieldname, decoder, InsnType) \
static DecodeStatus fname(const uint8_t DecodeTable[], MCInst *MI, \
           InsnType insn, uint64_t Address, MCRegisterInfo *MRI, int feature) \
{ \
  unsigned Start, Len, NumToSkip, PIdx, Opc, DecodeIdx; \
  InsnType Val, FieldValue, PositiveMask, NegativeMask; \
  bool Pred, Fail, DecodeComplete = true; \
  uint32_t ExpectedValue; \
  const uint8_t *Ptr = DecodeTable; \
  uint32_t CurFieldValue = 0; \
  DecodeStatus S = MCDisassembler_Success; \
  while (true) { \
    switch (*Ptr) { \
    default: \
      return MCDisassembler_Fail; \
    case MCD_OPC_ExtractField: { \
      Start = *++Ptr; \
      Len = *++Ptr; \
      ++Ptr; \
      CurFieldValue = fieldname(insn, Start, Len); \
      break; \
    } \
    case MCD_OPC_FilterValue: { \
      /* Decode the field value. */ \
      Val = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      /* NumToSkip is a plain 24-bit integer. */ \
      NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      NumToSkip |= (*Ptr++) << 16; \
      /* Perform the filter operation. */ \
      if (Val != CurFieldValue) \
        Ptr += NumToSkip; \
      break; \
    } \
    case MCD_OPC_CheckField: { \
      Start = *++Ptr; \
      Len = *++Ptr; \
      FieldValue = fieldname(insn, Start, Len); \
      /* Decode the field value. */ \
      ExpectedValue = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      /* NumToSkip is a plain 24-bit integer. */ \
      NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      NumToSkip |= (*Ptr++) << 16; \
      /* If the actual and expected values don't match, skip. */ \
      if (ExpectedValue != FieldValue) \
        Ptr += NumToSkip; \
      break; \
    } \
    case MCD_OPC_CheckPredicate: { \
      /* Decode the Predicate Index value. */ \
      PIdx = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      /* NumToSkip is a plain 24-bit integer. */ \
      NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      NumToSkip |= (*Ptr++) << 16; \
      /* Check the predicate. */ \
      if (!(Pred = checkDecoderPredicate(PIdx, feature))) \
        Ptr += NumToSkip; \
		/* printf("55 PIdx = %u, Pred = %u\n", PIdx, Pred); */ \
      (void)Pred; \
      break; \
    } \
    case MCD_OPC_Decode: { \
      /* Decode the Opcode value. */ \
      Opc = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      DecodeIdx = decodeULEB128(Ptr, &Len); \
      Ptr += Len; \
      MCInst_clear(MI); \
      MCInst_setOpcode(MI, Opc); \
      S = decoder(S, DecodeIdx, insn, MI, Address, &DecodeComplete); \
      /* assert(DecodeComplete); */ \
      return S; \
    } \
    case MCD_OPC_TryDecode: { \
      /* Decode the Opcode value. */ \
      Opc = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      DecodeIdx = decodeULEB128(Ptr, &Len); \
      Ptr += Len; \
      /* NumToSkip is a plain 24-bit integer. */ \
      NumToSkip = *Ptr++; \
      NumToSkip |= (*Ptr++) << 8; \
      NumToSkip |= (*Ptr++) << 16; \
      /* Perform the decode operation. */ \
      MCInst_setOpcode(MI, Opc); \
      S = decoder(S, DecodeIdx, insn, MI, Address, &DecodeComplete); \
      if (DecodeComplete) { \
        /* Decoding complete. */ \
        return S; \
      } else { \
        /* assert(S == MCDisassembler_Fail); */ \
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
      PositiveMask = decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      NegativeMask = decodeULEB128(Ptr, &Len); \
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
  /* llvm_unreachable("bogosity detected in disassembler state machine!");*/  \
}

FieldFromInstruction(fieldFromInstruction, uint32_t)
DecodeToMCInst(decodeToMCInst, fieldFromInstruction, uint32_t)
DecodeInstruction(decodeInstruction, fieldFromInstruction, decodeToMCInst, uint32_t)

#endif // MIPS_GET_DISASSEMBLER
#ifdef GET_REGINFO_ENUM
#undef GET_REGINFO_ENUM

#define XCore_CP 1
#define XCore_DP 2
#define XCore_LR 3
#define XCore_SP 4
#define XCore_R0 5
#define XCore_R1 6
#define XCore_R2 7
#define XCore_R3 8
#define XCore_R4 9
#define XCore_R5 10
#define XCore_R6 11
#define XCore_R7 12
#define XCore_R8 13
#define XCore_R9 14
#define XCore_R10 15
#define XCore_R11 16
#define XCore_NUM_TARGET_REGS 17


// Register classes

#define XCore_RRegsRegClassID 0
#define XCore_GRRegsRegClassID 1

#endif // GET_REGINFO_ENUM

#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM
#define XCore_PHI	 0
#define XCore_INLINEASM	 1
#define XCore_INLINEASM_BR	 2
#define XCore_CFI_INSTRUCTION	 3
#define XCore_EH_LABEL	 4
#define XCore_GC_LABEL	 5
#define XCore_ANNOTATION_LABEL	 6
#define XCore_KILL	 7
#define XCore_EXTRACT_SUBREG	 8
#define XCore_INSERT_SUBREG	 9
#define XCore_IMPLICIT_DEF	 10
#define XCore_SUBREG_TO_REG	 11
#define XCore_COPY_TO_REGCLASS	 12
#define XCore_DBG_VALUE	 13
#define XCore_DBG_VALUE_LIST	 14
#define XCore_DBG_INSTR_REF	 15
#define XCore_DBG_PHI	 16
#define XCore_DBG_LABEL	 17
#define XCore_REG_SEQUENCE	 18
#define XCore_COPY	 19
#define XCore_BUNDLE	 20
#define XCore_LIFETIME_START	 21
#define XCore_LIFETIME_END	 22
#define XCore_PSEUDO_PROBE	 23
#define XCore_ARITH_FENCE	 24
#define XCore_STACKMAP	 25
#define XCore_FENTRY_CALL	 26
#define XCore_PATCHPOINT	 27
#define XCore_LOAD_STACK_GUARD	 28
#define XCore_PREALLOCATED_SETUP	 29
#define XCore_PREALLOCATED_ARG	 30
#define XCore_STATEPOINT	 31
#define XCore_LOCAL_ESCAPE	 32
#define XCore_FAULTING_OP	 33
#define XCore_PATCHABLE_OP	 34
#define XCore_PATCHABLE_FUNCTION_ENTER	 35
#define XCore_PATCHABLE_RET	 36
#define XCore_PATCHABLE_FUNCTION_EXIT	 37
#define XCore_PATCHABLE_TAIL_CALL	 38
#define XCore_PATCHABLE_EVENT_CALL	 39
#define XCore_PATCHABLE_TYPED_EVENT_CALL	 40
#define XCore_ICALL_BRANCH_FUNNEL	 41
#define XCore_G_ASSERT_SEXT	 42
#define XCore_G_ASSERT_ZEXT	 43
#define XCore_G_ADD	 44
#define XCore_G_SUB	 45
#define XCore_G_MUL	 46
#define XCore_G_SDIV	 47
#define XCore_G_UDIV	 48
#define XCore_G_SREM	 49
#define XCore_G_UREM	 50
#define XCore_G_SDIVREM	 51
#define XCore_G_UDIVREM	 52
#define XCore_G_AND	 53
#define XCore_G_OR	 54
#define XCore_G_XOR	 55
#define XCore_G_IMPLICIT_DEF	 56
#define XCore_G_PHI	 57
#define XCore_G_FRAME_INDEX	 58
#define XCore_G_GLOBAL_VALUE	 59
#define XCore_G_EXTRACT	 60
#define XCore_G_UNMERGE_VALUES	 61
#define XCore_G_INSERT	 62
#define XCore_G_MERGE_VALUES	 63
#define XCore_G_BUILD_VECTOR	 64
#define XCore_G_BUILD_VECTOR_TRUNC	 65
#define XCore_G_CONCAT_VECTORS	 66
#define XCore_G_PTRTOINT	 67
#define XCore_G_INTTOPTR	 68
#define XCore_G_BITCAST	 69
#define XCore_G_FREEZE	 70
#define XCore_G_INTRINSIC_TRUNC	 71
#define XCore_G_INTRINSIC_ROUND	 72
#define XCore_G_INTRINSIC_LRINT	 73
#define XCore_G_INTRINSIC_ROUNDEVEN	 74
#define XCore_G_READCYCLECOUNTER	 75
#define XCore_G_LOAD	 76
#define XCore_G_SEXTLOAD	 77
#define XCore_G_ZEXTLOAD	 78
#define XCore_G_INDEXED_LOAD	 79
#define XCore_G_INDEXED_SEXTLOAD	 80
#define XCore_G_INDEXED_ZEXTLOAD	 81
#define XCore_G_STORE	 82
#define XCore_G_INDEXED_STORE	 83
#define XCore_G_ATOMIC_CMPXCHG_WITH_SUCCESS	 84
#define XCore_G_ATOMIC_CMPXCHG	 85
#define XCore_G_ATOMICRMW_XCHG	 86
#define XCore_G_ATOMICRMW_ADD	 87
#define XCore_G_ATOMICRMW_SUB	 88
#define XCore_G_ATOMICRMW_AND	 89
#define XCore_G_ATOMICRMW_NAND	 90
#define XCore_G_ATOMICRMW_OR	 91
#define XCore_G_ATOMICRMW_XOR	 92
#define XCore_G_ATOMICRMW_MAX	 93
#define XCore_G_ATOMICRMW_MIN	 94
#define XCore_G_ATOMICRMW_UMAX	 95
#define XCore_G_ATOMICRMW_UMIN	 96
#define XCore_G_ATOMICRMW_FADD	 97
#define XCore_G_ATOMICRMW_FSUB	 98
#define XCore_G_FENCE	 99
#define XCore_G_BRCOND	 100
#define XCore_G_BRINDIRECT	 101
#define XCore_G_INTRINSIC	 102
#define XCore_G_INTRINSIC_W_SIDE_EFFECTS	 103
#define XCore_G_ANYEXT	 104
#define XCore_G_TRUNC	 105
#define XCore_G_CONSTANT	 106
#define XCore_G_FCONSTANT	 107
#define XCore_G_VASTART	 108
#define XCore_G_VAARG	 109
#define XCore_G_SEXT	 110
#define XCore_G_SEXT_INREG	 111
#define XCore_G_ZEXT	 112
#define XCore_G_SHL	 113
#define XCore_G_LSHR	 114
#define XCore_G_ASHR	 115
#define XCore_G_FSHL	 116
#define XCore_G_FSHR	 117
#define XCore_G_ROTR	 118
#define XCore_G_ROTL	 119
#define XCore_G_ICMP	 120
#define XCore_G_FCMP	 121
#define XCore_G_SELECT	 122
#define XCore_G_UADDO	 123
#define XCore_G_UADDE	 124
#define XCore_G_USUBO	 125
#define XCore_G_USUBE	 126
#define XCore_G_SADDO	 127
#define XCore_G_SADDE	 128
#define XCore_G_SSUBO	 129
#define XCore_G_SSUBE	 130
#define XCore_G_UMULO	 131
#define XCore_G_SMULO	 132
#define XCore_G_UMULH	 133
#define XCore_G_SMULH	 134
#define XCore_G_UADDSAT	 135
#define XCore_G_SADDSAT	 136
#define XCore_G_USUBSAT	 137
#define XCore_G_SSUBSAT	 138
#define XCore_G_USHLSAT	 139
#define XCore_G_SSHLSAT	 140
#define XCore_G_SMULFIX	 141
#define XCore_G_UMULFIX	 142
#define XCore_G_SMULFIXSAT	 143
#define XCore_G_UMULFIXSAT	 144
#define XCore_G_SDIVFIX	 145
#define XCore_G_UDIVFIX	 146
#define XCore_G_SDIVFIXSAT	 147
#define XCore_G_UDIVFIXSAT	 148
#define XCore_G_FADD	 149
#define XCore_G_FSUB	 150
#define XCore_G_FMUL	 151
#define XCore_G_FMA	 152
#define XCore_G_FMAD	 153
#define XCore_G_FDIV	 154
#define XCore_G_FREM	 155
#define XCore_G_FPOW	 156
#define XCore_G_FPOWI	 157
#define XCore_G_FEXP	 158
#define XCore_G_FEXP2	 159
#define XCore_G_FLOG	 160
#define XCore_G_FLOG2	 161
#define XCore_G_FLOG10	 162
#define XCore_G_FNEG	 163
#define XCore_G_FPEXT	 164
#define XCore_G_FPTRUNC	 165
#define XCore_G_FPTOSI	 166
#define XCore_G_FPTOUI	 167
#define XCore_G_SITOFP	 168
#define XCore_G_UITOFP	 169
#define XCore_G_FABS	 170
#define XCore_G_FCOPYSIGN	 171
#define XCore_G_FCANONICALIZE	 172
#define XCore_G_FMINNUM	 173
#define XCore_G_FMAXNUM	 174
#define XCore_G_FMINNUM_IEEE	 175
#define XCore_G_FMAXNUM_IEEE	 176
#define XCore_G_FMINIMUM	 177
#define XCore_G_FMAXIMUM	 178
#define XCore_G_PTR_ADD	 179
#define XCore_G_PTRMASK	 180
#define XCore_G_SMIN	 181
#define XCore_G_SMAX	 182
#define XCore_G_UMIN	 183
#define XCore_G_UMAX	 184
#define XCore_G_ABS	 185
#define XCore_G_LROUND	 186
#define XCore_G_LLROUND	 187
#define XCore_G_BR	 188
#define XCore_G_BRJT	 189
#define XCore_G_INSERT_VECTOR_ELT	 190
#define XCore_G_EXTRACT_VECTOR_ELT	 191
#define XCore_G_SHUFFLE_VECTOR	 192
#define XCore_G_CTTZ	 193
#define XCore_G_CTTZ_ZERO_UNDEF	 194
#define XCore_G_CTLZ	 195
#define XCore_G_CTLZ_ZERO_UNDEF	 196
#define XCore_G_CTPOP	 197
#define XCore_G_BSWAP	 198
#define XCore_G_BITREVERSE	 199
#define XCore_G_FCEIL	 200
#define XCore_G_FCOS	 201
#define XCore_G_FSIN	 202
#define XCore_G_FSQRT	 203
#define XCore_G_FFLOOR	 204
#define XCore_G_FRINT	 205
#define XCore_G_FNEARBYINT	 206
#define XCore_G_ADDRSPACE_CAST	 207
#define XCore_G_BLOCK_ADDR	 208
#define XCore_G_JUMP_TABLE	 209
#define XCore_G_DYN_STACKALLOC	 210
#define XCore_G_STRICT_FADD	 211
#define XCore_G_STRICT_FSUB	 212
#define XCore_G_STRICT_FMUL	 213
#define XCore_G_STRICT_FDIV	 214
#define XCore_G_STRICT_FREM	 215
#define XCore_G_STRICT_FMA	 216
#define XCore_G_STRICT_FSQRT	 217
#define XCore_G_READ_REGISTER	 218
#define XCore_G_WRITE_REGISTER	 219
#define XCore_G_MEMCPY	 220
#define XCore_G_MEMCPY_INLINE	 221
#define XCore_G_MEMMOVE	 222
#define XCore_G_MEMSET	 223
#define XCore_G_BZERO	 224
#define XCore_G_VECREDUCE_SEQ_FADD	 225
#define XCore_G_VECREDUCE_SEQ_FMUL	 226
#define XCore_G_VECREDUCE_FADD	 227
#define XCore_G_VECREDUCE_FMUL	 228
#define XCore_G_VECREDUCE_FMAX	 229
#define XCore_G_VECREDUCE_FMIN	 230
#define XCore_G_VECREDUCE_ADD	 231
#define XCore_G_VECREDUCE_MUL	 232
#define XCore_G_VECREDUCE_AND	 233
#define XCore_G_VECREDUCE_OR	 234
#define XCore_G_VECREDUCE_XOR	 235
#define XCore_G_VECREDUCE_SMAX	 236
#define XCore_G_VECREDUCE_SMIN	 237
#define XCore_G_VECREDUCE_UMAX	 238
#define XCore_G_VECREDUCE_UMIN	 239
#define XCore_G_SBFX	 240
#define XCore_G_UBFX	 241
#define XCore_ADJCALLSTACKDOWN	 242
#define XCore_ADJCALLSTACKUP	 243
#define XCore_BR_JT	 244
#define XCore_BR_JT32	 245
#define XCore_EH_RETURN	 246
#define XCore_FRAME_TO_ARGS_OFFSET	 247
#define XCore_Int_MemBarrier	 248
#define XCore_LDAWFI	 249
#define XCore_LDWFI	 250
#define XCore_SELECT_CC	 251
#define XCore_STWFI	 252
#define XCore_ADD_2rus	 253
#define XCore_ADD_3r	 254
#define XCore_ANDNOT_2r	 255
#define XCore_AND_3r	 256
#define XCore_ASHR_l2rus	 257
#define XCore_ASHR_l3r	 258
#define XCore_BAU_1r	 259
#define XCore_BITREV_l2r	 260
#define XCore_BLACP_lu10	 261
#define XCore_BLACP_u10	 262
#define XCore_BLAT_lu6	 263
#define XCore_BLAT_u6	 264
#define XCore_BLA_1r	 265
#define XCore_BLRB_lu10	 266
#define XCore_BLRB_u10	 267
#define XCore_BLRF_lu10	 268
#define XCore_BLRF_u10	 269
#define XCore_BRBF_lru6	 270
#define XCore_BRBF_ru6	 271
#define XCore_BRBT_lru6	 272
#define XCore_BRBT_ru6	 273
#define XCore_BRBU_lu6	 274
#define XCore_BRBU_u6	 275
#define XCore_BRFF_lru6	 276
#define XCore_BRFF_ru6	 277
#define XCore_BRFT_lru6	 278
#define XCore_BRFT_ru6	 279
#define XCore_BRFU_lu6	 280
#define XCore_BRFU_u6	 281
#define XCore_BRU_1r	 282
#define XCore_BYTEREV_l2r	 283
#define XCore_CHKCT_2r	 284
#define XCore_CHKCT_rus	 285
#define XCore_CLRE_0R	 286
#define XCore_CLRPT_1R	 287
#define XCore_CLRSR_branch_lu6	 288
#define XCore_CLRSR_branch_u6	 289
#define XCore_CLRSR_lu6	 290
#define XCore_CLRSR_u6	 291
#define XCore_CLZ_l2r	 292
#define XCore_CRC8_l4r	 293
#define XCore_CRC_l3r	 294
#define XCore_DCALL_0R	 295
#define XCore_DENTSP_0R	 296
#define XCore_DGETREG_1r	 297
#define XCore_DIVS_l3r	 298
#define XCore_DIVU_l3r	 299
#define XCore_DRESTSP_0R	 300
#define XCore_DRET_0R	 301
#define XCore_ECALLF_1r	 302
#define XCore_ECALLT_1r	 303
#define XCore_EDU_1r	 304
#define XCore_EEF_2r	 305
#define XCore_EET_2r	 306
#define XCore_EEU_1r	 307
#define XCore_ENDIN_2r	 308
#define XCore_ENTSP_lu6	 309
#define XCore_ENTSP_u6	 310
#define XCore_EQ_2rus	 311
#define XCore_EQ_3r	 312
#define XCore_EXTDP_lu6	 313
#define XCore_EXTDP_u6	 314
#define XCore_EXTSP_lu6	 315
#define XCore_EXTSP_u6	 316
#define XCore_FREER_1r	 317
#define XCore_FREET_0R	 318
#define XCore_GETD_l2r	 319
#define XCore_GETED_0R	 320
#define XCore_GETET_0R	 321
#define XCore_GETID_0R	 322
#define XCore_GETKEP_0R	 323
#define XCore_GETKSP_0R	 324
#define XCore_GETN_l2r	 325
#define XCore_GETPS_l2r	 326
#define XCore_GETR_rus	 327
#define XCore_GETSR_lu6	 328
#define XCore_GETSR_u6	 329
#define XCore_GETST_2r	 330
#define XCore_GETTS_2r	 331
#define XCore_INCT_2r	 332
#define XCore_INITCP_2r	 333
#define XCore_INITDP_2r	 334
#define XCore_INITLR_l2r	 335
#define XCore_INITPC_2r	 336
#define XCore_INITSP_2r	 337
#define XCore_INPW_l2rus	 338
#define XCore_INSHR_2r	 339
#define XCore_INT_2r	 340
#define XCore_IN_2r	 341
#define XCore_KCALL_1r	 342
#define XCore_KCALL_lu6	 343
#define XCore_KCALL_u6	 344
#define XCore_KENTSP_lu6	 345
#define XCore_KENTSP_u6	 346
#define XCore_KRESTSP_lu6	 347
#define XCore_KRESTSP_u6	 348
#define XCore_KRET_0R	 349
#define XCore_LADD_l5r	 350
#define XCore_LD16S_3r	 351
#define XCore_LD8U_3r	 352
#define XCore_LDA16B_l3r	 353
#define XCore_LDA16F_l3r	 354
#define XCore_LDAPB_lu10	 355
#define XCore_LDAPB_u10	 356
#define XCore_LDAPF_lu10	 357
#define XCore_LDAPF_lu10_ba	 358
#define XCore_LDAPF_u10	 359
#define XCore_LDAWB_l2rus	 360
#define XCore_LDAWB_l3r	 361
#define XCore_LDAWCP_lu6	 362
#define XCore_LDAWCP_u6	 363
#define XCore_LDAWDP_lru6	 364
#define XCore_LDAWDP_ru6	 365
#define XCore_LDAWF_l2rus	 366
#define XCore_LDAWF_l3r	 367
#define XCore_LDAWSP_lru6	 368
#define XCore_LDAWSP_ru6	 369
#define XCore_LDC_lru6	 370
#define XCore_LDC_ru6	 371
#define XCore_LDET_0R	 372
#define XCore_LDIVU_l5r	 373
#define XCore_LDSED_0R	 374
#define XCore_LDSPC_0R	 375
#define XCore_LDSSR_0R	 376
#define XCore_LDWCP_lru6	 377
#define XCore_LDWCP_lu10	 378
#define XCore_LDWCP_ru6	 379
#define XCore_LDWCP_u10	 380
#define XCore_LDWDP_lru6	 381
#define XCore_LDWDP_ru6	 382
#define XCore_LDWSP_lru6	 383
#define XCore_LDWSP_ru6	 384
#define XCore_LDW_2rus	 385
#define XCore_LDW_3r	 386
#define XCore_LMUL_l6r	 387
#define XCore_LSS_3r	 388
#define XCore_LSUB_l5r	 389
#define XCore_LSU_3r	 390
#define XCore_MACCS_l4r	 391
#define XCore_MACCU_l4r	 392
#define XCore_MJOIN_1r	 393
#define XCore_MKMSK_2r	 394
#define XCore_MKMSK_rus	 395
#define XCore_MSYNC_1r	 396
#define XCore_MUL_l3r	 397
#define XCore_NEG	 398
#define XCore_NOT	 399
#define XCore_OR_3r	 400
#define XCore_OUTCT_2r	 401
#define XCore_OUTCT_rus	 402
#define XCore_OUTPW_l2rus	 403
#define XCore_OUTSHR_2r	 404
#define XCore_OUTT_2r	 405
#define XCore_OUT_2r	 406
#define XCore_PEEK_2r	 407
#define XCore_REMS_l3r	 408
#define XCore_REMU_l3r	 409
#define XCore_RETSP_lu6	 410
#define XCore_RETSP_u6	 411
#define XCore_SETCLK_l2r	 412
#define XCore_SETCP_1r	 413
#define XCore_SETC_l2r	 414
#define XCore_SETC_lru6	 415
#define XCore_SETC_ru6	 416
#define XCore_SETDP_1r	 417
#define XCore_SETD_2r	 418
#define XCore_SETEV_1r	 419
#define XCore_SETKEP_0R	 420
#define XCore_SETN_l2r	 421
#define XCore_SETPSC_2r	 422
#define XCore_SETPS_l2r	 423
#define XCore_SETPT_2r	 424
#define XCore_SETRDY_l2r	 425
#define XCore_SETSP_1r	 426
#define XCore_SETSR_branch_lu6	 427
#define XCore_SETSR_branch_u6	 428
#define XCore_SETSR_lu6	 429
#define XCore_SETSR_u6	 430
#define XCore_SETTW_l2r	 431
#define XCore_SETV_1r	 432
#define XCore_SEXT_2r	 433
#define XCore_SEXT_rus	 434
#define XCore_SHL_2rus	 435
#define XCore_SHL_3r	 436
#define XCore_SHR_2rus	 437
#define XCore_SHR_3r	 438
#define XCore_SSYNC_0r	 439
#define XCore_ST16_l3r	 440
#define XCore_ST8_l3r	 441
#define XCore_STET_0R	 442
#define XCore_STSED_0R	 443
#define XCore_STSPC_0R	 444
#define XCore_STSSR_0R	 445
#define XCore_STWDP_lru6	 446
#define XCore_STWDP_ru6	 447
#define XCore_STWSP_lru6	 448
#define XCore_STWSP_ru6	 449
#define XCore_STW_2rus	 450
#define XCore_STW_l3r	 451
#define XCore_SUB_2rus	 452
#define XCore_SUB_3r	 453
#define XCore_SYNCR_1r	 454
#define XCore_TESTCT_2r	 455
#define XCore_TESTLCL_l2r	 456
#define XCore_TESTWCT_2r	 457
#define XCore_TSETMR_2r	 458
#define XCore_TSETR_3r	 459
#define XCore_TSTART_1R	 460
#define XCore_WAITEF_1R	 461
#define XCore_WAITET_1R	 462
#define XCore_WAITEU_0R	 463
#define XCore_XOR_l3r	 464
#define XCore_ZEXT_2r	 465
#define XCore_ZEXT_rus	 466
#endif // GET_INSTRINFO_ENUM

#ifdef GET_REGINFO_EXTRA
#undef GET_REGINFO_EXTRA
#endif // GET_REGINFO_EXTRA


#ifdef GET_REGINFO_MC_DESC
#undef GET_REGINFO_MC_DESC



static const MCPhysReg XCoreRegDiffLists[] = {
  /* 0 */ 65535, 0,
};

static const uint16_t XCoreSubRegIdxLists[] = {
  /* 0 */ 0,
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
static const char XCoreRegStrings[] = {
  /* 0 */ "R10\0"
  /* 4 */ "R0\0"
  /* 7 */ "R11\0"
  /* 11 */ "R1\0"
  /* 14 */ "R2\0"
  /* 17 */ "R3\0"
  /* 20 */ "R4\0"
  /* 23 */ "R5\0"
  /* 26 */ "R6\0"
  /* 29 */ "R7\0"
  /* 32 */ "R8\0"
  /* 35 */ "R9\0"
  /* 38 */ "CP\0"
  /* 41 */ "DP\0"
  /* 44 */ "SP\0"
  /* 47 */ "LR\0"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

static const MCRegisterDesc XCoreRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0 },
  { 38, 1, 1, 0, 1, 0 },
  { 41, 1, 1, 0, 1, 0 },
  { 47, 1, 1, 0, 1, 0 },
  { 44, 1, 1, 0, 1, 0 },
  { 4, 1, 1, 0, 1, 0 },
  { 11, 1, 1, 0, 1, 0 },
  { 14, 1, 1, 0, 1, 2 },
  { 17, 1, 1, 0, 1, 4 },
  { 20, 1, 1, 0, 1, 6 },
  { 23, 1, 1, 0, 1, 6 },
  { 26, 1, 1, 0, 1, 6 },
  { 29, 1, 1, 0, 1, 8 },
  { 32, 1, 1, 0, 1, 0 },
  { 35, 1, 1, 0, 1, 0 },
  { 0, 1, 1, 0, 1, 6 },
  { 7, 1, 1, 0, 1, 10 },
};

  // RRegs Register Class...
  static const MCPhysReg RRegs[] = {
    XCore_R0, XCore_R1, XCore_R2, XCore_R3, XCore_R4, XCore_R5, XCore_R6, XCore_R7, XCore_R8, XCore_R9, XCore_R10, XCore_R11, XCore_CP, XCore_DP, XCore_SP, XCore_LR, 
  };

  // RRegs Bit set.
  static const uint8_t RRegsBits[] = {
    0xfe, 0xff, 0x01, 
  };

  // GRRegs Register Class...
  static const MCPhysReg GRRegs[] = {
    XCore_R0, XCore_R1, XCore_R2, XCore_R3, XCore_R4, XCore_R5, XCore_R6, XCore_R7, XCore_R8, XCore_R9, XCore_R10, XCore_R11, 
  };

  // GRRegs Bit set.
  static const uint8_t GRRegsBits[] = {
    0xe0, 0xff, 0x01, 
  };

// end of register classes misc


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
static const char XCoreRegClassStrings[] = {
  /* 0 */ "GRRegs\0"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

static const MCRegisterClass XCoreMCRegisterClasses[] = {
  { RRegs, RRegsBits, sizeof(RRegsBits) },
  { GRRegs, GRRegsBits, sizeof(GRRegsBits) },
};

#endif // GET_REGINFO_MC_DESC

#ifdef GET_ASM_WRITER
#undef GET_ASM_WRITER

static void llvm_unreachable(const char * info) {}
static void assert(int val) {}
typedef struct MCMnemonic {
    const char *first;
    uint64_t second;
} MCMnemonic;

static MCMnemonic createMnemonic(const char* first, uint64_t second) {
    MCMnemonic mnemonic;
    mnemonic.first = first;
    mnemonic.second = second;
    return mnemonic;
}

/// getMnemonic - This method is automatically generated by tablegen
/// from the instruction set description.
MCMnemonic XCore_getMnemonic(const MCInst *MI) {

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
  static const char AsmStrs[] = {
  /* 0 */ "ldap r11, \0"
  /* 11 */ "getsr r11, \0"
  /* 23 */ "set cp, \0"
  /* 32 */ "set dp, \0"
  /* 41 */ "set sp, \0"
  /* 50 */ "crc32 \0"
  /* 57 */ "lda16 \0"
  /* 64 */ "st16 \0"
  /* 70 */ "crc8 \0"
  /* 76 */ "st8 \0"
  /* 81 */ "# LDAWFI \0"
  /* 91 */ "# LDWFI \0"
  /* 100 */ "# STWFI \0"
  /* 109 */ "# EH_RETURN \0"
  /* 122 */ "# ADJCALLSTACKDOWN \0"
  /* 142 */ "# ADJCALLSTACKUP \0"
  /* 160 */ "# FRAME_TO_ARGS_OFFSET \0"
  /* 184 */ "bla \0"
  /* 189 */ "lsub \0"
  /* 195 */ "ldc \0"
  /* 200 */ "ladd \0"
  /* 206 */ "and \0"
  /* 211 */ "getd \0"
  /* 217 */ "bf \0"
  /* 221 */ "eef \0"
  /* 226 */ "waitef \0"
  /* 234 */ "ecallf \0"
  /* 242 */ "neg \0"
  /* 247 */ "dgetreg \0"
  /* 256 */ "peek \0"
  /* 262 */ "mkmsk \0"
  /* 269 */ "bl \0"
  /* 273 */ "testlcl \0"
  /* 282 */ "shl \0"
  /* 287 */ "kcall \0"
  /* 294 */ "lmul \0"
  /* 300 */ "endin \0"
  /* 307 */ "getn \0"
  /* 313 */ "extdp \0"
  /* 320 */ "retsp \0"
  /* 327 */ "kentsp \0"
  /* 335 */ "krestsp \0"
  /* 344 */ "extsp \0"
  /* 351 */ "eq \0"
  /* 355 */ "ashr \0"
  /* 361 */ "inshr \0"
  /* 368 */ "xor \0"
  /* 373 */ "clrsr \0"
  /* 380 */ "setsr \0"
  /* 387 */ "getr \0"
  /* 393 */ "ld16s \0"
  /* 400 */ "maccs \0"
  /* 407 */ "rems \0"
  /* 413 */ "lss \0"
  /* 418 */ "getts \0"
  /* 425 */ "divs \0"
  /* 431 */ "blat \0"
  /* 437 */ "bt \0"
  /* 441 */ "inct \0"
  /* 447 */ "testct \0"
  /* 455 */ "testwct \0"
  /* 464 */ "eet \0"
  /* 469 */ "get \0"
  /* 474 */ "waitet \0"
  /* 482 */ "ecallt \0"
  /* 490 */ "int \0"
  /* 495 */ "andnot \0"
  /* 503 */ "getst \0"
  /* 510 */ "sext \0"
  /* 516 */ "zext \0"
  /* 522 */ "ld8u \0"
  /* 528 */ "bau \0"
  /* 533 */ "bu \0"
  /* 537 */ "maccu \0"
  /* 544 */ "remu \0"
  /* 550 */ "bru \0"
  /* 555 */ "lsu \0"
  /* 560 */ "ldivu \0"
  /* 567 */ "byterev \0"
  /* 576 */ "bitrev \0"
  /* 584 */ "ldaw \0"
  /* 590 */ "ldw \0"
  /* 595 */ "inpw \0"
  /* 601 */ "stw \0"
  /* 606 */ "clz \0"
  /* 611 */ "# SELECT_CC PSEUDO!\0"
  /* 631 */ "# XRay Function Patchable RET.\0"
  /* 662 */ "# XRay Typed Event Log.\0"
  /* 686 */ "# XRay Custom Event Log.\0"
  /* 711 */ "# XRay Function Enter.\0"
  /* 734 */ "# XRay Tail Call Exit.\0"
  /* 757 */ "# XRay Function Exit.\0"
  /* 779 */ "set kep, r11\0"
  /* 792 */ "LIFETIME_END\0"
  /* 805 */ "PSEUDO_PROBE\0"
  /* 818 */ "BUNDLE\0"
  /* 825 */ "DBG_VALUE\0"
  /* 835 */ "DBG_INSTR_REF\0"
  /* 849 */ "DBG_PHI\0"
  /* 857 */ "DBG_LABEL\0"
  /* 867 */ "#MEMBARRIER\0"
  /* 879 */ "LIFETIME_START\0"
  /* 894 */ "DBG_VALUE_LIST\0"
  /* 909 */ "ldaw r11, cp[\0"
  /* 923 */ "ldw r11, cp[\0"
  /* 936 */ "bla cp[\0"
  /* 944 */ "msync res[\0"
  /* 955 */ "setpsc res[\0"
  /* 967 */ "setc res[\0"
  /* 977 */ "setd res[\0"
  /* 987 */ "setclk res[\0"
  /* 999 */ "mjoin res[\0"
  /* 1010 */ "setn res[\0"
  /* 1020 */ "syncr res[\0"
  /* 1031 */ "freer res[\0"
  /* 1042 */ "outshr res[\0"
  /* 1054 */ "chkct res[\0"
  /* 1065 */ "outct res[\0"
  /* 1076 */ "clrpt res[\0"
  /* 1087 */ "setpt res[\0"
  /* 1098 */ "outt res[\0"
  /* 1108 */ "out res[\0"
  /* 1117 */ "edu res[\0"
  /* 1126 */ "eeu res[\0"
  /* 1135 */ "setev res[\0"
  /* 1146 */ "setv res[\0"
  /* 1156 */ "outpw res[\0"
  /* 1167 */ "settw res[\0"
  /* 1178 */ "setrdy res[\0"
  /* 1190 */ "set ps[\0"
  /* 1198 */ "set t[\0"
  /* 1205 */ "init t[\0"
  /* 1213 */ "start t[\0"
  /* 1222 */ "ldw spc, sp[1]\0"
  /* 1237 */ "stw spc, sp[1]\0"
  /* 1252 */ "ldw ssr, sp[2]\0"
  /* 1267 */ "stw ssr, sp[2]\0"
  /* 1282 */ "ldw sed, sp[3]\0"
  /* 1297 */ "stw sed, sp[3]\0"
  /* 1312 */ "ldw et, sp[4]\0"
  /* 1326 */ "stw et, sp[4]\0"
  /* 1340 */ "ssync\0"
  /* 1346 */ "get r11, ed\0"
  /* 1358 */ "get r11, id\0"
  /* 1370 */ "clre\0"
  /* 1375 */ "# FEntry call\0"
  /* 1389 */ "dcall\0"
  /* 1395 */ "get r11, kep\0"
  /* 1408 */ "get r11, ksp\0"
  /* 1421 */ "dentsp\0"
  /* 1428 */ "drestsp\0"
  /* 1436 */ "tsetmr r\0"
  /* 1445 */ "get r11, et\0"
  /* 1457 */ "freet\0"
  /* 1463 */ "dret\0"
  /* 1468 */ "kret\0"
  /* 1473 */ "waiteu\0"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

  static const uint32_t OpInfo0[] = {
    0U,	// PHI
    0U,	// INLINEASM
    0U,	// INLINEASM_BR
    0U,	// CFI_INSTRUCTION
    0U,	// EH_LABEL
    0U,	// GC_LABEL
    0U,	// ANNOTATION_LABEL
    0U,	// KILL
    0U,	// EXTRACT_SUBREG
    0U,	// INSERT_SUBREG
    0U,	// IMPLICIT_DEF
    0U,	// SUBREG_TO_REG
    0U,	// COPY_TO_REGCLASS
    826U,	// DBG_VALUE
    895U,	// DBG_VALUE_LIST
    836U,	// DBG_INSTR_REF
    850U,	// DBG_PHI
    858U,	// DBG_LABEL
    0U,	// REG_SEQUENCE
    0U,	// COPY
    819U,	// BUNDLE
    880U,	// LIFETIME_START
    793U,	// LIFETIME_END
    806U,	// PSEUDO_PROBE
    0U,	// ARITH_FENCE
    0U,	// STACKMAP
    1376U,	// FENTRY_CALL
    0U,	// PATCHPOINT
    0U,	// LOAD_STACK_GUARD
    0U,	// PREALLOCATED_SETUP
    0U,	// PREALLOCATED_ARG
    0U,	// STATEPOINT
    0U,	// LOCAL_ESCAPE
    0U,	// FAULTING_OP
    0U,	// PATCHABLE_OP
    712U,	// PATCHABLE_FUNCTION_ENTER
    632U,	// PATCHABLE_RET
    758U,	// PATCHABLE_FUNCTION_EXIT
    735U,	// PATCHABLE_TAIL_CALL
    687U,	// PATCHABLE_EVENT_CALL
    663U,	// PATCHABLE_TYPED_EVENT_CALL
    0U,	// ICALL_BRANCH_FUNNEL
    0U,	// G_ASSERT_SEXT
    0U,	// G_ASSERT_ZEXT
    0U,	// G_ADD
    0U,	// G_SUB
    0U,	// G_MUL
    0U,	// G_SDIV
    0U,	// G_UDIV
    0U,	// G_SREM
    0U,	// G_UREM
    0U,	// G_SDIVREM
    0U,	// G_UDIVREM
    0U,	// G_AND
    0U,	// G_OR
    0U,	// G_XOR
    0U,	// G_IMPLICIT_DEF
    0U,	// G_PHI
    0U,	// G_FRAME_INDEX
    0U,	// G_GLOBAL_VALUE
    0U,	// G_EXTRACT
    0U,	// G_UNMERGE_VALUES
    0U,	// G_INSERT
    0U,	// G_MERGE_VALUES
    0U,	// G_BUILD_VECTOR
    0U,	// G_BUILD_VECTOR_TRUNC
    0U,	// G_CONCAT_VECTORS
    0U,	// G_PTRTOINT
    0U,	// G_INTTOPTR
    0U,	// G_BITCAST
    0U,	// G_FREEZE
    0U,	// G_INTRINSIC_TRUNC
    0U,	// G_INTRINSIC_ROUND
    0U,	// G_INTRINSIC_LRINT
    0U,	// G_INTRINSIC_ROUNDEVEN
    0U,	// G_READCYCLECOUNTER
    0U,	// G_LOAD
    0U,	// G_SEXTLOAD
    0U,	// G_ZEXTLOAD
    0U,	// G_INDEXED_LOAD
    0U,	// G_INDEXED_SEXTLOAD
    0U,	// G_INDEXED_ZEXTLOAD
    0U,	// G_STORE
    0U,	// G_INDEXED_STORE
    0U,	// G_ATOMIC_CMPXCHG_WITH_SUCCESS
    0U,	// G_ATOMIC_CMPXCHG
    0U,	// G_ATOMICRMW_XCHG
    0U,	// G_ATOMICRMW_ADD
    0U,	// G_ATOMICRMW_SUB
    0U,	// G_ATOMICRMW_AND
    0U,	// G_ATOMICRMW_NAND
    0U,	// G_ATOMICRMW_OR
    0U,	// G_ATOMICRMW_XOR
    0U,	// G_ATOMICRMW_MAX
    0U,	// G_ATOMICRMW_MIN
    0U,	// G_ATOMICRMW_UMAX
    0U,	// G_ATOMICRMW_UMIN
    0U,	// G_ATOMICRMW_FADD
    0U,	// G_ATOMICRMW_FSUB
    0U,	// G_FENCE
    0U,	// G_BRCOND
    0U,	// G_BRINDIRECT
    0U,	// G_INTRINSIC
    0U,	// G_INTRINSIC_W_SIDE_EFFECTS
    0U,	// G_ANYEXT
    0U,	// G_TRUNC
    0U,	// G_CONSTANT
    0U,	// G_FCONSTANT
    0U,	// G_VASTART
    0U,	// G_VAARG
    0U,	// G_SEXT
    0U,	// G_SEXT_INREG
    0U,	// G_ZEXT
    0U,	// G_SHL
    0U,	// G_LSHR
    0U,	// G_ASHR
    0U,	// G_FSHL
    0U,	// G_FSHR
    0U,	// G_ROTR
    0U,	// G_ROTL
    0U,	// G_ICMP
    0U,	// G_FCMP
    0U,	// G_SELECT
    0U,	// G_UADDO
    0U,	// G_UADDE
    0U,	// G_USUBO
    0U,	// G_USUBE
    0U,	// G_SADDO
    0U,	// G_SADDE
    0U,	// G_SSUBO
    0U,	// G_SSUBE
    0U,	// G_UMULO
    0U,	// G_SMULO
    0U,	// G_UMULH
    0U,	// G_SMULH
    0U,	// G_UADDSAT
    0U,	// G_SADDSAT
    0U,	// G_USUBSAT
    0U,	// G_SSUBSAT
    0U,	// G_USHLSAT
    0U,	// G_SSHLSAT
    0U,	// G_SMULFIX
    0U,	// G_UMULFIX
    0U,	// G_SMULFIXSAT
    0U,	// G_UMULFIXSAT
    0U,	// G_SDIVFIX
    0U,	// G_UDIVFIX
    0U,	// G_SDIVFIXSAT
    0U,	// G_UDIVFIXSAT
    0U,	// G_FADD
    0U,	// G_FSUB
    0U,	// G_FMUL
    0U,	// G_FMA
    0U,	// G_FMAD
    0U,	// G_FDIV
    0U,	// G_FREM
    0U,	// G_FPOW
    0U,	// G_FPOWI
    0U,	// G_FEXP
    0U,	// G_FEXP2
    0U,	// G_FLOG
    0U,	// G_FLOG2
    0U,	// G_FLOG10
    0U,	// G_FNEG
    0U,	// G_FPEXT
    0U,	// G_FPTRUNC
    0U,	// G_FPTOSI
    0U,	// G_FPTOUI
    0U,	// G_SITOFP
    0U,	// G_UITOFP
    0U,	// G_FABS
    0U,	// G_FCOPYSIGN
    0U,	// G_FCANONICALIZE
    0U,	// G_FMINNUM
    0U,	// G_FMAXNUM
    0U,	// G_FMINNUM_IEEE
    0U,	// G_FMAXNUM_IEEE
    0U,	// G_FMINIMUM
    0U,	// G_FMAXIMUM
    0U,	// G_PTR_ADD
    0U,	// G_PTRMASK
    0U,	// G_SMIN
    0U,	// G_SMAX
    0U,	// G_UMIN
    0U,	// G_UMAX
    0U,	// G_ABS
    0U,	// G_LROUND
    0U,	// G_LLROUND
    0U,	// G_BR
    0U,	// G_BRJT
    0U,	// G_INSERT_VECTOR_ELT
    0U,	// G_EXTRACT_VECTOR_ELT
    0U,	// G_SHUFFLE_VECTOR
    0U,	// G_CTTZ
    0U,	// G_CTTZ_ZERO_UNDEF
    0U,	// G_CTLZ
    0U,	// G_CTLZ_ZERO_UNDEF
    0U,	// G_CTPOP
    0U,	// G_BSWAP
    0U,	// G_BITREVERSE
    0U,	// G_FCEIL
    0U,	// G_FCOS
    0U,	// G_FSIN
    0U,	// G_FSQRT
    0U,	// G_FFLOOR
    0U,	// G_FRINT
    0U,	// G_FNEARBYINT
    0U,	// G_ADDRSPACE_CAST
    0U,	// G_BLOCK_ADDR
    0U,	// G_JUMP_TABLE
    0U,	// G_DYN_STACKALLOC
    0U,	// G_STRICT_FADD
    0U,	// G_STRICT_FSUB
    0U,	// G_STRICT_FMUL
    0U,	// G_STRICT_FDIV
    0U,	// G_STRICT_FREM
    0U,	// G_STRICT_FMA
    0U,	// G_STRICT_FSQRT
    0U,	// G_READ_REGISTER
    0U,	// G_WRITE_REGISTER
    0U,	// G_MEMCPY
    0U,	// G_MEMCPY_INLINE
    0U,	// G_MEMMOVE
    0U,	// G_MEMSET
    0U,	// G_BZERO
    0U,	// G_VECREDUCE_SEQ_FADD
    0U,	// G_VECREDUCE_SEQ_FMUL
    0U,	// G_VECREDUCE_FADD
    0U,	// G_VECREDUCE_FMUL
    0U,	// G_VECREDUCE_FMAX
    0U,	// G_VECREDUCE_FMIN
    0U,	// G_VECREDUCE_ADD
    0U,	// G_VECREDUCE_MUL
    0U,	// G_VECREDUCE_AND
    0U,	// G_VECREDUCE_OR
    0U,	// G_VECREDUCE_XOR
    0U,	// G_VECREDUCE_SMAX
    0U,	// G_VECREDUCE_SMIN
    0U,	// G_VECREDUCE_UMAX
    0U,	// G_VECREDUCE_UMIN
    0U,	// G_SBFX
    0U,	// G_UBFX
    2171U,	// ADJCALLSTACKDOWN
    10383U,	// ADJCALLSTACKUP
    283175U,	// BR_JT
    545319U,	// BR_JT32
    2158U,	// EH_RETURN
    10401U,	// FRAME_TO_ARGS_OFFSET
    868U,	// Int_MemBarrier
    2130U,	// LDAWFI
    2140U,	// LDWFI
    612U,	// SELECT_CC
    2149U,	// STWFI
    2099402U,	// ADD_2rus
    2099402U,	// ADD_3r
    788976U,	// ANDNOT_2r
    2099407U,	// AND_3r
    2099556U,	// ASHR_l2rus
    2099556U,	// ASHR_l3r
    10769U,	// BAU_1r
    2625U,	// BITREV_l2r
    27561U,	// BLACP_lu10
    27561U,	// BLACP_u10
    10672U,	// BLAT_lu6
    10672U,	// BLAT_u6
    10425U,	// BLA_1r
    10510U,	// BLRB_lu10
    10510U,	// BLRB_u10
    10510U,	// BLRF_lu10
    10510U,	// BLRF_u10
    2266U,	// BRBF_lru6
    2266U,	// BRBF_ru6
    2486U,	// BRBT_lru6
    2486U,	// BRBT_ru6
    10774U,	// BRBU_lu6
    10774U,	// BRBU_u6
    2266U,	// BRFF_lru6
    2266U,	// BRFF_ru6
    2486U,	// BRFT_lru6
    2486U,	// BRFT_ru6
    10774U,	// BRFU_lu6
    10774U,	// BRFU_u6
    10791U,	// BRU_1r
    2616U,	// BYTEREV_l2r
    35871U,	// CHKCT_2r
    35871U,	// CHKCT_rus
    1371U,	// CLRE_0R
    27701U,	// CLRPT_1R
    10614U,	// CLRSR_branch_lu6
    10614U,	// CLRSR_branch_u6
    10614U,	// CLRSR_lu6
    10614U,	// CLRSR_u6
    2655U,	// CLZ_l2r
    5247047U,	// CRC8_l4r
    19662899U,	// CRC_l3r
    1390U,	// DCALL_0R
    1422U,	// DENTSP_0R
    10488U,	// DGETREG_1r
    2099626U,	// DIVS_l3r
    2099762U,	// DIVU_l3r
    1429U,	// DRESTSP_0R
    1464U,	// DRET_0R
    10475U,	// ECALLF_1r
    10723U,	// ECALLT_1r
    27742U,	// EDU_1r
    6334686U,	// EEF_2r
    6334929U,	// EET_2r
    27751U,	// EEU_1r
    6334765U,	// ENDIN_2r
    10569U,	// ENTSP_lu6
    10569U,	// ENTSP_u6
    2099552U,	// EQ_2rus
    2099552U,	// EQ_3r
    10554U,	// EXTDP_lu6
    10554U,	// EXTDP_u6
    10585U,	// EXTSP_lu6
    10585U,	// EXTSP_u6
    27656U,	// FREER_1r
    1458U,	// FREET_0R
    6334676U,	// GETD_l2r
    1347U,	// GETED_0R
    1446U,	// GETET_0R
    1359U,	// GETID_0R
    1396U,	// GETKEP_0R
    1409U,	// GETKSP_0R
    6334772U,	// GETN_l2r
    51670U,	// GETPS_l2r
    2436U,	// GETR_rus
    10252U,	// GETSR_lu6
    10252U,	// GETSR_u6
    6334968U,	// GETST_2r
    6334883U,	// GETTS_2r
    6334906U,	// INCT_2r
    62646U,	// INITCP_2r
    70838U,	// INITDP_2r
    79030U,	// INITLR_l2r
    87222U,	// INITPC_2r
    95414U,	// INITSP_2r
    8432212U,	// INPW_l2rus
    7121258U,	// INSHR_2r
    6334955U,	// INT_2r
    6334768U,	// IN_2r
    10528U,	// KCALL_1r
    10528U,	// KCALL_lu6
    10528U,	// KCALL_u6
    10568U,	// KENTSP_lu6
    10568U,	// KENTSP_u6
    10576U,	// KRESTSP_lu6
    10576U,	// KRESTSP_u6
    1469U,	// KRET_0R
    45093065U,	// LADD_l5r
    12585354U,	// LD16S_3r
    12585483U,	// LD8U_3r
    14682170U,	// LDA16B_l3r
    12585018U,	// LDA16F_l3r
    10241U,	// LDAPB_lu10
    10241U,	// LDAPB_u10
    10241U,	// LDAPF_lu10
    10241U,	// LDAPF_lu10_ba
    10241U,	// LDAPF_u10
    14682697U,	// LDAWB_l2rus
    14682697U,	// LDAWB_l3r
    27534U,	// LDAWCP_lu6
    27534U,	// LDAWCP_u6
    100937U,	// LDAWDP_lru6
    100937U,	// LDAWDP_ru6
    12585545U,	// LDAWF_l2rus
    12585545U,	// LDAWF_l3r
    109129U,	// LDAWSP_lru6
    109129U,	// LDAWSP_ru6
    2244U,	// LDC_lru6
    2244U,	// LDC_ru6
    1313U,	// LDET_0R
    186649137U,	// LDIVU_l5r
    1283U,	// LDSED_0R
    1223U,	// LDSPC_0R
    1253U,	// LDSSR_0R
    117327U,	// LDWCP_lru6
    27548U,	// LDWCP_lu10
    117327U,	// LDWCP_ru6
    27548U,	// LDWCP_u10
    100943U,	// LDWDP_lru6
    100943U,	// LDWDP_ru6
    109135U,	// LDWSP_lru6
    109135U,	// LDWSP_ru6
    12585551U,	// LDW_2rus
    12585551U,	// LDW_3r
    270534951U,	// LMUL_l6r
    2099614U,	// LSS_3r
    45093054U,	// LSUB_l5r
    2099756U,	// LSU_3r
    455084433U,	// MACCS_l4r
    455084570U,	// MACCU_l4r
    27624U,	// MJOIN_1r
    2311U,	// MKMSK_2r
    2311U,	// MKMSK_rus
    27569U,	// MSYNC_1r
    2099496U,	// MUL_l3r
    2291U,	// NEG
    2547U,	// NOT
    2099570U,	// OR_3r
    35882U,	// OUTCT_2r
    35882U,	// OUTCT_rus
    78681221U,	// OUTPW_l2rus
    39955U,	// OUTSHR_2r
    35915U,	// OUTT_2r
    35925U,	// OUT_2r
    6334721U,	// PEEK_2r
    2099608U,	// REMS_l3r
    2099745U,	// REMU_l3r
    10561U,	// RETSP_lu6
    10561U,	// RETSP_u6
    35804U,	// SETCLK_l2r
    10264U,	// SETCP_1r
    35784U,	// SETC_l2r
    35784U,	// SETC_lru6
    35784U,	// SETC_ru6
    10273U,	// SETDP_1r
    35794U,	// SETD_2r
    126064U,	// SETEV_1r
    780U,	// SETKEP_0R
    35827U,	// SETN_l2r
    35772U,	// SETPSC_2r
    36007U,	// SETPS_l2r
    35904U,	// SETPT_2r
    35995U,	// SETRDY_l2r
    10282U,	// SETSP_1r
    10621U,	// SETSR_branch_lu6
    10621U,	// SETSR_branch_u6
    10621U,	// SETSR_lu6
    10621U,	// SETSR_u6
    35984U,	// SETTW_l2r
    126075U,	// SETV_1r
    788991U,	// SEXT_2r
    788991U,	// SEXT_rus
    2099483U,	// SHL_2rus
    2099483U,	// SHL_3r
    2099557U,	// SHR_2rus
    2099557U,	// SHR_3r
    1341U,	// SSYNC_0r
    12585025U,	// ST16_l3r
    12585037U,	// ST8_l3r
    1327U,	// STET_0R
    1298U,	// STSED_0R
    1238U,	// STSPC_0R
    1268U,	// STSSR_0R
    100954U,	// STWDP_lru6
    100954U,	// STWDP_ru6
    109146U,	// STWSP_lru6
    109146U,	// STWSP_ru6
    12585562U,	// STW_2rus
    12585562U,	// STW_l3r
    2099391U,	// SUB_2rus
    2099391U,	// SUB_3r
    27645U,	// SYNCR_1r
    6334912U,	// TESTCT_2r
    6334738U,	// TESTLCL_l2r
    6334920U,	// TESTWCT_2r
    3485U,	// TSETMR_2r
    138415U,	// TSETR_3r
    27838U,	// TSTART_1R
    10467U,	// WAITEF_1R
    10715U,	// WAITET_1R
    1474U,	// WAITEU_0R
    2099569U,	// XOR_l3r
    788997U,	// ZEXT_2r
    788997U,	// ZEXT_rus
  };

  // Emit the opcode for the instruction.
  uint32_t Bits = 0;
  Bits |= OpInfo0[MCInst_getOpcode(MI)] << 0;
  return createMnemonic(AsmStrs+(Bits & 2047)-1, Bits);

}
/// printInstruction - This method is automatically generated by tablegen
/// from the instruction set description.
static void printInstruction(MCInst *MI, SStream *O) {
  MCMnemonic MnemonicInfo =XCore_getMnemonic(MI);

#ifndef CAPSTONE_DIET

  SStream_concat0(O, MnemonicInfo.first);
#endif

  uint32_t Bits = MnemonicInfo.second;
  assert(Bits != 0 && "Cannot print this instruction.");

  // Fragment 0 encoded into 2 bits for 4 unique commands.
  switch ((Bits >> 11) & 3) {
  default: llvm_unreachable("Invalid command number.");
  case 0:
    // DBG_VALUE, DBG_VALUE_LIST, DBG_INSTR_REF, DBG_PHI, DBG_LABEL, BUNDLE, ...
    return;
    break;
  case 1:
    // ADJCALLSTACKDOWN, ADJCALLSTACKUP, EH_RETURN, FRAME_TO_ARGS_OFFSET, LDA...
    printOperand/* printOperand (+ ) */(MI, 0, O);
    break;
  case 2:
    // BR_JT, BR_JT32, CRC8_l4r, INITCP_2r, INITDP_2r, INITLR_l2r, INITPC_2r,...
    printOperand/* printOperand (+ ) */(MI, 1, O);
    break;
  case 3:
    // OUTSHR_2r, TSETR_3r
    printOperand/* printOperand (+ ) */(MI, 2, O);
    break;
  }


  // Fragment 1 encoded into 5 bits for 17 unique commands.
  switch ((Bits >> 13) & 31) {
  default: llvm_unreachable("Invalid command number.");
  case 0:
    // ADJCALLSTACKDOWN, EH_RETURN, LDAWFI, LDWFI, STWFI, ADD_2rus, ADD_3r, A...
    SStream_concat0(O, ", ");
    break;
  case 1:
    // ADJCALLSTACKUP, FRAME_TO_ARGS_OFFSET, BAU_1r, BLAT_lu6, BLAT_u6, BLA_1...
    return;
    break;
  case 2:
    // BR_JT, BR_JT32
    SStream_concat0(O, "\n");
    break;
  case 3:
    // BLACP_lu10, BLACP_u10, CLRPT_1R, EDU_1r, EEU_1r, FREER_1r, LDAWCP_lu6,...
    SStream_concat0(O, "]");
    return;
    break;
  case 4:
    // CHKCT_2r, CHKCT_rus, OUTCT_2r, OUTCT_rus, OUTPW_l2rus, OUTSHR_2r, OUTT...
    SStream_concat0(O, "], ");
    break;
  case 5:
    // EEF_2r, EET_2r, ENDIN_2r, GETD_l2r, GETN_l2r, GETST_2r, GETTS_2r, INCT...
    SStream_concat0(O, ", res[");
    break;
  case 6:
    // GETPS_l2r
    SStream_concat0(O, ", ps[");
    printOperand/* printOperand (+ ) */(MI, 1, O);
    SStream_concat0(O, "]");
    return;
    break;
  case 7:
    // INITCP_2r
    SStream_concat0(O, "]:cp, ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  case 8:
    // INITDP_2r
    SStream_concat0(O, "]:dp, ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  case 9:
    // INITLR_l2r
    SStream_concat0(O, "]:lr, ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  case 10:
    // INITPC_2r
    SStream_concat0(O, "]:pc, ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  case 11:
    // INITSP_2r
    SStream_concat0(O, "]:sp, ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  case 12:
    // LDAWDP_lru6, LDAWDP_ru6, LDWDP_lru6, LDWDP_ru6, STWDP_lru6, STWDP_ru6
    SStream_concat0(O, ", dp[");
    printOperand/* printOperand (+ ) */(MI, 1, O);
    SStream_concat0(O, "]");
    return;
    break;
  case 13:
    // LDAWSP_lru6, LDAWSP_ru6, LDWSP_lru6, LDWSP_ru6, STWSP_lru6, STWSP_ru6
    SStream_concat0(O, ", sp[");
    printOperand/* printOperand (+ ) */(MI, 1, O);
    SStream_concat0(O, "]");
    return;
    break;
  case 14:
    // LDWCP_lru6, LDWCP_ru6
    SStream_concat0(O, ", cp[");
    printOperand/* printOperand (+ ) */(MI, 1, O);
    SStream_concat0(O, "]");
    return;
    break;
  case 15:
    // SETEV_1r, SETV_1r
    SStream_concat0(O, "], r11");
    return;
    break;
  case 16:
    // TSETR_3r
    SStream_concat0(O, "]:r");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 1, O);
    return;
    break;
  }


  // Fragment 2 encoded into 3 bits for 5 unique commands.
  switch ((Bits >> 18) & 7) {
  default: llvm_unreachable("Invalid command number.");
  case 0:
    // ADJCALLSTACKDOWN, EH_RETURN, LDAWFI, LDWFI, STWFI, ADD_2rus, ADD_3r, A...
    printOperand/* printOperand (+ ) */(MI, 1, O);
    break;
  case 1:
    // BR_JT
    printInlineJT/* printInlineJT (+ ) */(MI, 0, O);
    return;
    break;
  case 2:
    // BR_JT32
    printInlineJT32/* printInlineJT32 (+ ) */(MI, 0, O);
    return;
    break;
  case 3:
    // ANDNOT_2r, CRC_l3r, INSHR_2r, SEXT_2r, SEXT_rus, ZEXT_2r, ZEXT_rus
    printOperand/* printOperand (+ ) */(MI, 2, O);
    break;
  case 4:
    // CRC8_l4r, LADD_l5r, LSUB_l5r, OUTPW_l2rus
    printOperand/* printOperand (+ ) */(MI, 0, O);
    SStream_concat0(O, ", ");
    break;
  }


  // Fragment 3 encoded into 3 bits for 8 unique commands.
  switch ((Bits >> 21) & 7) {
  default: llvm_unreachable("Invalid command number.");
  case 0:
    // ADJCALLSTACKDOWN, EH_RETURN, LDAWFI, LDWFI, STWFI, ANDNOT_2r, BITREV_l...
    return;
    break;
  case 1:
    // ADD_2rus, ADD_3r, AND_3r, ASHR_l2rus, ASHR_l3r, CRC_l3r, DIVS_l3r, DIV...
    SStream_concat0(O, ", ");
    break;
  case 2:
    // CRC8_l4r
    printOperand/* printOperand (+ ) */(MI, 3, O);
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 4, O);
    return;
    break;
  case 3:
    // EEF_2r, EET_2r, ENDIN_2r, GETD_l2r, GETN_l2r, GETST_2r, GETTS_2r, INCT...
    SStream_concat0(O, "]");
    return;
    break;
  case 4:
    // INPW_l2rus
    SStream_concat0(O, "], ");
    printOperand/* printOperand (+ ) */(MI, 2, O);
    return;
    break;
  case 5:
    // LADD_l5r, LSUB_l5r, OUTPW_l2rus
    printOperand/* printOperand (+ ) */(MI, 2, O);
    break;
  case 6:
    // LD16S_3r, LD8U_3r, LDA16F_l3r, LDAWF_l2rus, LDAWF_l3r, LDW_2rus, LDW_3...
    SStream_concat0(O, "[");
    printOperand/* printOperand (+ ) */(MI, 2, O);
    SStream_concat0(O, "]");
    return;
    break;
  case 7:
    // LDA16B_l3r, LDAWB_l2rus, LDAWB_l3r
    SStream_concat0(O, "[-");
    printOperand/* printOperand (+ ) */(MI, 2, O);
    SStream_concat0(O, "]");
    return;
    break;
  }


  // Fragment 4 encoded into 3 bits for 5 unique commands.
  switch ((Bits >> 24) & 7) {
  default: llvm_unreachable("Invalid command number.");
  case 0:
    // ADD_2rus, ADD_3r, AND_3r, ASHR_l2rus, ASHR_l3r, DIVS_l3r, DIVU_l3r, EQ...
    printOperand/* printOperand (+ ) */(MI, 2, O);
    break;
  case 1:
    // CRC_l3r
    printOperand/* printOperand (+ ) */(MI, 3, O);
    return;
    break;
  case 2:
    // LADD_l5r, LSUB_l5r
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 3, O);
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 4, O);
    return;
    break;
  case 3:
    // LDIVU_l5r, MACCS_l4r, MACCU_l4r
    printOperand/* printOperand (+ ) */(MI, 4, O);
    SStream_concat0(O, ", ");
    break;
  case 4:
    // OUTPW_l2rus
    return;
    break;
  }


  // Fragment 5 encoded into 2 bits for 4 unique commands.
  switch ((Bits >> 27) & 3) {
  default: llvm_unreachable("Invalid command number.");
  case 0:
    // ADD_2rus, ADD_3r, AND_3r, ASHR_l2rus, ASHR_l3r, DIVS_l3r, DIVU_l3r, EQ...
    return;
    break;
  case 1:
    // LDIVU_l5r
    printOperand/* printOperand (+ ) */(MI, 2, O);
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 3, O);
    return;
    break;
  case 2:
    // LMUL_l6r
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 3, O);
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 4, O);
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 5, O);
    return;
    break;
  case 3:
    // MACCS_l4r, MACCU_l4r
    printOperand/* printOperand (+ ) */(MI, 5, O);
    return;
    break;
  }

}


/// getRegisterName - This method is automatically generated by tblgen
/// from the register set description.  This returns the assembler name
/// for the specified register.
const char *getRegisterName(unsigned RegNo) {
  assert(RegNo && RegNo < 17 && "Invalid register number!");


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
  static const char AsmStrs[] = {
  /* 0 */ "r10\0"
  /* 4 */ "r0\0"
  /* 7 */ "r11\0"
  /* 11 */ "r1\0"
  /* 14 */ "r2\0"
  /* 17 */ "r3\0"
  /* 20 */ "r4\0"
  /* 23 */ "r5\0"
  /* 26 */ "r6\0"
  /* 29 */ "r7\0"
  /* 32 */ "r8\0"
  /* 35 */ "r9\0"
  /* 38 */ "cp\0"
  /* 41 */ "dp\0"
  /* 44 */ "sp\0"
  /* 47 */ "lr\0"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

  static const uint8_t RegAsmOffset[] = {
    38, 41, 47, 44, 4, 11, 14, 17, 20, 23, 26, 29, 32, 35, 
    0, 7, 
  };

  assert (*(AsmStrs+RegAsmOffset[RegNo-1]) &&
          "Invalid alt name index for register!");
  return AsmStrs+RegAsmOffset[RegNo-1];
}
#endif
#ifdef PRINT_ALIAS_INSTR
#undef PRINT_ALIAS_INSTR

void printCustomAliasOperand(
         const MCInst *MI, unsigned OpIdx,
         unsigned PrintMethodIdx,
         SStream *OS);

static char* printAliasInstr(MCInst *MI, SStream *OS) {
  return false;
}

#endif // PRINT_ALIAS_INSTR
