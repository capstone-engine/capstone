#include "../../MCInst.h"
#include "../../LEB128.h"


#define Sparc_DetectRoundChange 0ULL
#define Sparc_FeatureHardQuad 1ULL
#define Sparc_FeatureLeon 2ULL
#define Sparc_FeatureNoFMULS 3ULL
#define Sparc_FeatureNoFSMULD 4ULL
#define Sparc_FeaturePWRPSR 5ULL
#define Sparc_FeatureSoftFloat 6ULL
#define Sparc_FeatureSoftMulDiv 7ULL
#define Sparc_FeatureV8Deprecated 8ULL
#define Sparc_FeatureV9 9ULL
#define Sparc_FeatureVIS 10ULL
#define Sparc_FeatureVIS2 11ULL
#define Sparc_FeatureVIS3 12ULL
#define Sparc_FixAllFDIVSQRT 13ULL
#define Sparc_InsertNOPLoad 14ULL
#define Sparc_LeonCASA 15ULL
#define Sparc_LeonCycleCounter 16ULL
#define Sparc_UMACSMACSupport 17ULL
#define Sparc_UsePopc 18ULL
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

static const uint8_t DecoderTableSparc32[] = {
/* 0 */       MCD_OPC_ExtractField, 30, 2,  // Inst{31-30} ...
/* 3 */       MCD_OPC_FilterValue, 0, 155, 2, 0, // Skip to: 675
/* 8 */       MCD_OPC_ExtractField, 22, 3,  // Inst{24-22} ...
/* 11 */      MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 27
/* 16 */      MCD_OPC_CheckField, 25, 5, 0, 97, 31, 0, // Skip to: 8056
/* 23 */      MCD_OPC_Decode, 229, 5, 0, // Opcode: UNIMP
/* 27 */      MCD_OPC_FilterValue, 1, 127, 0, 0, // Skip to: 159
/* 32 */      MCD_OPC_ExtractField, 19, 3,  // Inst{21-19} ...
/* 35 */      MCD_OPC_FilterValue, 0, 31, 0, 0, // Skip to: 71
/* 40 */      MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 43 */      MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 57
/* 48 */      MCD_OPC_CheckPredicate, 0, 67, 31, 0, // Skip to: 8056
/* 53 */      MCD_OPC_Decode, 175, 2, 1, // Opcode: BPICCNT
/* 57 */      MCD_OPC_FilterValue, 1, 58, 31, 0, // Skip to: 8056
/* 62 */      MCD_OPC_CheckPredicate, 0, 53, 31, 0, // Skip to: 8056
/* 67 */      MCD_OPC_Decode, 174, 2, 1, // Opcode: BPICCANT
/* 71 */      MCD_OPC_FilterValue, 1, 31, 0, 0, // Skip to: 107
/* 76 */      MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 79 */      MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 93
/* 84 */      MCD_OPC_CheckPredicate, 0, 31, 31, 0, // Skip to: 8056
/* 89 */      MCD_OPC_Decode, 172, 2, 1, // Opcode: BPICC
/* 93 */      MCD_OPC_FilterValue, 1, 22, 31, 0, // Skip to: 8056
/* 98 */      MCD_OPC_CheckPredicate, 0, 17, 31, 0, // Skip to: 8056
/* 103 */     MCD_OPC_Decode, 173, 2, 1, // Opcode: BPICCA
/* 107 */     MCD_OPC_FilterValue, 4, 21, 0, 0, // Skip to: 133
/* 112 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 115 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 124
/* 120 */     MCD_OPC_Decode, 191, 2, 1, // Opcode: BPXCCNT
/* 124 */     MCD_OPC_FilterValue, 1, 247, 30, 0, // Skip to: 8056
/* 129 */     MCD_OPC_Decode, 190, 2, 1, // Opcode: BPXCCANT
/* 133 */     MCD_OPC_FilterValue, 5, 238, 30, 0, // Skip to: 8056
/* 138 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 141 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 150
/* 146 */     MCD_OPC_Decode, 188, 2, 1, // Opcode: BPXCC
/* 150 */     MCD_OPC_FilterValue, 1, 221, 30, 0, // Skip to: 8056
/* 155 */     MCD_OPC_Decode, 189, 2, 1, // Opcode: BPXCCA
/* 159 */     MCD_OPC_FilterValue, 2, 32, 0, 0, // Skip to: 196
/* 164 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 167 */     MCD_OPC_FilterValue, 0, 15, 0, 0, // Skip to: 187
/* 172 */     MCD_OPC_CheckField, 25, 4, 8, 4, 0, 0, // Skip to: 183
/* 179 */     MCD_OPC_Decode, 154, 2, 0, // Opcode: BA
/* 183 */     MCD_OPC_Decode, 155, 2, 2, // Opcode: BCOND
/* 187 */     MCD_OPC_FilterValue, 1, 184, 30, 0, // Skip to: 8056
/* 192 */     MCD_OPC_Decode, 156, 2, 2, // Opcode: BCONDA
/* 196 */     MCD_OPC_FilterValue, 3, 59, 1, 0, // Skip to: 516
/* 201 */     MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 204 */     MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 230
/* 209 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 212 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 221
/* 217 */     MCD_OPC_Decode, 194, 2, 3, // Opcode: BPZnapn
/* 221 */     MCD_OPC_FilterValue, 1, 150, 30, 0, // Skip to: 8056
/* 226 */     MCD_OPC_Decode, 195, 2, 3, // Opcode: BPZnapt
/* 230 */     MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 256
/* 235 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 238 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 247
/* 243 */     MCD_OPC_Decode, 178, 2, 3, // Opcode: BPLEZnapn
/* 247 */     MCD_OPC_FilterValue, 1, 124, 30, 0, // Skip to: 8056
/* 252 */     MCD_OPC_Decode, 179, 2, 3, // Opcode: BPLEZnapt
/* 256 */     MCD_OPC_FilterValue, 3, 21, 0, 0, // Skip to: 282
/* 261 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 264 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 273
/* 269 */     MCD_OPC_Decode, 182, 2, 3, // Opcode: BPLZnapn
/* 273 */     MCD_OPC_FilterValue, 1, 98, 30, 0, // Skip to: 8056
/* 278 */     MCD_OPC_Decode, 183, 2, 3, // Opcode: BPLZnapt
/* 282 */     MCD_OPC_FilterValue, 5, 21, 0, 0, // Skip to: 308
/* 287 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 290 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 299
/* 295 */     MCD_OPC_Decode, 186, 2, 3, // Opcode: BPNZnapn
/* 299 */     MCD_OPC_FilterValue, 1, 72, 30, 0, // Skip to: 8056
/* 304 */     MCD_OPC_Decode, 187, 2, 3, // Opcode: BPNZnapt
/* 308 */     MCD_OPC_FilterValue, 6, 21, 0, 0, // Skip to: 334
/* 313 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 316 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 325
/* 321 */     MCD_OPC_Decode, 170, 2, 3, // Opcode: BPGZnapn
/* 325 */     MCD_OPC_FilterValue, 1, 46, 30, 0, // Skip to: 8056
/* 330 */     MCD_OPC_Decode, 171, 2, 3, // Opcode: BPGZnapt
/* 334 */     MCD_OPC_FilterValue, 7, 21, 0, 0, // Skip to: 360
/* 339 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 342 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 351
/* 347 */     MCD_OPC_Decode, 166, 2, 3, // Opcode: BPGEZnapn
/* 351 */     MCD_OPC_FilterValue, 1, 20, 30, 0, // Skip to: 8056
/* 356 */     MCD_OPC_Decode, 167, 2, 3, // Opcode: BPGEZnapt
/* 360 */     MCD_OPC_FilterValue, 17, 21, 0, 0, // Skip to: 386
/* 365 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 368 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 377
/* 373 */     MCD_OPC_Decode, 192, 2, 3, // Opcode: BPZapn
/* 377 */     MCD_OPC_FilterValue, 1, 250, 29, 0, // Skip to: 8056
/* 382 */     MCD_OPC_Decode, 193, 2, 3, // Opcode: BPZapt
/* 386 */     MCD_OPC_FilterValue, 18, 21, 0, 0, // Skip to: 412
/* 391 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 394 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 403
/* 399 */     MCD_OPC_Decode, 176, 2, 3, // Opcode: BPLEZapn
/* 403 */     MCD_OPC_FilterValue, 1, 224, 29, 0, // Skip to: 8056
/* 408 */     MCD_OPC_Decode, 177, 2, 3, // Opcode: BPLEZapt
/* 412 */     MCD_OPC_FilterValue, 19, 21, 0, 0, // Skip to: 438
/* 417 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 420 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 429
/* 425 */     MCD_OPC_Decode, 180, 2, 3, // Opcode: BPLZapn
/* 429 */     MCD_OPC_FilterValue, 1, 198, 29, 0, // Skip to: 8056
/* 434 */     MCD_OPC_Decode, 181, 2, 3, // Opcode: BPLZapt
/* 438 */     MCD_OPC_FilterValue, 21, 21, 0, 0, // Skip to: 464
/* 443 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 446 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 455
/* 451 */     MCD_OPC_Decode, 184, 2, 3, // Opcode: BPNZapn
/* 455 */     MCD_OPC_FilterValue, 1, 172, 29, 0, // Skip to: 8056
/* 460 */     MCD_OPC_Decode, 185, 2, 3, // Opcode: BPNZapt
/* 464 */     MCD_OPC_FilterValue, 22, 21, 0, 0, // Skip to: 490
/* 469 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 472 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 481
/* 477 */     MCD_OPC_Decode, 168, 2, 3, // Opcode: BPGZapn
/* 481 */     MCD_OPC_FilterValue, 1, 146, 29, 0, // Skip to: 8056
/* 486 */     MCD_OPC_Decode, 169, 2, 3, // Opcode: BPGZapt
/* 490 */     MCD_OPC_FilterValue, 23, 137, 29, 0, // Skip to: 8056
/* 495 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 498 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 507
/* 503 */     MCD_OPC_Decode, 164, 2, 3, // Opcode: BPGEZapn
/* 507 */     MCD_OPC_FilterValue, 1, 120, 29, 0, // Skip to: 8056
/* 512 */     MCD_OPC_Decode, 165, 2, 3, // Opcode: BPGEZapt
/* 516 */     MCD_OPC_FilterValue, 4, 22, 0, 0, // Skip to: 543
/* 521 */     MCD_OPC_CheckField, 25, 5, 0, 11, 0, 0, // Skip to: 539
/* 528 */     MCD_OPC_CheckField, 0, 22, 0, 4, 0, 0, // Skip to: 539
/* 535 */     MCD_OPC_Decode, 209, 4, 4, // Opcode: NOP
/* 539 */     MCD_OPC_Decode, 249, 4, 5, // Opcode: SETHIi
/* 543 */     MCD_OPC_FilterValue, 5, 75, 0, 0, // Skip to: 623
/* 548 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 551 */     MCD_OPC_FilterValue, 0, 31, 0, 0, // Skip to: 587
/* 556 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 559 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 573
/* 564 */     MCD_OPC_CheckPredicate, 0, 63, 29, 0, // Skip to: 8056
/* 569 */     MCD_OPC_Decode, 163, 2, 6, // Opcode: BPFCCNT
/* 573 */     MCD_OPC_FilterValue, 1, 54, 29, 0, // Skip to: 8056
/* 578 */     MCD_OPC_CheckPredicate, 0, 49, 29, 0, // Skip to: 8056
/* 583 */     MCD_OPC_Decode, 162, 2, 6, // Opcode: BPFCCANT
/* 587 */     MCD_OPC_FilterValue, 1, 40, 29, 0, // Skip to: 8056
/* 592 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 595 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 609
/* 600 */     MCD_OPC_CheckPredicate, 0, 27, 29, 0, // Skip to: 8056
/* 605 */     MCD_OPC_Decode, 160, 2, 6, // Opcode: BPFCC
/* 609 */     MCD_OPC_FilterValue, 1, 18, 29, 0, // Skip to: 8056
/* 614 */     MCD_OPC_CheckPredicate, 0, 13, 29, 0, // Skip to: 8056
/* 619 */     MCD_OPC_Decode, 161, 2, 6, // Opcode: BPFCCA
/* 623 */     MCD_OPC_FilterValue, 6, 21, 0, 0, // Skip to: 649
/* 628 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 631 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 640
/* 636 */     MCD_OPC_Decode, 236, 2, 2, // Opcode: FBCOND
/* 640 */     MCD_OPC_FilterValue, 1, 243, 28, 0, // Skip to: 8056
/* 645 */     MCD_OPC_Decode, 237, 2, 2, // Opcode: FBCONDA
/* 649 */     MCD_OPC_FilterValue, 7, 234, 28, 0, // Skip to: 8056
/* 654 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 657 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 666
/* 662 */     MCD_OPC_Decode, 204, 2, 2, // Opcode: CBCOND
/* 666 */     MCD_OPC_FilterValue, 1, 217, 28, 0, // Skip to: 8056
/* 671 */     MCD_OPC_Decode, 205, 2, 2, // Opcode: CBCONDA
/* 675 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 684
/* 680 */     MCD_OPC_Decode, 197, 2, 7, // Opcode: CALL
/* 684 */     MCD_OPC_FilterValue, 2, 188, 22, 0, // Skip to: 6509
/* 689 */     MCD_OPC_ExtractField, 19, 6,  // Inst{24-19} ...
/* 692 */     MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 725
/* 697 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 700 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 716
/* 705 */     MCD_OPC_CheckField, 5, 8, 0, 176, 28, 0, // Skip to: 8056
/* 712 */     MCD_OPC_Decode, 137, 2, 8, // Opcode: ADDrr
/* 716 */     MCD_OPC_FilterValue, 1, 167, 28, 0, // Skip to: 8056
/* 721 */     MCD_OPC_Decode, 136, 2, 9, // Opcode: ADDri
/* 725 */     MCD_OPC_FilterValue, 1, 28, 0, 0, // Skip to: 758
/* 730 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 733 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 749
/* 738 */     MCD_OPC_CheckField, 5, 8, 0, 143, 28, 0, // Skip to: 8056
/* 745 */     MCD_OPC_Decode, 150, 2, 8, // Opcode: ANDrr
/* 749 */     MCD_OPC_FilterValue, 1, 134, 28, 0, // Skip to: 8056
/* 754 */     MCD_OPC_Decode, 149, 2, 9, // Opcode: ANDri
/* 758 */     MCD_OPC_FilterValue, 2, 28, 0, 0, // Skip to: 791
/* 763 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 766 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 782
/* 771 */     MCD_OPC_CheckField, 5, 8, 0, 110, 28, 0, // Skip to: 8056
/* 778 */     MCD_OPC_Decode, 220, 4, 8, // Opcode: ORrr
/* 782 */     MCD_OPC_FilterValue, 1, 101, 28, 0, // Skip to: 8056
/* 787 */     MCD_OPC_Decode, 219, 4, 9, // Opcode: ORri
/* 791 */     MCD_OPC_FilterValue, 3, 28, 0, 0, // Skip to: 824
/* 796 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 799 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 815
/* 804 */     MCD_OPC_CheckField, 5, 8, 0, 77, 28, 0, // Skip to: 8056
/* 811 */     MCD_OPC_Decode, 135, 6, 8, // Opcode: XORrr
/* 815 */     MCD_OPC_FilterValue, 1, 68, 28, 0, // Skip to: 8056
/* 820 */     MCD_OPC_Decode, 134, 6, 9, // Opcode: XORri
/* 824 */     MCD_OPC_FilterValue, 4, 28, 0, 0, // Skip to: 857
/* 829 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 832 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 848
/* 837 */     MCD_OPC_CheckField, 5, 8, 0, 44, 28, 0, // Skip to: 8056
/* 844 */     MCD_OPC_Decode, 190, 5, 8, // Opcode: SUBrr
/* 848 */     MCD_OPC_FilterValue, 1, 35, 28, 0, // Skip to: 8056
/* 853 */     MCD_OPC_Decode, 189, 5, 9, // Opcode: SUBri
/* 857 */     MCD_OPC_FilterValue, 5, 28, 0, 0, // Skip to: 890
/* 862 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 865 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 881
/* 870 */     MCD_OPC_CheckField, 5, 8, 0, 11, 28, 0, // Skip to: 8056
/* 877 */     MCD_OPC_Decode, 145, 2, 8, // Opcode: ANDNrr
/* 881 */     MCD_OPC_FilterValue, 1, 2, 28, 0, // Skip to: 8056
/* 886 */     MCD_OPC_Decode, 144, 2, 9, // Opcode: ANDNri
/* 890 */     MCD_OPC_FilterValue, 6, 28, 0, 0, // Skip to: 923
/* 895 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 898 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 914
/* 903 */     MCD_OPC_CheckField, 5, 8, 0, 234, 27, 0, // Skip to: 8056
/* 910 */     MCD_OPC_Decode, 215, 4, 8, // Opcode: ORNrr
/* 914 */     MCD_OPC_FilterValue, 1, 225, 27, 0, // Skip to: 8056
/* 919 */     MCD_OPC_Decode, 214, 4, 9, // Opcode: ORNri
/* 923 */     MCD_OPC_FilterValue, 7, 28, 0, 0, // Skip to: 956
/* 928 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 931 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 947
/* 936 */     MCD_OPC_CheckField, 5, 8, 0, 201, 27, 0, // Skip to: 8056
/* 943 */     MCD_OPC_Decode, 129, 6, 8, // Opcode: XNORrr
/* 947 */     MCD_OPC_FilterValue, 1, 192, 27, 0, // Skip to: 8056
/* 952 */     MCD_OPC_Decode, 128, 6, 9, // Opcode: XNORri
/* 956 */     MCD_OPC_FilterValue, 8, 28, 0, 0, // Skip to: 989
/* 961 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 964 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 980
/* 969 */     MCD_OPC_CheckField, 5, 8, 0, 168, 27, 0, // Skip to: 8056
/* 976 */     MCD_OPC_Decode, 129, 2, 8, // Opcode: ADDCrr
/* 980 */     MCD_OPC_FilterValue, 1, 159, 27, 0, // Skip to: 8056
/* 985 */     MCD_OPC_Decode, 128, 2, 9, // Opcode: ADDCri
/* 989 */     MCD_OPC_FilterValue, 9, 28, 0, 0, // Skip to: 1022
/* 994 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 997 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1013
/* 1002 */    MCD_OPC_CheckField, 5, 8, 0, 135, 27, 0, // Skip to: 8056
/* 1009 */    MCD_OPC_Decode, 208, 4, 10, // Opcode: MULXrr
/* 1013 */    MCD_OPC_FilterValue, 1, 126, 27, 0, // Skip to: 8056
/* 1018 */    MCD_OPC_Decode, 207, 4, 11, // Opcode: MULXri
/* 1022 */    MCD_OPC_FilterValue, 10, 28, 0, 0, // Skip to: 1055
/* 1027 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1030 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1046
/* 1035 */    MCD_OPC_CheckField, 5, 8, 0, 102, 27, 0, // Skip to: 8056
/* 1042 */    MCD_OPC_Decode, 228, 5, 8, // Opcode: UMULrr
/* 1046 */    MCD_OPC_FilterValue, 1, 93, 27, 0, // Skip to: 8056
/* 1051 */    MCD_OPC_Decode, 227, 5, 9, // Opcode: UMULri
/* 1055 */    MCD_OPC_FilterValue, 11, 28, 0, 0, // Skip to: 1088
/* 1060 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1063 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1079
/* 1068 */    MCD_OPC_CheckField, 5, 8, 0, 69, 27, 0, // Skip to: 8056
/* 1075 */    MCD_OPC_Decode, 134, 5, 8, // Opcode: SMULrr
/* 1079 */    MCD_OPC_FilterValue, 1, 60, 27, 0, // Skip to: 8056
/* 1084 */    MCD_OPC_Decode, 133, 5, 9, // Opcode: SMULri
/* 1088 */    MCD_OPC_FilterValue, 12, 28, 0, 0, // Skip to: 1121
/* 1093 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1096 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1112
/* 1101 */    MCD_OPC_CheckField, 5, 8, 0, 36, 27, 0, // Skip to: 8056
/* 1108 */    MCD_OPC_Decode, 184, 5, 8, // Opcode: SUBCrr
/* 1112 */    MCD_OPC_FilterValue, 1, 27, 27, 0, // Skip to: 8056
/* 1117 */    MCD_OPC_Decode, 183, 5, 9, // Opcode: SUBCri
/* 1121 */    MCD_OPC_FilterValue, 13, 28, 0, 0, // Skip to: 1154
/* 1126 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1129 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1145
/* 1134 */    MCD_OPC_CheckField, 5, 8, 0, 3, 27, 0, // Skip to: 8056
/* 1141 */    MCD_OPC_Decode, 219, 5, 10, // Opcode: UDIVXrr
/* 1145 */    MCD_OPC_FilterValue, 1, 250, 26, 0, // Skip to: 8056
/* 1150 */    MCD_OPC_Decode, 218, 5, 11, // Opcode: UDIVXri
/* 1154 */    MCD_OPC_FilterValue, 14, 28, 0, 0, // Skip to: 1187
/* 1159 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1162 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1178
/* 1167 */    MCD_OPC_CheckField, 5, 8, 0, 226, 26, 0, // Skip to: 8056
/* 1174 */    MCD_OPC_Decode, 221, 5, 8, // Opcode: UDIVrr
/* 1178 */    MCD_OPC_FilterValue, 1, 217, 26, 0, // Skip to: 8056
/* 1183 */    MCD_OPC_Decode, 220, 5, 9, // Opcode: UDIVri
/* 1187 */    MCD_OPC_FilterValue, 15, 28, 0, 0, // Skip to: 1220
/* 1192 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1195 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1211
/* 1200 */    MCD_OPC_CheckField, 5, 8, 0, 193, 26, 0, // Skip to: 8056
/* 1207 */    MCD_OPC_Decode, 247, 4, 8, // Opcode: SDIVrr
/* 1211 */    MCD_OPC_FilterValue, 1, 184, 26, 0, // Skip to: 8056
/* 1216 */    MCD_OPC_Decode, 246, 4, 9, // Opcode: SDIVri
/* 1220 */    MCD_OPC_FilterValue, 16, 28, 0, 0, // Skip to: 1253
/* 1225 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1228 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1244
/* 1233 */    MCD_OPC_CheckField, 5, 8, 0, 160, 26, 0, // Skip to: 8056
/* 1240 */    MCD_OPC_Decode, 255, 1, 8, // Opcode: ADDCCrr
/* 1244 */    MCD_OPC_FilterValue, 1, 151, 26, 0, // Skip to: 8056
/* 1249 */    MCD_OPC_Decode, 254, 1, 9, // Opcode: ADDCCri
/* 1253 */    MCD_OPC_FilterValue, 17, 28, 0, 0, // Skip to: 1286
/* 1258 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1261 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1277
/* 1266 */    MCD_OPC_CheckField, 5, 8, 0, 127, 26, 0, // Skip to: 8056
/* 1273 */    MCD_OPC_Decode, 141, 2, 8, // Opcode: ANDCCrr
/* 1277 */    MCD_OPC_FilterValue, 1, 118, 26, 0, // Skip to: 8056
/* 1282 */    MCD_OPC_Decode, 140, 2, 9, // Opcode: ANDCCri
/* 1286 */    MCD_OPC_FilterValue, 18, 28, 0, 0, // Skip to: 1319
/* 1291 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1294 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1310
/* 1299 */    MCD_OPC_CheckField, 5, 8, 0, 94, 26, 0, // Skip to: 8056
/* 1306 */    MCD_OPC_Decode, 211, 4, 8, // Opcode: ORCCrr
/* 1310 */    MCD_OPC_FilterValue, 1, 85, 26, 0, // Skip to: 8056
/* 1315 */    MCD_OPC_Decode, 210, 4, 9, // Opcode: ORCCri
/* 1319 */    MCD_OPC_FilterValue, 19, 28, 0, 0, // Skip to: 1352
/* 1324 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1327 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1343
/* 1332 */    MCD_OPC_CheckField, 5, 8, 0, 61, 26, 0, // Skip to: 8056
/* 1339 */    MCD_OPC_Decode, 131, 6, 8, // Opcode: XORCCrr
/* 1343 */    MCD_OPC_FilterValue, 1, 52, 26, 0, // Skip to: 8056
/* 1348 */    MCD_OPC_Decode, 130, 6, 9, // Opcode: XORCCri
/* 1352 */    MCD_OPC_FilterValue, 20, 51, 0, 0, // Skip to: 1408
/* 1357 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1360 */    MCD_OPC_FilterValue, 0, 23, 0, 0, // Skip to: 1388
/* 1365 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 1368 */    MCD_OPC_FilterValue, 0, 27, 26, 0, // Skip to: 8056
/* 1373 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 1384
/* 1380 */    MCD_OPC_Decode, 210, 2, 12, // Opcode: CMPrr
/* 1384 */    MCD_OPC_Decode, 182, 5, 8, // Opcode: SUBCCrr
/* 1388 */    MCD_OPC_FilterValue, 1, 7, 26, 0, // Skip to: 8056
/* 1393 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 1404
/* 1400 */    MCD_OPC_Decode, 209, 2, 13, // Opcode: CMPri
/* 1404 */    MCD_OPC_Decode, 181, 5, 9, // Opcode: SUBCCri
/* 1408 */    MCD_OPC_FilterValue, 21, 28, 0, 0, // Skip to: 1441
/* 1413 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1416 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1432
/* 1421 */    MCD_OPC_CheckField, 5, 8, 0, 228, 25, 0, // Skip to: 8056
/* 1428 */    MCD_OPC_Decode, 143, 2, 8, // Opcode: ANDNCCrr
/* 1432 */    MCD_OPC_FilterValue, 1, 219, 25, 0, // Skip to: 8056
/* 1437 */    MCD_OPC_Decode, 142, 2, 9, // Opcode: ANDNCCri
/* 1441 */    MCD_OPC_FilterValue, 22, 28, 0, 0, // Skip to: 1474
/* 1446 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1449 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1465
/* 1454 */    MCD_OPC_CheckField, 5, 8, 0, 195, 25, 0, // Skip to: 8056
/* 1461 */    MCD_OPC_Decode, 213, 4, 8, // Opcode: ORNCCrr
/* 1465 */    MCD_OPC_FilterValue, 1, 186, 25, 0, // Skip to: 8056
/* 1470 */    MCD_OPC_Decode, 212, 4, 9, // Opcode: ORNCCri
/* 1474 */    MCD_OPC_FilterValue, 23, 28, 0, 0, // Skip to: 1507
/* 1479 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1482 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1498
/* 1487 */    MCD_OPC_CheckField, 5, 8, 0, 162, 25, 0, // Skip to: 8056
/* 1494 */    MCD_OPC_Decode, 254, 5, 8, // Opcode: XNORCCrr
/* 1498 */    MCD_OPC_FilterValue, 1, 153, 25, 0, // Skip to: 8056
/* 1503 */    MCD_OPC_Decode, 253, 5, 9, // Opcode: XNORCCri
/* 1507 */    MCD_OPC_FilterValue, 24, 28, 0, 0, // Skip to: 1540
/* 1512 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1515 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1531
/* 1520 */    MCD_OPC_CheckField, 5, 8, 0, 129, 25, 0, // Skip to: 8056
/* 1527 */    MCD_OPC_Decode, 131, 2, 8, // Opcode: ADDErr
/* 1531 */    MCD_OPC_FilterValue, 1, 120, 25, 0, // Skip to: 8056
/* 1536 */    MCD_OPC_Decode, 130, 2, 9, // Opcode: ADDEri
/* 1540 */    MCD_OPC_FilterValue, 26, 28, 0, 0, // Skip to: 1573
/* 1545 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1548 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1564
/* 1553 */    MCD_OPC_CheckField, 5, 8, 0, 96, 25, 0, // Skip to: 8056
/* 1560 */    MCD_OPC_Decode, 225, 5, 8, // Opcode: UMULCCrr
/* 1564 */    MCD_OPC_FilterValue, 1, 87, 25, 0, // Skip to: 8056
/* 1569 */    MCD_OPC_Decode, 224, 5, 9, // Opcode: UMULCCri
/* 1573 */    MCD_OPC_FilterValue, 27, 28, 0, 0, // Skip to: 1606
/* 1578 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1581 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1597
/* 1586 */    MCD_OPC_CheckField, 5, 8, 0, 63, 25, 0, // Skip to: 8056
/* 1593 */    MCD_OPC_Decode, 132, 5, 8, // Opcode: SMULCCrr
/* 1597 */    MCD_OPC_FilterValue, 1, 54, 25, 0, // Skip to: 8056
/* 1602 */    MCD_OPC_Decode, 131, 5, 9, // Opcode: SMULCCri
/* 1606 */    MCD_OPC_FilterValue, 28, 28, 0, 0, // Skip to: 1639
/* 1611 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1614 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1630
/* 1619 */    MCD_OPC_CheckField, 5, 8, 0, 30, 25, 0, // Skip to: 8056
/* 1626 */    MCD_OPC_Decode, 186, 5, 8, // Opcode: SUBErr
/* 1630 */    MCD_OPC_FilterValue, 1, 21, 25, 0, // Skip to: 8056
/* 1635 */    MCD_OPC_Decode, 185, 5, 9, // Opcode: SUBEri
/* 1639 */    MCD_OPC_FilterValue, 30, 28, 0, 0, // Skip to: 1672
/* 1644 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1647 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1663
/* 1652 */    MCD_OPC_CheckField, 5, 8, 0, 253, 24, 0, // Skip to: 8056
/* 1659 */    MCD_OPC_Decode, 217, 5, 8, // Opcode: UDIVCCrr
/* 1663 */    MCD_OPC_FilterValue, 1, 244, 24, 0, // Skip to: 8056
/* 1668 */    MCD_OPC_Decode, 216, 5, 9, // Opcode: UDIVCCri
/* 1672 */    MCD_OPC_FilterValue, 31, 28, 0, 0, // Skip to: 1705
/* 1677 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1680 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1696
/* 1685 */    MCD_OPC_CheckField, 5, 8, 0, 220, 24, 0, // Skip to: 8056
/* 1692 */    MCD_OPC_Decode, 243, 4, 8, // Opcode: SDIVCCrr
/* 1696 */    MCD_OPC_FilterValue, 1, 211, 24, 0, // Skip to: 8056
/* 1701 */    MCD_OPC_Decode, 242, 4, 9, // Opcode: SDIVCCri
/* 1705 */    MCD_OPC_FilterValue, 32, 28, 0, 0, // Skip to: 1738
/* 1710 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1713 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1729
/* 1718 */    MCD_OPC_CheckField, 5, 8, 0, 187, 24, 0, // Skip to: 8056
/* 1725 */    MCD_OPC_Decode, 200, 5, 8, // Opcode: TADDCCrr
/* 1729 */    MCD_OPC_FilterValue, 1, 178, 24, 0, // Skip to: 8056
/* 1734 */    MCD_OPC_Decode, 199, 5, 9, // Opcode: TADDCCri
/* 1738 */    MCD_OPC_FilterValue, 33, 28, 0, 0, // Skip to: 1771
/* 1743 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1746 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1762
/* 1751 */    MCD_OPC_CheckField, 5, 8, 0, 154, 24, 0, // Skip to: 8056
/* 1758 */    MCD_OPC_Decode, 213, 5, 8, // Opcode: TSUBCCrr
/* 1762 */    MCD_OPC_FilterValue, 1, 145, 24, 0, // Skip to: 8056
/* 1767 */    MCD_OPC_Decode, 212, 5, 9, // Opcode: TSUBCCri
/* 1771 */    MCD_OPC_FilterValue, 34, 28, 0, 0, // Skip to: 1804
/* 1776 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1779 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1795
/* 1784 */    MCD_OPC_CheckField, 5, 8, 0, 121, 24, 0, // Skip to: 8056
/* 1791 */    MCD_OPC_Decode, 198, 5, 8, // Opcode: TADDCCTVrr
/* 1795 */    MCD_OPC_FilterValue, 1, 112, 24, 0, // Skip to: 8056
/* 1800 */    MCD_OPC_Decode, 197, 5, 9, // Opcode: TADDCCTVri
/* 1804 */    MCD_OPC_FilterValue, 35, 28, 0, 0, // Skip to: 1837
/* 1809 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1812 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1828
/* 1817 */    MCD_OPC_CheckField, 5, 8, 0, 88, 24, 0, // Skip to: 8056
/* 1824 */    MCD_OPC_Decode, 211, 5, 8, // Opcode: TSUBCCTVrr
/* 1828 */    MCD_OPC_FilterValue, 1, 79, 24, 0, // Skip to: 8056
/* 1833 */    MCD_OPC_Decode, 210, 5, 9, // Opcode: TSUBCCTVri
/* 1837 */    MCD_OPC_FilterValue, 36, 28, 0, 0, // Skip to: 1870
/* 1842 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1845 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1861
/* 1850 */    MCD_OPC_CheckField, 5, 8, 0, 55, 24, 0, // Skip to: 8056
/* 1857 */    MCD_OPC_Decode, 206, 4, 8, // Opcode: MULSCCrr
/* 1861 */    MCD_OPC_FilterValue, 1, 46, 24, 0, // Skip to: 8056
/* 1866 */    MCD_OPC_Decode, 205, 4, 9, // Opcode: MULSCCri
/* 1870 */    MCD_OPC_FilterValue, 37, 39, 0, 0, // Skip to: 1914
/* 1875 */    MCD_OPC_ExtractField, 12, 2,  // Inst{13-12} ...
/* 1878 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1887
/* 1883 */    MCD_OPC_Decode, 128, 5, 8, // Opcode: SLLrr
/* 1887 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1896
/* 1892 */    MCD_OPC_Decode, 254, 4, 14, // Opcode: SLLXrr
/* 1896 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1905
/* 1901 */    MCD_OPC_Decode, 255, 4, 15, // Opcode: SLLri
/* 1905 */    MCD_OPC_FilterValue, 3, 2, 24, 0, // Skip to: 8056
/* 1910 */    MCD_OPC_Decode, 253, 4, 16, // Opcode: SLLXri
/* 1914 */    MCD_OPC_FilterValue, 38, 39, 0, 0, // Skip to: 1958
/* 1919 */    MCD_OPC_ExtractField, 12, 2,  // Inst{13-12} ...
/* 1922 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1931
/* 1927 */    MCD_OPC_Decode, 142, 5, 8, // Opcode: SRLrr
/* 1931 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1940
/* 1936 */    MCD_OPC_Decode, 140, 5, 14, // Opcode: SRLXrr
/* 1940 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1949
/* 1945 */    MCD_OPC_Decode, 141, 5, 15, // Opcode: SRLri
/* 1949 */    MCD_OPC_FilterValue, 3, 214, 23, 0, // Skip to: 8056
/* 1954 */    MCD_OPC_Decode, 139, 5, 16, // Opcode: SRLXri
/* 1958 */    MCD_OPC_FilterValue, 39, 39, 0, 0, // Skip to: 2002
/* 1963 */    MCD_OPC_ExtractField, 12, 2,  // Inst{13-12} ...
/* 1966 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1975
/* 1971 */    MCD_OPC_Decode, 138, 5, 8, // Opcode: SRArr
/* 1975 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1984
/* 1980 */    MCD_OPC_Decode, 136, 5, 14, // Opcode: SRAXrr
/* 1984 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1993
/* 1989 */    MCD_OPC_Decode, 137, 5, 15, // Opcode: SRAri
/* 1993 */    MCD_OPC_FilterValue, 3, 170, 23, 0, // Skip to: 8056
/* 1998 */    MCD_OPC_Decode, 135, 5, 16, // Opcode: SRAXri
/* 2002 */    MCD_OPC_FilterValue, 40, 81, 0, 0, // Skip to: 2088
/* 2007 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2010 */    MCD_OPC_FilterValue, 0, 45, 0, 0, // Skip to: 2060
/* 2015 */    MCD_OPC_ExtractField, 0, 13,  // Inst{12-0} ...
/* 2018 */    MCD_OPC_FilterValue, 0, 145, 23, 0, // Skip to: 8056
/* 2023 */    MCD_OPC_ExtractField, 14, 5,  // Inst{18-14} ...
/* 2026 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 2040
/* 2031 */    MCD_OPC_CheckPredicate, 0, 20, 0, 0, // Skip to: 2056
/* 2036 */    MCD_OPC_Decode, 229, 4, 17, // Opcode: RDPC
/* 2040 */    MCD_OPC_FilterValue, 15, 11, 0, 0, // Skip to: 2056
/* 2045 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 2056
/* 2052 */    MCD_OPC_Decode, 144, 5, 4, // Opcode: STBAR
/* 2056 */    MCD_OPC_Decode, 228, 4, 18, // Opcode: RDASR
/* 2060 */    MCD_OPC_FilterValue, 1, 103, 23, 0, // Skip to: 8056
/* 2065 */    MCD_OPC_CheckPredicate, 0, 98, 23, 0, // Skip to: 8056
/* 2070 */    MCD_OPC_CheckField, 25, 5, 0, 91, 23, 0, // Skip to: 8056
/* 2077 */    MCD_OPC_CheckField, 14, 5, 15, 84, 23, 0, // Skip to: 8056
/* 2084 */    MCD_OPC_Decode, 181, 4, 19, // Opcode: MEMBARi
/* 2088 */    MCD_OPC_FilterValue, 41, 11, 0, 0, // Skip to: 2104
/* 2093 */    MCD_OPC_CheckField, 0, 19, 0, 68, 23, 0, // Skip to: 8056
/* 2100 */    MCD_OPC_Decode, 231, 4, 17, // Opcode: RDPSR
/* 2104 */    MCD_OPC_FilterValue, 42, 28, 0, 0, // Skip to: 2137
/* 2109 */    MCD_OPC_ExtractField, 0, 14,  // Inst{13-0} ...
/* 2112 */    MCD_OPC_FilterValue, 0, 51, 23, 0, // Skip to: 8056
/* 2117 */    MCD_OPC_CheckField, 14, 5, 0, 4, 0, 0, // Skip to: 2128
/* 2124 */    MCD_OPC_Decode, 233, 4, 17, // Opcode: RDWIM
/* 2128 */    MCD_OPC_CheckPredicate, 0, 35, 23, 0, // Skip to: 8056
/* 2133 */    MCD_OPC_Decode, 230, 4, 20, // Opcode: RDPR
/* 2137 */    MCD_OPC_FilterValue, 43, 28, 0, 0, // Skip to: 2170
/* 2142 */    MCD_OPC_ExtractField, 0, 19,  // Inst{18-0} ...
/* 2145 */    MCD_OPC_FilterValue, 0, 18, 23, 0, // Skip to: 8056
/* 2150 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 2166
/* 2155 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 2166
/* 2162 */    MCD_OPC_Decode, 141, 3, 4, // Opcode: FLUSHW
/* 2166 */    MCD_OPC_Decode, 232, 4, 17, // Opcode: RDTBR
/* 2170 */    MCD_OPC_FilterValue, 44, 141, 0, 0, // Skip to: 2316
/* 2175 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2178 */    MCD_OPC_FilterValue, 0, 64, 0, 0, // Skip to: 2247
/* 2183 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 2186 */    MCD_OPC_FilterValue, 0, 25, 0, 0, // Skip to: 2216
/* 2191 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 2207
/* 2196 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 2207
/* 2203 */    MCD_OPC_Decode, 184, 4, 21, // Opcode: MOVFCCrr
/* 2207 */    MCD_OPC_CheckPredicate, 0, 212, 22, 0, // Skip to: 8056
/* 2212 */    MCD_OPC_Decode, 240, 5, 22, // Opcode: V9MOVFCCrr
/* 2216 */    MCD_OPC_FilterValue, 1, 203, 22, 0, // Skip to: 8056
/* 2221 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 2224 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 2238
/* 2229 */    MCD_OPC_CheckPredicate, 0, 190, 22, 0, // Skip to: 8056
/* 2234 */    MCD_OPC_Decode, 186, 4, 21, // Opcode: MOVICCrr
/* 2238 */    MCD_OPC_FilterValue, 2, 181, 22, 0, // Skip to: 8056
/* 2243 */    MCD_OPC_Decode, 203, 4, 21, // Opcode: MOVXCCrr
/* 2247 */    MCD_OPC_FilterValue, 1, 172, 22, 0, // Skip to: 8056
/* 2252 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 2255 */    MCD_OPC_FilterValue, 0, 25, 0, 0, // Skip to: 2285
/* 2260 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 2276
/* 2265 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 2276
/* 2272 */    MCD_OPC_Decode, 183, 4, 23, // Opcode: MOVFCCri
/* 2276 */    MCD_OPC_CheckPredicate, 0, 143, 22, 0, // Skip to: 8056
/* 2281 */    MCD_OPC_Decode, 239, 5, 24, // Opcode: V9MOVFCCri
/* 2285 */    MCD_OPC_FilterValue, 1, 134, 22, 0, // Skip to: 8056
/* 2290 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 2293 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 2307
/* 2298 */    MCD_OPC_CheckPredicate, 0, 121, 22, 0, // Skip to: 8056
/* 2303 */    MCD_OPC_Decode, 185, 4, 23, // Opcode: MOVICCri
/* 2307 */    MCD_OPC_FilterValue, 2, 112, 22, 0, // Skip to: 8056
/* 2312 */    MCD_OPC_Decode, 202, 4, 23, // Opcode: MOVXCCri
/* 2316 */    MCD_OPC_FilterValue, 45, 28, 0, 0, // Skip to: 2349
/* 2321 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2324 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2340
/* 2329 */    MCD_OPC_CheckField, 5, 8, 0, 88, 22, 0, // Skip to: 8056
/* 2336 */    MCD_OPC_Decode, 245, 4, 10, // Opcode: SDIVXrr
/* 2340 */    MCD_OPC_FilterValue, 1, 79, 22, 0, // Skip to: 8056
/* 2345 */    MCD_OPC_Decode, 244, 4, 11, // Opcode: SDIVXri
/* 2349 */    MCD_OPC_FilterValue, 46, 16, 0, 0, // Skip to: 2370
/* 2354 */    MCD_OPC_CheckPredicate, 0, 65, 22, 0, // Skip to: 8056
/* 2359 */    MCD_OPC_CheckField, 5, 14, 0, 58, 22, 0, // Skip to: 8056
/* 2366 */    MCD_OPC_Decode, 223, 4, 25, // Opcode: POPCrr
/* 2370 */    MCD_OPC_FilterValue, 47, 153, 0, 0, // Skip to: 2528
/* 2375 */    MCD_OPC_ExtractField, 10, 4,  // Inst{13-10} ...
/* 2378 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 2394
/* 2383 */    MCD_OPC_CheckField, 5, 5, 0, 34, 22, 0, // Skip to: 8056
/* 2390 */    MCD_OPC_Decode, 198, 4, 14, // Opcode: MOVRRZrr
/* 2394 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 2410
/* 2399 */    MCD_OPC_CheckField, 5, 5, 0, 18, 22, 0, // Skip to: 8056
/* 2406 */    MCD_OPC_Decode, 192, 4, 14, // Opcode: MOVRLEZrr
/* 2410 */    MCD_OPC_FilterValue, 3, 11, 0, 0, // Skip to: 2426
/* 2415 */    MCD_OPC_CheckField, 5, 5, 0, 2, 22, 0, // Skip to: 8056
/* 2422 */    MCD_OPC_Decode, 194, 4, 14, // Opcode: MOVRLZrr
/* 2426 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 2442
/* 2431 */    MCD_OPC_CheckField, 5, 5, 0, 242, 21, 0, // Skip to: 8056
/* 2438 */    MCD_OPC_Decode, 196, 4, 14, // Opcode: MOVRNZrr
/* 2442 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 2458
/* 2447 */    MCD_OPC_CheckField, 5, 5, 0, 226, 21, 0, // Skip to: 8056
/* 2454 */    MCD_OPC_Decode, 190, 4, 14, // Opcode: MOVRGZrr
/* 2458 */    MCD_OPC_FilterValue, 7, 11, 0, 0, // Skip to: 2474
/* 2463 */    MCD_OPC_CheckField, 5, 5, 0, 210, 21, 0, // Skip to: 8056
/* 2470 */    MCD_OPC_Decode, 188, 4, 14, // Opcode: MOVRGEZrr
/* 2474 */    MCD_OPC_FilterValue, 9, 4, 0, 0, // Skip to: 2483
/* 2479 */    MCD_OPC_Decode, 197, 4, 26, // Opcode: MOVRRZri
/* 2483 */    MCD_OPC_FilterValue, 10, 4, 0, 0, // Skip to: 2492
/* 2488 */    MCD_OPC_Decode, 191, 4, 26, // Opcode: MOVRLEZri
/* 2492 */    MCD_OPC_FilterValue, 11, 4, 0, 0, // Skip to: 2501
/* 2497 */    MCD_OPC_Decode, 193, 4, 26, // Opcode: MOVRLZri
/* 2501 */    MCD_OPC_FilterValue, 13, 4, 0, 0, // Skip to: 2510
/* 2506 */    MCD_OPC_Decode, 195, 4, 26, // Opcode: MOVRNZri
/* 2510 */    MCD_OPC_FilterValue, 14, 4, 0, 0, // Skip to: 2519
/* 2515 */    MCD_OPC_Decode, 189, 4, 26, // Opcode: MOVRGZri
/* 2519 */    MCD_OPC_FilterValue, 15, 156, 21, 0, // Skip to: 8056
/* 2524 */    MCD_OPC_Decode, 187, 4, 26, // Opcode: MOVRGEZri
/* 2528 */    MCD_OPC_FilterValue, 48, 51, 0, 0, // Skip to: 2584
/* 2533 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2536 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2552
/* 2541 */    MCD_OPC_CheckField, 5, 8, 0, 132, 21, 0, // Skip to: 8056
/* 2548 */    MCD_OPC_Decode, 242, 5, 27, // Opcode: WRASRrr
/* 2552 */    MCD_OPC_FilterValue, 1, 123, 21, 0, // Skip to: 8056
/* 2557 */    MCD_OPC_CheckPredicate, 0, 18, 0, 0, // Skip to: 2580
/* 2562 */    MCD_OPC_CheckField, 25, 5, 15, 11, 0, 0, // Skip to: 2580
/* 2569 */    MCD_OPC_CheckField, 14, 5, 0, 4, 0, 0, // Skip to: 2580
/* 2576 */    MCD_OPC_Decode, 252, 4, 28, // Opcode: SIR
/* 2580 */    MCD_OPC_Decode, 241, 5, 29, // Opcode: WRASRri
/* 2584 */    MCD_OPC_FilterValue, 49, 79, 0, 0, // Skip to: 2668
/* 2589 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2592 */    MCD_OPC_FilterValue, 0, 40, 0, 0, // Skip to: 2637
/* 2597 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 2600 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2616
/* 2605 */    MCD_OPC_CheckField, 5, 8, 0, 68, 21, 0, // Skip to: 8056
/* 2612 */    MCD_OPC_Decode, 246, 5, 12, // Opcode: WRPSRrr
/* 2616 */    MCD_OPC_FilterValue, 1, 59, 21, 0, // Skip to: 8056
/* 2621 */    MCD_OPC_CheckPredicate, 1, 54, 21, 0, // Skip to: 8056
/* 2626 */    MCD_OPC_CheckField, 5, 8, 0, 47, 21, 0, // Skip to: 8056
/* 2633 */    MCD_OPC_Decode, 227, 4, 12, // Opcode: PWRPSRrr
/* 2637 */    MCD_OPC_FilterValue, 1, 38, 21, 0, // Skip to: 8056
/* 2642 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 2645 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2654
/* 2650 */    MCD_OPC_Decode, 245, 5, 13, // Opcode: WRPSRri
/* 2654 */    MCD_OPC_FilterValue, 1, 21, 21, 0, // Skip to: 8056
/* 2659 */    MCD_OPC_CheckPredicate, 1, 16, 21, 0, // Skip to: 8056
/* 2664 */    MCD_OPC_Decode, 226, 4, 13, // Opcode: PWRPSRri
/* 2668 */    MCD_OPC_FilterValue, 50, 61, 0, 0, // Skip to: 2734
/* 2673 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2676 */    MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 2709
/* 2681 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 2684 */    MCD_OPC_FilterValue, 0, 247, 20, 0, // Skip to: 8056
/* 2689 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 2700
/* 2696 */    MCD_OPC_Decode, 250, 5, 12, // Opcode: WRWIMrr
/* 2700 */    MCD_OPC_CheckPredicate, 0, 231, 20, 0, // Skip to: 8056
/* 2705 */    MCD_OPC_Decode, 244, 5, 30, // Opcode: WRPRrr
/* 2709 */    MCD_OPC_FilterValue, 1, 222, 20, 0, // Skip to: 8056
/* 2714 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 2725
/* 2721 */    MCD_OPC_Decode, 249, 5, 13, // Opcode: WRWIMri
/* 2725 */    MCD_OPC_CheckPredicate, 0, 206, 20, 0, // Skip to: 8056
/* 2730 */    MCD_OPC_Decode, 243, 5, 31, // Opcode: WRPRri
/* 2734 */    MCD_OPC_FilterValue, 51, 42, 0, 0, // Skip to: 2781
/* 2739 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2742 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 2765
/* 2747 */    MCD_OPC_CheckField, 25, 5, 0, 182, 20, 0, // Skip to: 8056
/* 2754 */    MCD_OPC_CheckField, 5, 8, 0, 175, 20, 0, // Skip to: 8056
/* 2761 */    MCD_OPC_Decode, 248, 5, 12, // Opcode: WRTBRrr
/* 2765 */    MCD_OPC_FilterValue, 1, 166, 20, 0, // Skip to: 8056
/* 2770 */    MCD_OPC_CheckField, 25, 5, 0, 159, 20, 0, // Skip to: 8056
/* 2777 */    MCD_OPC_Decode, 247, 5, 13, // Opcode: WRTBRri
/* 2781 */    MCD_OPC_FilterValue, 52, 43, 3, 0, // Skip to: 3597
/* 2786 */    MCD_OPC_ExtractField, 5, 9,  // Inst{13-5} ...
/* 2789 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 2805
/* 2794 */    MCD_OPC_CheckField, 14, 5, 0, 135, 20, 0, // Skip to: 8056
/* 2801 */    MCD_OPC_Decode, 171, 3, 32, // Opcode: FMOVS
/* 2805 */    MCD_OPC_FilterValue, 2, 16, 0, 0, // Skip to: 2826
/* 2810 */    MCD_OPC_CheckPredicate, 0, 121, 20, 0, // Skip to: 8056
/* 2815 */    MCD_OPC_CheckField, 14, 5, 0, 114, 20, 0, // Skip to: 8056
/* 2822 */    MCD_OPC_Decode, 145, 3, 33, // Opcode: FMOVD
/* 2826 */    MCD_OPC_FilterValue, 3, 16, 0, 0, // Skip to: 2847
/* 2831 */    MCD_OPC_CheckPredicate, 0, 100, 20, 0, // Skip to: 8056
/* 2836 */    MCD_OPC_CheckField, 14, 5, 0, 93, 20, 0, // Skip to: 8056
/* 2843 */    MCD_OPC_Decode, 149, 3, 34, // Opcode: FMOVQ
/* 2847 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 2863
/* 2852 */    MCD_OPC_CheckField, 14, 5, 0, 77, 20, 0, // Skip to: 8056
/* 2859 */    MCD_OPC_Decode, 191, 3, 32, // Opcode: FNEGS
/* 2863 */    MCD_OPC_FilterValue, 6, 16, 0, 0, // Skip to: 2884
/* 2868 */    MCD_OPC_CheckPredicate, 0, 63, 20, 0, // Skip to: 8056
/* 2873 */    MCD_OPC_CheckField, 14, 5, 0, 56, 20, 0, // Skip to: 8056
/* 2880 */    MCD_OPC_Decode, 189, 3, 33, // Opcode: FNEGD
/* 2884 */    MCD_OPC_FilterValue, 7, 16, 0, 0, // Skip to: 2905
/* 2889 */    MCD_OPC_CheckPredicate, 0, 42, 20, 0, // Skip to: 8056
/* 2894 */    MCD_OPC_CheckField, 14, 5, 0, 35, 20, 0, // Skip to: 8056
/* 2901 */    MCD_OPC_Decode, 190, 3, 34, // Opcode: FNEGQ
/* 2905 */    MCD_OPC_FilterValue, 9, 11, 0, 0, // Skip to: 2921
/* 2910 */    MCD_OPC_CheckField, 14, 5, 0, 19, 20, 0, // Skip to: 8056
/* 2917 */    MCD_OPC_Decode, 225, 2, 32, // Opcode: FABSS
/* 2921 */    MCD_OPC_FilterValue, 10, 16, 0, 0, // Skip to: 2942
/* 2926 */    MCD_OPC_CheckPredicate, 0, 5, 20, 0, // Skip to: 8056
/* 2931 */    MCD_OPC_CheckField, 14, 5, 0, 254, 19, 0, // Skip to: 8056
/* 2938 */    MCD_OPC_Decode, 223, 2, 33, // Opcode: FABSD
/* 2942 */    MCD_OPC_FilterValue, 11, 16, 0, 0, // Skip to: 2963
/* 2947 */    MCD_OPC_CheckPredicate, 0, 240, 19, 0, // Skip to: 8056
/* 2952 */    MCD_OPC_CheckField, 14, 5, 0, 233, 19, 0, // Skip to: 8056
/* 2959 */    MCD_OPC_Decode, 224, 2, 34, // Opcode: FABSQ
/* 2963 */    MCD_OPC_FilterValue, 41, 11, 0, 0, // Skip to: 2979
/* 2968 */    MCD_OPC_CheckField, 14, 5, 0, 217, 19, 0, // Skip to: 8056
/* 2975 */    MCD_OPC_Decode, 235, 3, 32, // Opcode: FSQRTS
/* 2979 */    MCD_OPC_FilterValue, 42, 11, 0, 0, // Skip to: 2995
/* 2984 */    MCD_OPC_CheckField, 14, 5, 0, 201, 19, 0, // Skip to: 8056
/* 2991 */    MCD_OPC_Decode, 233, 3, 33, // Opcode: FSQRTD
/* 2995 */    MCD_OPC_FilterValue, 43, 11, 0, 0, // Skip to: 3011
/* 3000 */    MCD_OPC_CheckField, 14, 5, 0, 185, 19, 0, // Skip to: 8056
/* 3007 */    MCD_OPC_Decode, 234, 3, 34, // Opcode: FSQRTQ
/* 3011 */    MCD_OPC_FilterValue, 65, 4, 0, 0, // Skip to: 3020
/* 3016 */    MCD_OPC_Decode, 228, 2, 35, // Opcode: FADDS
/* 3020 */    MCD_OPC_FilterValue, 66, 4, 0, 0, // Skip to: 3029
/* 3025 */    MCD_OPC_Decode, 226, 2, 36, // Opcode: FADDD
/* 3029 */    MCD_OPC_FilterValue, 67, 4, 0, 0, // Skip to: 3038
/* 3034 */    MCD_OPC_Decode, 227, 2, 37, // Opcode: FADDQ
/* 3038 */    MCD_OPC_FilterValue, 69, 4, 0, 0, // Skip to: 3047
/* 3043 */    MCD_OPC_Decode, 250, 3, 35, // Opcode: FSUBS
/* 3047 */    MCD_OPC_FilterValue, 70, 4, 0, 0, // Skip to: 3056
/* 3052 */    MCD_OPC_Decode, 248, 3, 36, // Opcode: FSUBD
/* 3056 */    MCD_OPC_FilterValue, 71, 4, 0, 0, // Skip to: 3065
/* 3061 */    MCD_OPC_Decode, 249, 3, 37, // Opcode: FSUBQ
/* 3065 */    MCD_OPC_FilterValue, 73, 4, 0, 0, // Skip to: 3074
/* 3070 */    MCD_OPC_Decode, 184, 3, 35, // Opcode: FMULS
/* 3074 */    MCD_OPC_FilterValue, 74, 4, 0, 0, // Skip to: 3083
/* 3079 */    MCD_OPC_Decode, 180, 3, 36, // Opcode: FMULD
/* 3083 */    MCD_OPC_FilterValue, 75, 4, 0, 0, // Skip to: 3092
/* 3088 */    MCD_OPC_Decode, 183, 3, 37, // Opcode: FMULQ
/* 3092 */    MCD_OPC_FilterValue, 77, 4, 0, 0, // Skip to: 3101
/* 3097 */    MCD_OPC_Decode, 252, 2, 35, // Opcode: FDIVS
/* 3101 */    MCD_OPC_FilterValue, 78, 4, 0, 0, // Skip to: 3110
/* 3106 */    MCD_OPC_Decode, 250, 2, 36, // Opcode: FDIVD
/* 3110 */    MCD_OPC_FilterValue, 79, 4, 0, 0, // Skip to: 3119
/* 3115 */    MCD_OPC_Decode, 251, 2, 37, // Opcode: FDIVQ
/* 3119 */    MCD_OPC_FilterValue, 81, 9, 0, 0, // Skip to: 3133
/* 3124 */    MCD_OPC_CheckPredicate, 2, 63, 19, 0, // Skip to: 8056
/* 3129 */    MCD_OPC_Decode, 186, 3, 36, // Opcode: FNADDS
/* 3133 */    MCD_OPC_FilterValue, 82, 9, 0, 0, // Skip to: 3147
/* 3138 */    MCD_OPC_CheckPredicate, 2, 49, 19, 0, // Skip to: 8056
/* 3143 */    MCD_OPC_Decode, 185, 3, 36, // Opcode: FNADDD
/* 3147 */    MCD_OPC_FilterValue, 89, 9, 0, 0, // Skip to: 3161
/* 3152 */    MCD_OPC_CheckPredicate, 2, 35, 19, 0, // Skip to: 8056
/* 3157 */    MCD_OPC_Decode, 195, 3, 36, // Opcode: FNMULS
/* 3161 */    MCD_OPC_FilterValue, 90, 9, 0, 0, // Skip to: 3175
/* 3166 */    MCD_OPC_CheckPredicate, 2, 21, 19, 0, // Skip to: 8056
/* 3171 */    MCD_OPC_Decode, 194, 3, 36, // Opcode: FNMULD
/* 3175 */    MCD_OPC_FilterValue, 97, 9, 0, 0, // Skip to: 3189
/* 3180 */    MCD_OPC_CheckPredicate, 2, 7, 19, 0, // Skip to: 8056
/* 3185 */    MCD_OPC_Decode, 132, 3, 36, // Opcode: FHADDS
/* 3189 */    MCD_OPC_FilterValue, 98, 9, 0, 0, // Skip to: 3203
/* 3194 */    MCD_OPC_CheckPredicate, 2, 249, 18, 0, // Skip to: 8056
/* 3199 */    MCD_OPC_Decode, 131, 3, 36, // Opcode: FHADDD
/* 3203 */    MCD_OPC_FilterValue, 101, 9, 0, 0, // Skip to: 3217
/* 3208 */    MCD_OPC_CheckPredicate, 2, 235, 18, 0, // Skip to: 8056
/* 3213 */    MCD_OPC_Decode, 134, 3, 36, // Opcode: FHSUBS
/* 3217 */    MCD_OPC_FilterValue, 102, 9, 0, 0, // Skip to: 3231
/* 3222 */    MCD_OPC_CheckPredicate, 2, 221, 18, 0, // Skip to: 8056
/* 3227 */    MCD_OPC_Decode, 133, 3, 36, // Opcode: FHSUBD
/* 3231 */    MCD_OPC_FilterValue, 105, 4, 0, 0, // Skip to: 3240
/* 3236 */    MCD_OPC_Decode, 232, 3, 38, // Opcode: FSMULD
/* 3240 */    MCD_OPC_FilterValue, 110, 4, 0, 0, // Skip to: 3249
/* 3245 */    MCD_OPC_Decode, 253, 2, 39, // Opcode: FDMULQ
/* 3249 */    MCD_OPC_FilterValue, 113, 9, 0, 0, // Skip to: 3263
/* 3254 */    MCD_OPC_CheckPredicate, 2, 189, 18, 0, // Skip to: 8056
/* 3259 */    MCD_OPC_Decode, 193, 3, 36, // Opcode: FNHADDS
/* 3263 */    MCD_OPC_FilterValue, 114, 9, 0, 0, // Skip to: 3277
/* 3268 */    MCD_OPC_CheckPredicate, 2, 175, 18, 0, // Skip to: 8056
/* 3273 */    MCD_OPC_Decode, 192, 3, 36, // Opcode: FNHADDD
/* 3277 */    MCD_OPC_FilterValue, 121, 9, 0, 0, // Skip to: 3291
/* 3282 */    MCD_OPC_CheckPredicate, 2, 161, 18, 0, // Skip to: 8056
/* 3287 */    MCD_OPC_Decode, 202, 3, 36, // Opcode: FNSMULD
/* 3291 */    MCD_OPC_FilterValue, 129, 1, 11, 0, 0, // Skip to: 3308
/* 3297 */    MCD_OPC_CheckField, 14, 5, 0, 144, 18, 0, // Skip to: 8056
/* 3304 */    MCD_OPC_Decode, 247, 3, 40, // Opcode: FSTOX
/* 3308 */    MCD_OPC_FilterValue, 130, 1, 11, 0, 0, // Skip to: 3325
/* 3314 */    MCD_OPC_CheckField, 14, 5, 0, 127, 18, 0, // Skip to: 8056
/* 3321 */    MCD_OPC_Decode, 129, 3, 33, // Opcode: FDTOX
/* 3325 */    MCD_OPC_FilterValue, 131, 1, 11, 0, 0, // Skip to: 3342
/* 3331 */    MCD_OPC_CheckField, 14, 5, 0, 110, 18, 0, // Skip to: 8056
/* 3338 */    MCD_OPC_Decode, 227, 3, 41, // Opcode: FQTOX
/* 3342 */    MCD_OPC_FilterValue, 132, 1, 11, 0, 0, // Skip to: 3359
/* 3348 */    MCD_OPC_CheckField, 14, 5, 0, 93, 18, 0, // Skip to: 8056
/* 3355 */    MCD_OPC_Decode, 129, 4, 42, // Opcode: FXTOS
/* 3359 */    MCD_OPC_FilterValue, 136, 1, 11, 0, 0, // Skip to: 3376
/* 3365 */    MCD_OPC_CheckField, 14, 5, 0, 76, 18, 0, // Skip to: 8056
/* 3372 */    MCD_OPC_Decode, 255, 3, 33, // Opcode: FXTOD
/* 3376 */    MCD_OPC_FilterValue, 140, 1, 11, 0, 0, // Skip to: 3393
/* 3382 */    MCD_OPC_CheckField, 14, 5, 0, 59, 18, 0, // Skip to: 8056
/* 3389 */    MCD_OPC_Decode, 128, 4, 43, // Opcode: FXTOQ
/* 3393 */    MCD_OPC_FilterValue, 196, 1, 11, 0, 0, // Skip to: 3410
/* 3399 */    MCD_OPC_CheckField, 14, 5, 0, 42, 18, 0, // Skip to: 8056
/* 3406 */    MCD_OPC_Decode, 137, 3, 32, // Opcode: FITOS
/* 3410 */    MCD_OPC_FilterValue, 198, 1, 11, 0, 0, // Skip to: 3427
/* 3416 */    MCD_OPC_CheckField, 14, 5, 0, 25, 18, 0, // Skip to: 8056
/* 3423 */    MCD_OPC_Decode, 128, 3, 42, // Opcode: FDTOS
/* 3427 */    MCD_OPC_FilterValue, 199, 1, 11, 0, 0, // Skip to: 3444
/* 3433 */    MCD_OPC_CheckField, 14, 5, 0, 8, 18, 0, // Skip to: 8056
/* 3440 */    MCD_OPC_Decode, 226, 3, 44, // Opcode: FQTOS
/* 3444 */    MCD_OPC_FilterValue, 200, 1, 11, 0, 0, // Skip to: 3461
/* 3450 */    MCD_OPC_CheckField, 14, 5, 0, 247, 17, 0, // Skip to: 8056
/* 3457 */    MCD_OPC_Decode, 135, 3, 40, // Opcode: FITOD
/* 3461 */    MCD_OPC_FilterValue, 201, 1, 11, 0, 0, // Skip to: 3478
/* 3467 */    MCD_OPC_CheckField, 14, 5, 0, 230, 17, 0, // Skip to: 8056
/* 3474 */    MCD_OPC_Decode, 244, 3, 40, // Opcode: FSTOD
/* 3478 */    MCD_OPC_FilterValue, 203, 1, 11, 0, 0, // Skip to: 3495
/* 3484 */    MCD_OPC_CheckField, 14, 5, 0, 213, 17, 0, // Skip to: 8056
/* 3491 */    MCD_OPC_Decode, 224, 3, 41, // Opcode: FQTOD
/* 3495 */    MCD_OPC_FilterValue, 204, 1, 11, 0, 0, // Skip to: 3512
/* 3501 */    MCD_OPC_CheckField, 14, 5, 0, 196, 17, 0, // Skip to: 8056
/* 3508 */    MCD_OPC_Decode, 136, 3, 45, // Opcode: FITOQ
/* 3512 */    MCD_OPC_FilterValue, 205, 1, 11, 0, 0, // Skip to: 3529
/* 3518 */    MCD_OPC_CheckField, 14, 5, 0, 179, 17, 0, // Skip to: 8056
/* 3525 */    MCD_OPC_Decode, 246, 3, 45, // Opcode: FSTOQ
/* 3529 */    MCD_OPC_FilterValue, 206, 1, 11, 0, 0, // Skip to: 3546
/* 3535 */    MCD_OPC_CheckField, 14, 5, 0, 162, 17, 0, // Skip to: 8056
/* 3542 */    MCD_OPC_Decode, 255, 2, 43, // Opcode: FDTOQ
/* 3546 */    MCD_OPC_FilterValue, 209, 1, 11, 0, 0, // Skip to: 3563
/* 3552 */    MCD_OPC_CheckField, 14, 5, 0, 145, 17, 0, // Skip to: 8056
/* 3559 */    MCD_OPC_Decode, 245, 3, 32, // Opcode: FSTOI
/* 3563 */    MCD_OPC_FilterValue, 210, 1, 11, 0, 0, // Skip to: 3580
/* 3569 */    MCD_OPC_CheckField, 14, 5, 0, 128, 17, 0, // Skip to: 8056
/* 3576 */    MCD_OPC_Decode, 254, 2, 42, // Opcode: FDTOI
/* 3580 */    MCD_OPC_FilterValue, 211, 1, 118, 17, 0, // Skip to: 8056
/* 3586 */    MCD_OPC_CheckField, 14, 5, 0, 111, 17, 0, // Skip to: 8056
/* 3593 */    MCD_OPC_Decode, 225, 3, 44, // Opcode: FQTOI
/* 3597 */    MCD_OPC_FilterValue, 53, 160, 2, 0, // Skip to: 4274
/* 3602 */    MCD_OPC_ExtractField, 5, 6,  // Inst{10-5} ...
/* 3605 */    MCD_OPC_FilterValue, 1, 86, 0, 0, // Skip to: 3696
/* 3610 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 3613 */    MCD_OPC_FilterValue, 0, 33, 0, 0, // Skip to: 3651
/* 3618 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 3621 */    MCD_OPC_FilterValue, 0, 78, 17, 0, // Skip to: 8056
/* 3626 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 3642
/* 3631 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 3642
/* 3638 */    MCD_OPC_Decode, 172, 3, 46, // Opcode: FMOVS_FCC
/* 3642 */    MCD_OPC_CheckPredicate, 0, 57, 17, 0, // Skip to: 8056
/* 3647 */    MCD_OPC_Decode, 238, 5, 47, // Opcode: V9FMOVS_FCC
/* 3651 */    MCD_OPC_FilterValue, 1, 48, 17, 0, // Skip to: 8056
/* 3656 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 3659 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 3680
/* 3664 */    MCD_OPC_CheckPredicate, 0, 35, 17, 0, // Skip to: 8056
/* 3669 */    MCD_OPC_CheckField, 18, 1, 0, 28, 17, 0, // Skip to: 8056
/* 3676 */    MCD_OPC_Decode, 173, 3, 46, // Opcode: FMOVS_ICC
/* 3680 */    MCD_OPC_FilterValue, 2, 19, 17, 0, // Skip to: 8056
/* 3685 */    MCD_OPC_CheckField, 18, 1, 0, 12, 17, 0, // Skip to: 8056
/* 3692 */    MCD_OPC_Decode, 174, 3, 46, // Opcode: FMOVS_XCC
/* 3696 */    MCD_OPC_FilterValue, 2, 86, 0, 0, // Skip to: 3787
/* 3701 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 3704 */    MCD_OPC_FilterValue, 0, 33, 0, 0, // Skip to: 3742
/* 3709 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 3712 */    MCD_OPC_FilterValue, 0, 243, 16, 0, // Skip to: 8056
/* 3717 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 3733
/* 3722 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 3733
/* 3729 */    MCD_OPC_Decode, 146, 3, 48, // Opcode: FMOVD_FCC
/* 3733 */    MCD_OPC_CheckPredicate, 0, 222, 16, 0, // Skip to: 8056
/* 3738 */    MCD_OPC_Decode, 236, 5, 49, // Opcode: V9FMOVD_FCC
/* 3742 */    MCD_OPC_FilterValue, 1, 213, 16, 0, // Skip to: 8056
/* 3747 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 3750 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 3771
/* 3755 */    MCD_OPC_CheckPredicate, 0, 200, 16, 0, // Skip to: 8056
/* 3760 */    MCD_OPC_CheckField, 18, 1, 0, 193, 16, 0, // Skip to: 8056
/* 3767 */    MCD_OPC_Decode, 147, 3, 48, // Opcode: FMOVD_ICC
/* 3771 */    MCD_OPC_FilterValue, 2, 184, 16, 0, // Skip to: 8056
/* 3776 */    MCD_OPC_CheckField, 18, 1, 0, 177, 16, 0, // Skip to: 8056
/* 3783 */    MCD_OPC_Decode, 148, 3, 48, // Opcode: FMOVD_XCC
/* 3787 */    MCD_OPC_FilterValue, 3, 86, 0, 0, // Skip to: 3878
/* 3792 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 3795 */    MCD_OPC_FilterValue, 0, 33, 0, 0, // Skip to: 3833
/* 3800 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 3803 */    MCD_OPC_FilterValue, 0, 152, 16, 0, // Skip to: 8056
/* 3808 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 3824
/* 3813 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 3824
/* 3820 */    MCD_OPC_Decode, 150, 3, 50, // Opcode: FMOVQ_FCC
/* 3824 */    MCD_OPC_CheckPredicate, 0, 131, 16, 0, // Skip to: 8056
/* 3829 */    MCD_OPC_Decode, 237, 5, 51, // Opcode: V9FMOVQ_FCC
/* 3833 */    MCD_OPC_FilterValue, 1, 122, 16, 0, // Skip to: 8056
/* 3838 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 3841 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 3862
/* 3846 */    MCD_OPC_CheckPredicate, 0, 109, 16, 0, // Skip to: 8056
/* 3851 */    MCD_OPC_CheckField, 18, 1, 0, 102, 16, 0, // Skip to: 8056
/* 3858 */    MCD_OPC_Decode, 151, 3, 50, // Opcode: FMOVQ_ICC
/* 3862 */    MCD_OPC_FilterValue, 2, 93, 16, 0, // Skip to: 8056
/* 3867 */    MCD_OPC_CheckField, 18, 1, 0, 86, 16, 0, // Skip to: 8056
/* 3874 */    MCD_OPC_Decode, 152, 3, 50, // Opcode: FMOVQ_XCC
/* 3878 */    MCD_OPC_FilterValue, 5, 31, 0, 0, // Skip to: 3914
/* 3883 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 3886 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 3900
/* 3891 */    MCD_OPC_CheckPredicate, 0, 64, 16, 0, // Skip to: 8056
/* 3896 */    MCD_OPC_Decode, 161, 3, 52, // Opcode: FMOVRLEZS
/* 3900 */    MCD_OPC_FilterValue, 3, 55, 16, 0, // Skip to: 8056
/* 3905 */    MCD_OPC_CheckPredicate, 0, 50, 16, 0, // Skip to: 8056
/* 3910 */    MCD_OPC_Decode, 158, 3, 52, // Opcode: FMOVRGZS
/* 3914 */    MCD_OPC_FilterValue, 6, 31, 0, 0, // Skip to: 3950
/* 3919 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 3922 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 3936
/* 3927 */    MCD_OPC_CheckPredicate, 0, 28, 16, 0, // Skip to: 8056
/* 3932 */    MCD_OPC_Decode, 159, 3, 52, // Opcode: FMOVRLEZD
/* 3936 */    MCD_OPC_FilterValue, 3, 19, 16, 0, // Skip to: 8056
/* 3941 */    MCD_OPC_CheckPredicate, 0, 14, 16, 0, // Skip to: 8056
/* 3946 */    MCD_OPC_Decode, 156, 3, 52, // Opcode: FMOVRGZD
/* 3950 */    MCD_OPC_FilterValue, 7, 31, 0, 0, // Skip to: 3986
/* 3955 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 3958 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 3972
/* 3963 */    MCD_OPC_CheckPredicate, 0, 248, 15, 0, // Skip to: 8056
/* 3968 */    MCD_OPC_Decode, 160, 3, 52, // Opcode: FMOVRLEZQ
/* 3972 */    MCD_OPC_FilterValue, 3, 239, 15, 0, // Skip to: 8056
/* 3977 */    MCD_OPC_CheckPredicate, 0, 234, 15, 0, // Skip to: 8056
/* 3982 */    MCD_OPC_Decode, 157, 3, 52, // Opcode: FMOVRGZQ
/* 3986 */    MCD_OPC_FilterValue, 17, 11, 0, 0, // Skip to: 4002
/* 3991 */    MCD_OPC_CheckField, 11, 3, 1, 218, 15, 0, // Skip to: 8056
/* 3998 */    MCD_OPC_Decode, 235, 5, 53, // Opcode: V9FCMPS
/* 4002 */    MCD_OPC_FilterValue, 18, 11, 0, 0, // Skip to: 4018
/* 4007 */    MCD_OPC_CheckField, 11, 3, 1, 202, 15, 0, // Skip to: 8056
/* 4014 */    MCD_OPC_Decode, 230, 5, 54, // Opcode: V9FCMPD
/* 4018 */    MCD_OPC_FilterValue, 19, 11, 0, 0, // Skip to: 4034
/* 4023 */    MCD_OPC_CheckField, 11, 3, 1, 186, 15, 0, // Skip to: 8056
/* 4030 */    MCD_OPC_Decode, 234, 5, 55, // Opcode: V9FCMPQ
/* 4034 */    MCD_OPC_FilterValue, 21, 11, 0, 0, // Skip to: 4050
/* 4039 */    MCD_OPC_CheckField, 11, 3, 1, 170, 15, 0, // Skip to: 8056
/* 4046 */    MCD_OPC_Decode, 233, 5, 53, // Opcode: V9FCMPES
/* 4050 */    MCD_OPC_FilterValue, 22, 11, 0, 0, // Skip to: 4066
/* 4055 */    MCD_OPC_CheckField, 11, 3, 1, 154, 15, 0, // Skip to: 8056
/* 4062 */    MCD_OPC_Decode, 231, 5, 54, // Opcode: V9FCMPED
/* 4066 */    MCD_OPC_FilterValue, 23, 11, 0, 0, // Skip to: 4082
/* 4071 */    MCD_OPC_CheckField, 11, 3, 1, 138, 15, 0, // Skip to: 8056
/* 4078 */    MCD_OPC_Decode, 232, 5, 55, // Opcode: V9FCMPEQ
/* 4082 */    MCD_OPC_FilterValue, 37, 59, 0, 0, // Skip to: 4146
/* 4087 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 4090 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 4104
/* 4095 */    MCD_OPC_CheckPredicate, 0, 116, 15, 0, // Skip to: 8056
/* 4100 */    MCD_OPC_Decode, 170, 3, 52, // Opcode: FMOVRZS
/* 4104 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 4118
/* 4109 */    MCD_OPC_CheckPredicate, 0, 102, 15, 0, // Skip to: 8056
/* 4114 */    MCD_OPC_Decode, 164, 3, 52, // Opcode: FMOVRLZS
/* 4118 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 4132
/* 4123 */    MCD_OPC_CheckPredicate, 0, 88, 15, 0, // Skip to: 8056
/* 4128 */    MCD_OPC_Decode, 167, 3, 52, // Opcode: FMOVRNZS
/* 4132 */    MCD_OPC_FilterValue, 3, 79, 15, 0, // Skip to: 8056
/* 4137 */    MCD_OPC_CheckPredicate, 0, 74, 15, 0, // Skip to: 8056
/* 4142 */    MCD_OPC_Decode, 155, 3, 52, // Opcode: FMOVRGEZS
/* 4146 */    MCD_OPC_FilterValue, 38, 59, 0, 0, // Skip to: 4210
/* 4151 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 4154 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 4168
/* 4159 */    MCD_OPC_CheckPredicate, 0, 52, 15, 0, // Skip to: 8056
/* 4164 */    MCD_OPC_Decode, 168, 3, 52, // Opcode: FMOVRZD
/* 4168 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 4182
/* 4173 */    MCD_OPC_CheckPredicate, 0, 38, 15, 0, // Skip to: 8056
/* 4178 */    MCD_OPC_Decode, 162, 3, 52, // Opcode: FMOVRLZD
/* 4182 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 4196
/* 4187 */    MCD_OPC_CheckPredicate, 0, 24, 15, 0, // Skip to: 8056
/* 4192 */    MCD_OPC_Decode, 165, 3, 52, // Opcode: FMOVRNZD
/* 4196 */    MCD_OPC_FilterValue, 3, 15, 15, 0, // Skip to: 8056
/* 4201 */    MCD_OPC_CheckPredicate, 0, 10, 15, 0, // Skip to: 8056
/* 4206 */    MCD_OPC_Decode, 153, 3, 52, // Opcode: FMOVRGEZD
/* 4210 */    MCD_OPC_FilterValue, 39, 1, 15, 0, // Skip to: 8056
/* 4215 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 4218 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 4232
/* 4223 */    MCD_OPC_CheckPredicate, 0, 244, 14, 0, // Skip to: 8056
/* 4228 */    MCD_OPC_Decode, 169, 3, 52, // Opcode: FMOVRZQ
/* 4232 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 4246
/* 4237 */    MCD_OPC_CheckPredicate, 0, 230, 14, 0, // Skip to: 8056
/* 4242 */    MCD_OPC_Decode, 163, 3, 52, // Opcode: FMOVRLZQ
/* 4246 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 4260
/* 4251 */    MCD_OPC_CheckPredicate, 0, 216, 14, 0, // Skip to: 8056
/* 4256 */    MCD_OPC_Decode, 166, 3, 52, // Opcode: FMOVRNZQ
/* 4260 */    MCD_OPC_FilterValue, 3, 207, 14, 0, // Skip to: 8056
/* 4265 */    MCD_OPC_CheckPredicate, 0, 202, 14, 0, // Skip to: 8056
/* 4270 */    MCD_OPC_Decode, 154, 3, 52, // Opcode: FMOVRGEZQ
/* 4274 */    MCD_OPC_FilterValue, 54, 35, 7, 0, // Skip to: 6106
/* 4279 */    MCD_OPC_ExtractField, 5, 9,  // Inst{13-5} ...
/* 4282 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 4296
/* 4287 */    MCD_OPC_CheckPredicate, 3, 180, 14, 0, // Skip to: 8056
/* 4292 */    MCD_OPC_Decode, 219, 2, 10, // Opcode: EDGE8
/* 4296 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 4310
/* 4301 */    MCD_OPC_CheckPredicate, 4, 166, 14, 0, // Skip to: 8056
/* 4306 */    MCD_OPC_Decode, 222, 2, 10, // Opcode: EDGE8N
/* 4310 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 4324
/* 4315 */    MCD_OPC_CheckPredicate, 3, 152, 14, 0, // Skip to: 8056
/* 4320 */    MCD_OPC_Decode, 220, 2, 10, // Opcode: EDGE8L
/* 4324 */    MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 4338
/* 4329 */    MCD_OPC_CheckPredicate, 4, 138, 14, 0, // Skip to: 8056
/* 4334 */    MCD_OPC_Decode, 221, 2, 10, // Opcode: EDGE8LN
/* 4338 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 4352
/* 4343 */    MCD_OPC_CheckPredicate, 3, 124, 14, 0, // Skip to: 8056
/* 4348 */    MCD_OPC_Decode, 211, 2, 10, // Opcode: EDGE16
/* 4352 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 4366
/* 4357 */    MCD_OPC_CheckPredicate, 4, 110, 14, 0, // Skip to: 8056
/* 4362 */    MCD_OPC_Decode, 214, 2, 10, // Opcode: EDGE16N
/* 4366 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 4380
/* 4371 */    MCD_OPC_CheckPredicate, 3, 96, 14, 0, // Skip to: 8056
/* 4376 */    MCD_OPC_Decode, 212, 2, 10, // Opcode: EDGE16L
/* 4380 */    MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 4394
/* 4385 */    MCD_OPC_CheckPredicate, 4, 82, 14, 0, // Skip to: 8056
/* 4390 */    MCD_OPC_Decode, 213, 2, 10, // Opcode: EDGE16LN
/* 4394 */    MCD_OPC_FilterValue, 8, 9, 0, 0, // Skip to: 4408
/* 4399 */    MCD_OPC_CheckPredicate, 3, 68, 14, 0, // Skip to: 8056
/* 4404 */    MCD_OPC_Decode, 215, 2, 10, // Opcode: EDGE32
/* 4408 */    MCD_OPC_FilterValue, 9, 9, 0, 0, // Skip to: 4422
/* 4413 */    MCD_OPC_CheckPredicate, 4, 54, 14, 0, // Skip to: 8056
/* 4418 */    MCD_OPC_Decode, 218, 2, 10, // Opcode: EDGE32N
/* 4422 */    MCD_OPC_FilterValue, 10, 9, 0, 0, // Skip to: 4436
/* 4427 */    MCD_OPC_CheckPredicate, 3, 40, 14, 0, // Skip to: 8056
/* 4432 */    MCD_OPC_Decode, 216, 2, 10, // Opcode: EDGE32L
/* 4436 */    MCD_OPC_FilterValue, 11, 9, 0, 0, // Skip to: 4450
/* 4441 */    MCD_OPC_CheckPredicate, 4, 26, 14, 0, // Skip to: 8056
/* 4446 */    MCD_OPC_Decode, 217, 2, 10, // Opcode: EDGE32LN
/* 4450 */    MCD_OPC_FilterValue, 16, 9, 0, 0, // Skip to: 4464
/* 4455 */    MCD_OPC_CheckPredicate, 3, 12, 14, 0, // Skip to: 8056
/* 4460 */    MCD_OPC_Decode, 153, 2, 10, // Opcode: ARRAY8
/* 4464 */    MCD_OPC_FilterValue, 17, 9, 0, 0, // Skip to: 4478
/* 4469 */    MCD_OPC_CheckPredicate, 2, 254, 13, 0, // Skip to: 8056
/* 4474 */    MCD_OPC_Decode, 132, 2, 10, // Opcode: ADDXC
/* 4478 */    MCD_OPC_FilterValue, 18, 9, 0, 0, // Skip to: 4492
/* 4483 */    MCD_OPC_CheckPredicate, 3, 240, 13, 0, // Skip to: 8056
/* 4488 */    MCD_OPC_Decode, 151, 2, 10, // Opcode: ARRAY16
/* 4492 */    MCD_OPC_FilterValue, 19, 9, 0, 0, // Skip to: 4506
/* 4497 */    MCD_OPC_CheckPredicate, 2, 226, 13, 0, // Skip to: 8056
/* 4502 */    MCD_OPC_Decode, 133, 2, 10, // Opcode: ADDXCCC
/* 4506 */    MCD_OPC_FilterValue, 20, 9, 0, 0, // Skip to: 4520
/* 4511 */    MCD_OPC_CheckPredicate, 3, 212, 13, 0, // Skip to: 8056
/* 4516 */    MCD_OPC_Decode, 152, 2, 10, // Opcode: ARRAY32
/* 4520 */    MCD_OPC_FilterValue, 22, 9, 0, 0, // Skip to: 4534
/* 4525 */    MCD_OPC_CheckPredicate, 2, 198, 13, 0, // Skip to: 8056
/* 4530 */    MCD_OPC_Decode, 226, 5, 10, // Opcode: UMULXHI
/* 4534 */    MCD_OPC_FilterValue, 23, 16, 0, 0, // Skip to: 4555
/* 4539 */    MCD_OPC_CheckPredicate, 2, 184, 13, 0, // Skip to: 8056
/* 4544 */    MCD_OPC_CheckField, 14, 5, 0, 177, 13, 0, // Skip to: 8056
/* 4551 */    MCD_OPC_Decode, 180, 4, 56, // Opcode: LZCNT
/* 4555 */    MCD_OPC_FilterValue, 24, 9, 0, 0, // Skip to: 4569
/* 4560 */    MCD_OPC_CheckPredicate, 3, 163, 13, 0, // Skip to: 8056
/* 4565 */    MCD_OPC_Decode, 138, 2, 10, // Opcode: ALIGNADDR
/* 4569 */    MCD_OPC_FilterValue, 25, 9, 0, 0, // Skip to: 4583
/* 4574 */    MCD_OPC_CheckPredicate, 4, 149, 13, 0, // Skip to: 8056
/* 4579 */    MCD_OPC_Decode, 159, 2, 10, // Opcode: BMASK
/* 4583 */    MCD_OPC_FilterValue, 26, 9, 0, 0, // Skip to: 4597
/* 4588 */    MCD_OPC_CheckPredicate, 3, 135, 13, 0, // Skip to: 8056
/* 4593 */    MCD_OPC_Decode, 139, 2, 10, // Opcode: ALIGNADDRL
/* 4597 */    MCD_OPC_FilterValue, 27, 23, 0, 0, // Skip to: 4625
/* 4602 */    MCD_OPC_CheckPredicate, 2, 121, 13, 0, // Skip to: 8056
/* 4607 */    MCD_OPC_CheckField, 25, 5, 0, 114, 13, 0, // Skip to: 8056
/* 4614 */    MCD_OPC_CheckField, 14, 5, 0, 107, 13, 0, // Skip to: 8056
/* 4621 */    MCD_OPC_Decode, 208, 2, 57, // Opcode: CMASK8
/* 4625 */    MCD_OPC_FilterValue, 28, 9, 0, 0, // Skip to: 4639
/* 4630 */    MCD_OPC_CheckPredicate, 4, 93, 13, 0, // Skip to: 8056
/* 4635 */    MCD_OPC_Decode, 196, 2, 36, // Opcode: BSHUFFLE
/* 4639 */    MCD_OPC_FilterValue, 29, 23, 0, 0, // Skip to: 4667
/* 4644 */    MCD_OPC_CheckPredicate, 2, 79, 13, 0, // Skip to: 8056
/* 4649 */    MCD_OPC_CheckField, 25, 5, 0, 72, 13, 0, // Skip to: 8056
/* 4656 */    MCD_OPC_CheckField, 14, 5, 0, 65, 13, 0, // Skip to: 8056
/* 4663 */    MCD_OPC_Decode, 206, 2, 57, // Opcode: CMASK16
/* 4667 */    MCD_OPC_FilterValue, 31, 23, 0, 0, // Skip to: 4695
/* 4672 */    MCD_OPC_CheckPredicate, 2, 51, 13, 0, // Skip to: 8056
/* 4677 */    MCD_OPC_CheckField, 25, 5, 0, 44, 13, 0, // Skip to: 8056
/* 4684 */    MCD_OPC_CheckField, 14, 5, 0, 37, 13, 0, // Skip to: 8056
/* 4691 */    MCD_OPC_Decode, 207, 2, 57, // Opcode: CMASK32
/* 4695 */    MCD_OPC_FilterValue, 32, 9, 0, 0, // Skip to: 4709
/* 4700 */    MCD_OPC_CheckPredicate, 3, 23, 13, 0, // Skip to: 8056
/* 4705 */    MCD_OPC_Decode, 244, 2, 58, // Opcode: FCMPLE16
/* 4709 */    MCD_OPC_FilterValue, 33, 9, 0, 0, // Skip to: 4723
/* 4714 */    MCD_OPC_CheckPredicate, 2, 9, 13, 0, // Skip to: 8056
/* 4719 */    MCD_OPC_Decode, 230, 3, 36, // Opcode: FSLL16
/* 4723 */    MCD_OPC_FilterValue, 34, 9, 0, 0, // Skip to: 4737
/* 4728 */    MCD_OPC_CheckPredicate, 3, 251, 12, 0, // Skip to: 8056
/* 4733 */    MCD_OPC_Decode, 246, 2, 58, // Opcode: FCMPNE16
/* 4737 */    MCD_OPC_FilterValue, 35, 9, 0, 0, // Skip to: 4751
/* 4742 */    MCD_OPC_CheckPredicate, 2, 237, 12, 0, // Skip to: 8056
/* 4747 */    MCD_OPC_Decode, 242, 3, 36, // Opcode: FSRL16
/* 4751 */    MCD_OPC_FilterValue, 36, 9, 0, 0, // Skip to: 4765
/* 4756 */    MCD_OPC_CheckPredicate, 3, 223, 12, 0, // Skip to: 8056
/* 4761 */    MCD_OPC_Decode, 245, 2, 58, // Opcode: FCMPLE32
/* 4765 */    MCD_OPC_FilterValue, 37, 9, 0, 0, // Skip to: 4779
/* 4770 */    MCD_OPC_CheckPredicate, 2, 209, 12, 0, // Skip to: 8056
/* 4775 */    MCD_OPC_Decode, 231, 3, 36, // Opcode: FSLL32
/* 4779 */    MCD_OPC_FilterValue, 38, 9, 0, 0, // Skip to: 4793
/* 4784 */    MCD_OPC_CheckPredicate, 3, 195, 12, 0, // Skip to: 8056
/* 4789 */    MCD_OPC_Decode, 247, 2, 58, // Opcode: FCMPNE32
/* 4793 */    MCD_OPC_FilterValue, 39, 9, 0, 0, // Skip to: 4807
/* 4798 */    MCD_OPC_CheckPredicate, 2, 181, 12, 0, // Skip to: 8056
/* 4803 */    MCD_OPC_Decode, 243, 3, 36, // Opcode: FSRL32
/* 4807 */    MCD_OPC_FilterValue, 40, 9, 0, 0, // Skip to: 4821
/* 4812 */    MCD_OPC_CheckPredicate, 3, 167, 12, 0, // Skip to: 8056
/* 4817 */    MCD_OPC_Decode, 242, 2, 58, // Opcode: FCMPGT16
/* 4821 */    MCD_OPC_FilterValue, 41, 9, 0, 0, // Skip to: 4835
/* 4826 */    MCD_OPC_CheckPredicate, 2, 153, 12, 0, // Skip to: 8056
/* 4831 */    MCD_OPC_Decode, 228, 3, 36, // Opcode: FSLAS16
/* 4835 */    MCD_OPC_FilterValue, 42, 9, 0, 0, // Skip to: 4849
/* 4840 */    MCD_OPC_CheckPredicate, 3, 139, 12, 0, // Skip to: 8056
/* 4845 */    MCD_OPC_Decode, 240, 2, 58, // Opcode: FCMPEQ16
/* 4849 */    MCD_OPC_FilterValue, 43, 9, 0, 0, // Skip to: 4863
/* 4854 */    MCD_OPC_CheckPredicate, 2, 125, 12, 0, // Skip to: 8056
/* 4859 */    MCD_OPC_Decode, 236, 3, 36, // Opcode: FSRA16
/* 4863 */    MCD_OPC_FilterValue, 44, 9, 0, 0, // Skip to: 4877
/* 4868 */    MCD_OPC_CheckPredicate, 3, 111, 12, 0, // Skip to: 8056
/* 4873 */    MCD_OPC_Decode, 243, 2, 58, // Opcode: FCMPGT32
/* 4877 */    MCD_OPC_FilterValue, 45, 9, 0, 0, // Skip to: 4891
/* 4882 */    MCD_OPC_CheckPredicate, 2, 97, 12, 0, // Skip to: 8056
/* 4887 */    MCD_OPC_Decode, 229, 3, 36, // Opcode: FSLAS32
/* 4891 */    MCD_OPC_FilterValue, 46, 9, 0, 0, // Skip to: 4905
/* 4896 */    MCD_OPC_CheckPredicate, 3, 83, 12, 0, // Skip to: 8056
/* 4901 */    MCD_OPC_Decode, 241, 2, 58, // Opcode: FCMPEQ32
/* 4905 */    MCD_OPC_FilterValue, 47, 9, 0, 0, // Skip to: 4919
/* 4910 */    MCD_OPC_CheckPredicate, 2, 69, 12, 0, // Skip to: 8056
/* 4915 */    MCD_OPC_Decode, 237, 3, 36, // Opcode: FSRA32
/* 4919 */    MCD_OPC_FilterValue, 49, 9, 0, 0, // Skip to: 4933
/* 4924 */    MCD_OPC_CheckPredicate, 3, 55, 12, 0, // Skip to: 8056
/* 4929 */    MCD_OPC_Decode, 177, 3, 36, // Opcode: FMUL8X16
/* 4933 */    MCD_OPC_FilterValue, 51, 9, 0, 0, // Skip to: 4947
/* 4938 */    MCD_OPC_CheckPredicate, 3, 41, 12, 0, // Skip to: 8056
/* 4943 */    MCD_OPC_Decode, 179, 3, 36, // Opcode: FMUL8X16AU
/* 4947 */    MCD_OPC_FilterValue, 53, 9, 0, 0, // Skip to: 4961
/* 4952 */    MCD_OPC_CheckPredicate, 3, 27, 12, 0, // Skip to: 8056
/* 4957 */    MCD_OPC_Decode, 178, 3, 36, // Opcode: FMUL8X16AL
/* 4961 */    MCD_OPC_FilterValue, 54, 9, 0, 0, // Skip to: 4975
/* 4966 */    MCD_OPC_CheckPredicate, 3, 13, 12, 0, // Skip to: 8056
/* 4971 */    MCD_OPC_Decode, 175, 3, 36, // Opcode: FMUL8SUX16
/* 4975 */    MCD_OPC_FilterValue, 55, 9, 0, 0, // Skip to: 4989
/* 4980 */    MCD_OPC_CheckPredicate, 3, 255, 11, 0, // Skip to: 8056
/* 4985 */    MCD_OPC_Decode, 176, 3, 36, // Opcode: FMUL8ULX16
/* 4989 */    MCD_OPC_FilterValue, 56, 9, 0, 0, // Skip to: 5003
/* 4994 */    MCD_OPC_CheckPredicate, 3, 241, 11, 0, // Skip to: 8056
/* 4999 */    MCD_OPC_Decode, 181, 3, 36, // Opcode: FMULD8SUX16
/* 5003 */    MCD_OPC_FilterValue, 57, 9, 0, 0, // Skip to: 5017
/* 5008 */    MCD_OPC_CheckPredicate, 3, 227, 11, 0, // Skip to: 8056
/* 5013 */    MCD_OPC_Decode, 182, 3, 36, // Opcode: FMULD8ULX16
/* 5017 */    MCD_OPC_FilterValue, 58, 9, 0, 0, // Skip to: 5031
/* 5022 */    MCD_OPC_CheckPredicate, 3, 213, 11, 0, // Skip to: 8056
/* 5027 */    MCD_OPC_Decode, 212, 3, 36, // Opcode: FPACK32
/* 5031 */    MCD_OPC_FilterValue, 59, 16, 0, 0, // Skip to: 5052
/* 5036 */    MCD_OPC_CheckPredicate, 3, 199, 11, 0, // Skip to: 8056
/* 5041 */    MCD_OPC_CheckField, 14, 5, 0, 192, 11, 0, // Skip to: 8056
/* 5048 */    MCD_OPC_Decode, 211, 3, 33, // Opcode: FPACK16
/* 5052 */    MCD_OPC_FilterValue, 61, 16, 0, 0, // Skip to: 5073
/* 5057 */    MCD_OPC_CheckPredicate, 3, 178, 11, 0, // Skip to: 8056
/* 5062 */    MCD_OPC_CheckField, 14, 5, 0, 171, 11, 0, // Skip to: 8056
/* 5069 */    MCD_OPC_Decode, 213, 3, 33, // Opcode: FPACKFIX
/* 5073 */    MCD_OPC_FilterValue, 62, 9, 0, 0, // Skip to: 5087
/* 5078 */    MCD_OPC_CheckPredicate, 3, 157, 11, 0, // Skip to: 8056
/* 5083 */    MCD_OPC_Decode, 221, 4, 36, // Opcode: PDIST
/* 5087 */    MCD_OPC_FilterValue, 63, 9, 0, 0, // Skip to: 5101
/* 5092 */    MCD_OPC_CheckPredicate, 2, 143, 11, 0, // Skip to: 8056
/* 5097 */    MCD_OPC_Decode, 222, 4, 36, // Opcode: PDISTN
/* 5101 */    MCD_OPC_FilterValue, 64, 9, 0, 0, // Skip to: 5115
/* 5106 */    MCD_OPC_CheckPredicate, 2, 129, 11, 0, // Skip to: 8056
/* 5111 */    MCD_OPC_Decode, 144, 3, 36, // Opcode: FMEAN16
/* 5115 */    MCD_OPC_FilterValue, 66, 9, 0, 0, // Skip to: 5129
/* 5120 */    MCD_OPC_CheckPredicate, 2, 115, 11, 0, // Skip to: 8056
/* 5125 */    MCD_OPC_Decode, 218, 3, 36, // Opcode: FPADD64
/* 5129 */    MCD_OPC_FilterValue, 68, 9, 0, 0, // Skip to: 5143
/* 5134 */    MCD_OPC_CheckPredicate, 2, 101, 11, 0, // Skip to: 8056
/* 5139 */    MCD_OPC_Decode, 238, 2, 36, // Opcode: FCHKSM16
/* 5143 */    MCD_OPC_FilterValue, 72, 9, 0, 0, // Skip to: 5157
/* 5148 */    MCD_OPC_CheckPredicate, 3, 87, 11, 0, // Skip to: 8056
/* 5153 */    MCD_OPC_Decode, 229, 2, 36, // Opcode: FALIGNADATA
/* 5157 */    MCD_OPC_FilterValue, 75, 9, 0, 0, // Skip to: 5171
/* 5162 */    MCD_OPC_CheckPredicate, 3, 73, 11, 0, // Skip to: 8056
/* 5167 */    MCD_OPC_Decode, 219, 3, 36, // Opcode: FPMERGE
/* 5171 */    MCD_OPC_FilterValue, 77, 16, 0, 0, // Skip to: 5192
/* 5176 */    MCD_OPC_CheckPredicate, 3, 59, 11, 0, // Skip to: 8056
/* 5181 */    MCD_OPC_CheckField, 14, 5, 0, 52, 11, 0, // Skip to: 8056
/* 5188 */    MCD_OPC_Decode, 130, 3, 33, // Opcode: FEXPAND
/* 5192 */    MCD_OPC_FilterValue, 80, 9, 0, 0, // Skip to: 5206
/* 5197 */    MCD_OPC_CheckPredicate, 3, 38, 11, 0, // Skip to: 8056
/* 5202 */    MCD_OPC_Decode, 214, 3, 36, // Opcode: FPADD16
/* 5206 */    MCD_OPC_FilterValue, 81, 9, 0, 0, // Skip to: 5220
/* 5211 */    MCD_OPC_CheckPredicate, 3, 24, 11, 0, // Skip to: 8056
/* 5216 */    MCD_OPC_Decode, 215, 3, 36, // Opcode: FPADD16S
/* 5220 */    MCD_OPC_FilterValue, 82, 9, 0, 0, // Skip to: 5234
/* 5225 */    MCD_OPC_CheckPredicate, 3, 10, 11, 0, // Skip to: 8056
/* 5230 */    MCD_OPC_Decode, 216, 3, 36, // Opcode: FPADD32
/* 5234 */    MCD_OPC_FilterValue, 83, 9, 0, 0, // Skip to: 5248
/* 5239 */    MCD_OPC_CheckPredicate, 3, 252, 10, 0, // Skip to: 8056
/* 5244 */    MCD_OPC_Decode, 217, 3, 36, // Opcode: FPADD32S
/* 5248 */    MCD_OPC_FilterValue, 84, 9, 0, 0, // Skip to: 5262
/* 5253 */    MCD_OPC_CheckPredicate, 3, 238, 10, 0, // Skip to: 8056
/* 5258 */    MCD_OPC_Decode, 220, 3, 36, // Opcode: FPSUB16
/* 5262 */    MCD_OPC_FilterValue, 85, 9, 0, 0, // Skip to: 5276
/* 5267 */    MCD_OPC_CheckPredicate, 3, 224, 10, 0, // Skip to: 8056
/* 5272 */    MCD_OPC_Decode, 221, 3, 36, // Opcode: FPSUB16S
/* 5276 */    MCD_OPC_FilterValue, 86, 9, 0, 0, // Skip to: 5290
/* 5281 */    MCD_OPC_CheckPredicate, 3, 210, 10, 0, // Skip to: 8056
/* 5286 */    MCD_OPC_Decode, 222, 3, 36, // Opcode: FPSUB32
/* 5290 */    MCD_OPC_FilterValue, 87, 9, 0, 0, // Skip to: 5304
/* 5295 */    MCD_OPC_CheckPredicate, 3, 196, 10, 0, // Skip to: 8056
/* 5300 */    MCD_OPC_Decode, 223, 3, 36, // Opcode: FPSUB32S
/* 5304 */    MCD_OPC_FilterValue, 96, 23, 0, 0, // Skip to: 5332
/* 5309 */    MCD_OPC_CheckPredicate, 3, 182, 10, 0, // Skip to: 8056
/* 5314 */    MCD_OPC_CheckField, 14, 5, 0, 175, 10, 0, // Skip to: 8056
/* 5321 */    MCD_OPC_CheckField, 0, 5, 0, 168, 10, 0, // Skip to: 8056
/* 5328 */    MCD_OPC_Decode, 130, 4, 59, // Opcode: FZERO
/* 5332 */    MCD_OPC_FilterValue, 97, 23, 0, 0, // Skip to: 5360
/* 5337 */    MCD_OPC_CheckPredicate, 3, 154, 10, 0, // Skip to: 8056
/* 5342 */    MCD_OPC_CheckField, 14, 5, 0, 147, 10, 0, // Skip to: 8056
/* 5349 */    MCD_OPC_CheckField, 0, 5, 0, 140, 10, 0, // Skip to: 8056
/* 5356 */    MCD_OPC_Decode, 131, 4, 60, // Opcode: FZEROS
/* 5360 */    MCD_OPC_FilterValue, 98, 9, 0, 0, // Skip to: 5374
/* 5365 */    MCD_OPC_CheckPredicate, 3, 126, 10, 0, // Skip to: 8056
/* 5370 */    MCD_OPC_Decode, 196, 3, 36, // Opcode: FNOR
/* 5374 */    MCD_OPC_FilterValue, 99, 9, 0, 0, // Skip to: 5388
/* 5379 */    MCD_OPC_CheckPredicate, 3, 112, 10, 0, // Skip to: 8056
/* 5384 */    MCD_OPC_Decode, 197, 3, 35, // Opcode: FNORS
/* 5388 */    MCD_OPC_FilterValue, 100, 9, 0, 0, // Skip to: 5402
/* 5393 */    MCD_OPC_CheckPredicate, 3, 98, 10, 0, // Skip to: 8056
/* 5398 */    MCD_OPC_Decode, 233, 2, 36, // Opcode: FANDNOT2
/* 5402 */    MCD_OPC_FilterValue, 101, 9, 0, 0, // Skip to: 5416
/* 5407 */    MCD_OPC_CheckPredicate, 3, 84, 10, 0, // Skip to: 8056
/* 5412 */    MCD_OPC_Decode, 234, 2, 35, // Opcode: FANDNOT2S
/* 5416 */    MCD_OPC_FilterValue, 102, 16, 0, 0, // Skip to: 5437
/* 5421 */    MCD_OPC_CheckPredicate, 3, 70, 10, 0, // Skip to: 8056
/* 5426 */    MCD_OPC_CheckField, 14, 5, 0, 63, 10, 0, // Skip to: 8056
/* 5433 */    MCD_OPC_Decode, 200, 3, 33, // Opcode: FNOT2
/* 5437 */    MCD_OPC_FilterValue, 103, 16, 0, 0, // Skip to: 5458
/* 5442 */    MCD_OPC_CheckPredicate, 3, 49, 10, 0, // Skip to: 8056
/* 5447 */    MCD_OPC_CheckField, 14, 5, 0, 42, 10, 0, // Skip to: 8056
/* 5454 */    MCD_OPC_Decode, 201, 3, 32, // Opcode: FNOT2S
/* 5458 */    MCD_OPC_FilterValue, 104, 9, 0, 0, // Skip to: 5472
/* 5463 */    MCD_OPC_CheckPredicate, 3, 28, 10, 0, // Skip to: 8056
/* 5468 */    MCD_OPC_Decode, 231, 2, 36, // Opcode: FANDNOT1
/* 5472 */    MCD_OPC_FilterValue, 105, 9, 0, 0, // Skip to: 5486
/* 5477 */    MCD_OPC_CheckPredicate, 3, 14, 10, 0, // Skip to: 8056
/* 5482 */    MCD_OPC_Decode, 232, 2, 35, // Opcode: FANDNOT1S
/* 5486 */    MCD_OPC_FilterValue, 106, 16, 0, 0, // Skip to: 5507
/* 5491 */    MCD_OPC_CheckPredicate, 3, 0, 10, 0, // Skip to: 8056
/* 5496 */    MCD_OPC_CheckField, 0, 5, 0, 249, 9, 0, // Skip to: 8056
/* 5503 */    MCD_OPC_Decode, 198, 3, 61, // Opcode: FNOT1
/* 5507 */    MCD_OPC_FilterValue, 107, 16, 0, 0, // Skip to: 5528
/* 5512 */    MCD_OPC_CheckPredicate, 3, 235, 9, 0, // Skip to: 8056
/* 5517 */    MCD_OPC_CheckField, 0, 5, 0, 228, 9, 0, // Skip to: 8056
/* 5524 */    MCD_OPC_Decode, 199, 3, 62, // Opcode: FNOT1S
/* 5528 */    MCD_OPC_FilterValue, 108, 9, 0, 0, // Skip to: 5542
/* 5533 */    MCD_OPC_CheckPredicate, 3, 214, 9, 0, // Skip to: 8056
/* 5538 */    MCD_OPC_Decode, 253, 3, 36, // Opcode: FXOR
/* 5542 */    MCD_OPC_FilterValue, 109, 9, 0, 0, // Skip to: 5556
/* 5547 */    MCD_OPC_CheckPredicate, 3, 200, 9, 0, // Skip to: 8056
/* 5552 */    MCD_OPC_Decode, 254, 3, 35, // Opcode: FXORS
/* 5556 */    MCD_OPC_FilterValue, 110, 9, 0, 0, // Skip to: 5570
/* 5561 */    MCD_OPC_CheckPredicate, 3, 186, 9, 0, // Skip to: 8056
/* 5566 */    MCD_OPC_Decode, 187, 3, 36, // Opcode: FNAND
/* 5570 */    MCD_OPC_FilterValue, 111, 9, 0, 0, // Skip to: 5584
/* 5575 */    MCD_OPC_CheckPredicate, 3, 172, 9, 0, // Skip to: 8056
/* 5580 */    MCD_OPC_Decode, 188, 3, 35, // Opcode: FNANDS
/* 5584 */    MCD_OPC_FilterValue, 112, 9, 0, 0, // Skip to: 5598
/* 5589 */    MCD_OPC_CheckPredicate, 3, 158, 9, 0, // Skip to: 8056
/* 5594 */    MCD_OPC_Decode, 230, 2, 36, // Opcode: FAND
/* 5598 */    MCD_OPC_FilterValue, 113, 9, 0, 0, // Skip to: 5612
/* 5603 */    MCD_OPC_CheckPredicate, 3, 144, 9, 0, // Skip to: 8056
/* 5608 */    MCD_OPC_Decode, 235, 2, 35, // Opcode: FANDS
/* 5612 */    MCD_OPC_FilterValue, 114, 9, 0, 0, // Skip to: 5626
/* 5617 */    MCD_OPC_CheckPredicate, 3, 130, 9, 0, // Skip to: 8056
/* 5622 */    MCD_OPC_Decode, 251, 3, 36, // Opcode: FXNOR
/* 5626 */    MCD_OPC_FilterValue, 115, 9, 0, 0, // Skip to: 5640
/* 5631 */    MCD_OPC_CheckPredicate, 3, 116, 9, 0, // Skip to: 8056
/* 5636 */    MCD_OPC_Decode, 252, 3, 35, // Opcode: FXNORS
/* 5640 */    MCD_OPC_FilterValue, 116, 16, 0, 0, // Skip to: 5661
/* 5645 */    MCD_OPC_CheckPredicate, 3, 102, 9, 0, // Skip to: 8056
/* 5650 */    MCD_OPC_CheckField, 0, 5, 0, 95, 9, 0, // Skip to: 8056
/* 5657 */    MCD_OPC_Decode, 238, 3, 61, // Opcode: FSRC1
/* 5661 */    MCD_OPC_FilterValue, 117, 16, 0, 0, // Skip to: 5682
/* 5666 */    MCD_OPC_CheckPredicate, 3, 81, 9, 0, // Skip to: 8056
/* 5671 */    MCD_OPC_CheckField, 0, 5, 0, 74, 9, 0, // Skip to: 8056
/* 5678 */    MCD_OPC_Decode, 239, 3, 62, // Opcode: FSRC1S
/* 5682 */    MCD_OPC_FilterValue, 118, 9, 0, 0, // Skip to: 5696
/* 5687 */    MCD_OPC_CheckPredicate, 3, 60, 9, 0, // Skip to: 8056
/* 5692 */    MCD_OPC_Decode, 208, 3, 36, // Opcode: FORNOT2
/* 5696 */    MCD_OPC_FilterValue, 119, 9, 0, 0, // Skip to: 5710
/* 5701 */    MCD_OPC_CheckPredicate, 3, 46, 9, 0, // Skip to: 8056
/* 5706 */    MCD_OPC_Decode, 209, 3, 35, // Opcode: FORNOT2S
/* 5710 */    MCD_OPC_FilterValue, 120, 16, 0, 0, // Skip to: 5731
/* 5715 */    MCD_OPC_CheckPredicate, 3, 32, 9, 0, // Skip to: 8056
/* 5720 */    MCD_OPC_CheckField, 14, 5, 0, 25, 9, 0, // Skip to: 8056
/* 5727 */    MCD_OPC_Decode, 240, 3, 33, // Opcode: FSRC2
/* 5731 */    MCD_OPC_FilterValue, 121, 16, 0, 0, // Skip to: 5752
/* 5736 */    MCD_OPC_CheckPredicate, 3, 11, 9, 0, // Skip to: 8056
/* 5741 */    MCD_OPC_CheckField, 14, 5, 0, 4, 9, 0, // Skip to: 8056
/* 5748 */    MCD_OPC_Decode, 241, 3, 32, // Opcode: FSRC2S
/* 5752 */    MCD_OPC_FilterValue, 122, 9, 0, 0, // Skip to: 5766
/* 5757 */    MCD_OPC_CheckPredicate, 3, 246, 8, 0, // Skip to: 8056
/* 5762 */    MCD_OPC_Decode, 206, 3, 36, // Opcode: FORNOT1
/* 5766 */    MCD_OPC_FilterValue, 123, 9, 0, 0, // Skip to: 5780
/* 5771 */    MCD_OPC_CheckPredicate, 3, 232, 8, 0, // Skip to: 8056
/* 5776 */    MCD_OPC_Decode, 207, 3, 35, // Opcode: FORNOT1S
/* 5780 */    MCD_OPC_FilterValue, 124, 9, 0, 0, // Skip to: 5794
/* 5785 */    MCD_OPC_CheckPredicate, 3, 218, 8, 0, // Skip to: 8056
/* 5790 */    MCD_OPC_Decode, 205, 3, 36, // Opcode: FOR
/* 5794 */    MCD_OPC_FilterValue, 125, 9, 0, 0, // Skip to: 5808
/* 5799 */    MCD_OPC_CheckPredicate, 3, 204, 8, 0, // Skip to: 8056
/* 5804 */    MCD_OPC_Decode, 210, 3, 35, // Opcode: FORS
/* 5808 */    MCD_OPC_FilterValue, 126, 23, 0, 0, // Skip to: 5836
/* 5813 */    MCD_OPC_CheckPredicate, 3, 190, 8, 0, // Skip to: 8056
/* 5818 */    MCD_OPC_CheckField, 14, 5, 0, 183, 8, 0, // Skip to: 8056
/* 5825 */    MCD_OPC_CheckField, 0, 5, 0, 176, 8, 0, // Skip to: 8056
/* 5832 */    MCD_OPC_Decode, 203, 3, 59, // Opcode: FONE
/* 5836 */    MCD_OPC_FilterValue, 127, 23, 0, 0, // Skip to: 5864
/* 5841 */    MCD_OPC_CheckPredicate, 3, 162, 8, 0, // Skip to: 8056
/* 5846 */    MCD_OPC_CheckField, 14, 5, 0, 155, 8, 0, // Skip to: 8056
/* 5853 */    MCD_OPC_CheckField, 0, 5, 0, 148, 8, 0, // Skip to: 8056
/* 5860 */    MCD_OPC_Decode, 204, 3, 60, // Opcode: FONES
/* 5864 */    MCD_OPC_FilterValue, 128, 1, 30, 0, 0, // Skip to: 5900
/* 5870 */    MCD_OPC_CheckPredicate, 3, 133, 8, 0, // Skip to: 8056
/* 5875 */    MCD_OPC_CheckField, 25, 5, 0, 126, 8, 0, // Skip to: 8056
/* 5882 */    MCD_OPC_CheckField, 14, 5, 0, 119, 8, 0, // Skip to: 8056
/* 5889 */    MCD_OPC_CheckField, 0, 5, 0, 112, 8, 0, // Skip to: 8056
/* 5896 */    MCD_OPC_Decode, 250, 4, 4, // Opcode: SHUTDOWN
/* 5900 */    MCD_OPC_FilterValue, 129, 1, 30, 0, 0, // Skip to: 5936
/* 5906 */    MCD_OPC_CheckPredicate, 4, 97, 8, 0, // Skip to: 8056
/* 5911 */    MCD_OPC_CheckField, 25, 5, 0, 90, 8, 0, // Skip to: 8056
/* 5918 */    MCD_OPC_CheckField, 14, 5, 0, 83, 8, 0, // Skip to: 8056
/* 5925 */    MCD_OPC_CheckField, 0, 5, 0, 76, 8, 0, // Skip to: 8056
/* 5932 */    MCD_OPC_Decode, 251, 4, 4, // Opcode: SIAM
/* 5936 */    MCD_OPC_FilterValue, 144, 2, 16, 0, 0, // Skip to: 5958
/* 5942 */    MCD_OPC_CheckPredicate, 2, 61, 8, 0, // Skip to: 8056
/* 5947 */    MCD_OPC_CheckField, 14, 5, 0, 54, 8, 0, // Skip to: 8056
/* 5954 */    MCD_OPC_Decode, 182, 4, 63, // Opcode: MOVDTOX
/* 5958 */    MCD_OPC_FilterValue, 145, 2, 16, 0, 0, // Skip to: 5980
/* 5964 */    MCD_OPC_CheckPredicate, 2, 39, 8, 0, // Skip to: 8056
/* 5969 */    MCD_OPC_CheckField, 14, 5, 0, 32, 8, 0, // Skip to: 8056
/* 5976 */    MCD_OPC_Decode, 200, 4, 63, // Opcode: MOVSTOUW
/* 5980 */    MCD_OPC_FilterValue, 147, 2, 16, 0, 0, // Skip to: 6002
/* 5986 */    MCD_OPC_CheckPredicate, 2, 17, 8, 0, // Skip to: 8056
/* 5991 */    MCD_OPC_CheckField, 14, 5, 0, 10, 8, 0, // Skip to: 8056
/* 5998 */    MCD_OPC_Decode, 199, 4, 63, // Opcode: MOVSTOSW
/* 6002 */    MCD_OPC_FilterValue, 149, 2, 9, 0, 0, // Skip to: 6017
/* 6008 */    MCD_OPC_CheckPredicate, 2, 251, 7, 0, // Skip to: 8056
/* 6013 */    MCD_OPC_Decode, 251, 5, 10, // Opcode: XMULX
/* 6017 */    MCD_OPC_FilterValue, 151, 2, 9, 0, 0, // Skip to: 6032
/* 6023 */    MCD_OPC_CheckPredicate, 2, 236, 7, 0, // Skip to: 8056
/* 6028 */    MCD_OPC_Decode, 252, 5, 10, // Opcode: XMULXHI
/* 6032 */    MCD_OPC_FilterValue, 152, 2, 16, 0, 0, // Skip to: 6054
/* 6038 */    MCD_OPC_CheckPredicate, 2, 221, 7, 0, // Skip to: 8056
/* 6043 */    MCD_OPC_CheckField, 14, 5, 0, 214, 7, 0, // Skip to: 8056
/* 6050 */    MCD_OPC_Decode, 204, 4, 64, // Opcode: MOVXTOD
/* 6054 */    MCD_OPC_FilterValue, 153, 2, 16, 0, 0, // Skip to: 6076
/* 6060 */    MCD_OPC_CheckPredicate, 2, 199, 7, 0, // Skip to: 8056
/* 6065 */    MCD_OPC_CheckField, 14, 5, 0, 192, 7, 0, // Skip to: 8056
/* 6072 */    MCD_OPC_Decode, 201, 4, 64, // Opcode: MOVWTOS
/* 6076 */    MCD_OPC_FilterValue, 209, 2, 9, 0, 0, // Skip to: 6091
/* 6082 */    MCD_OPC_CheckPredicate, 2, 177, 7, 0, // Skip to: 8056
/* 6087 */    MCD_OPC_Decode, 139, 3, 54, // Opcode: FLCMPS
/* 6091 */    MCD_OPC_FilterValue, 210, 2, 167, 7, 0, // Skip to: 8056
/* 6097 */    MCD_OPC_CheckPredicate, 2, 162, 7, 0, // Skip to: 8056
/* 6102 */    MCD_OPC_Decode, 138, 3, 54, // Opcode: FLCMPD
/* 6106 */    MCD_OPC_FilterValue, 56, 28, 0, 0, // Skip to: 6139
/* 6111 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6114 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6130
/* 6119 */    MCD_OPC_CheckField, 5, 8, 0, 138, 7, 0, // Skip to: 8056
/* 6126 */    MCD_OPC_Decode, 133, 4, 65, // Opcode: JMPLrr
/* 6130 */    MCD_OPC_FilterValue, 1, 129, 7, 0, // Skip to: 8056
/* 6135 */    MCD_OPC_Decode, 132, 4, 65, // Opcode: JMPLri
/* 6139 */    MCD_OPC_FilterValue, 57, 42, 0, 0, // Skip to: 6186
/* 6144 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6147 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 6170
/* 6152 */    MCD_OPC_CheckField, 25, 5, 0, 105, 7, 0, // Skip to: 8056
/* 6159 */    MCD_OPC_CheckField, 5, 8, 0, 98, 7, 0, // Skip to: 8056
/* 6166 */    MCD_OPC_Decode, 239, 4, 66, // Opcode: RETTrr
/* 6170 */    MCD_OPC_FilterValue, 1, 89, 7, 0, // Skip to: 8056
/* 6175 */    MCD_OPC_CheckField, 25, 5, 0, 82, 7, 0, // Skip to: 8056
/* 6182 */    MCD_OPC_Decode, 238, 4, 66, // Opcode: RETTri
/* 6186 */    MCD_OPC_FilterValue, 58, 119, 0, 0, // Skip to: 6310
/* 6191 */    MCD_OPC_ExtractField, 8, 6,  // Inst{13-8} ...
/* 6194 */    MCD_OPC_FilterValue, 16, 18, 0, 0, // Skip to: 6217
/* 6199 */    MCD_OPC_CheckField, 29, 1, 0, 58, 7, 0, // Skip to: 8056
/* 6206 */    MCD_OPC_CheckField, 5, 3, 0, 51, 7, 0, // Skip to: 8056
/* 6213 */    MCD_OPC_Decode, 215, 5, 67, // Opcode: TXCCrr
/* 6217 */    MCD_OPC_FilterValue, 32, 72, 0, 0, // Skip to: 6294
/* 6222 */    MCD_OPC_ExtractField, 0, 8,  // Inst{7-0} ...
/* 6225 */    MCD_OPC_FilterValue, 1, 18, 0, 0, // Skip to: 6248
/* 6230 */    MCD_OPC_CheckField, 25, 5, 8, 27, 7, 0, // Skip to: 8056
/* 6237 */    MCD_OPC_CheckField, 14, 5, 0, 20, 7, 0, // Skip to: 8056
/* 6244 */    MCD_OPC_Decode, 194, 5, 4, // Opcode: TA1
/* 6248 */    MCD_OPC_FilterValue, 3, 18, 0, 0, // Skip to: 6271
/* 6253 */    MCD_OPC_CheckField, 25, 5, 8, 4, 7, 0, // Skip to: 8056
/* 6260 */    MCD_OPC_CheckField, 14, 5, 0, 253, 6, 0, // Skip to: 8056
/* 6267 */    MCD_OPC_Decode, 195, 5, 4, // Opcode: TA3
/* 6271 */    MCD_OPC_FilterValue, 5, 244, 6, 0, // Skip to: 8056
/* 6276 */    MCD_OPC_CheckField, 25, 5, 8, 237, 6, 0, // Skip to: 8056
/* 6283 */    MCD_OPC_CheckField, 14, 5, 0, 230, 6, 0, // Skip to: 8056
/* 6290 */    MCD_OPC_Decode, 196, 5, 4, // Opcode: TA5
/* 6294 */    MCD_OPC_FilterValue, 48, 221, 6, 0, // Skip to: 8056
/* 6299 */    MCD_OPC_CheckField, 29, 1, 0, 214, 6, 0, // Skip to: 8056
/* 6306 */    MCD_OPC_Decode, 214, 5, 68, // Opcode: TXCCri
/* 6310 */    MCD_OPC_FilterValue, 59, 62, 0, 0, // Skip to: 6377
/* 6315 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6318 */    MCD_OPC_FilterValue, 0, 38, 0, 0, // Skip to: 6361
/* 6323 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 6326 */    MCD_OPC_FilterValue, 0, 189, 6, 0, // Skip to: 8056
/* 6331 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 6334 */    MCD_OPC_FilterValue, 0, 181, 6, 0, // Skip to: 8056
/* 6339 */    MCD_OPC_CheckField, 14, 5, 0, 11, 0, 0, // Skip to: 6357
/* 6346 */    MCD_OPC_CheckField, 0, 5, 0, 4, 0, 0, // Skip to: 6357
/* 6353 */    MCD_OPC_Decode, 140, 3, 4, // Opcode: FLUSH
/* 6357 */    MCD_OPC_Decode, 143, 3, 4, // Opcode: FLUSHrr
/* 6361 */    MCD_OPC_FilterValue, 1, 154, 6, 0, // Skip to: 8056
/* 6366 */    MCD_OPC_CheckField, 25, 5, 0, 147, 6, 0, // Skip to: 8056
/* 6373 */    MCD_OPC_Decode, 142, 3, 4, // Opcode: FLUSHri
/* 6377 */    MCD_OPC_FilterValue, 60, 28, 0, 0, // Skip to: 6410
/* 6382 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6385 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6401
/* 6390 */    MCD_OPC_CheckField, 5, 8, 0, 123, 6, 0, // Skip to: 8056
/* 6397 */    MCD_OPC_Decode, 241, 4, 8, // Opcode: SAVErr
/* 6401 */    MCD_OPC_FilterValue, 1, 114, 6, 0, // Skip to: 8056
/* 6406 */    MCD_OPC_Decode, 240, 4, 9, // Opcode: SAVEri
/* 6410 */    MCD_OPC_FilterValue, 61, 28, 0, 0, // Skip to: 6443
/* 6415 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6418 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6434
/* 6423 */    MCD_OPC_CheckField, 5, 8, 0, 90, 6, 0, // Skip to: 8056
/* 6430 */    MCD_OPC_Decode, 235, 4, 8, // Opcode: RESTORErr
/* 6434 */    MCD_OPC_FilterValue, 1, 81, 6, 0, // Skip to: 8056
/* 6439 */    MCD_OPC_Decode, 234, 4, 9, // Opcode: RESTOREri
/* 6443 */    MCD_OPC_FilterValue, 62, 28, 0, 0, // Skip to: 6476
/* 6448 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6451 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6467
/* 6456 */    MCD_OPC_CheckField, 5, 8, 0, 57, 6, 0, // Skip to: 8056
/* 6463 */    MCD_OPC_Decode, 223, 5, 8, // Opcode: UMACrr
/* 6467 */    MCD_OPC_FilterValue, 1, 48, 6, 0, // Skip to: 8056
/* 6472 */    MCD_OPC_Decode, 222, 5, 9, // Opcode: UMACri
/* 6476 */    MCD_OPC_FilterValue, 63, 39, 6, 0, // Skip to: 8056
/* 6481 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6484 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6500
/* 6489 */    MCD_OPC_CheckField, 5, 8, 0, 24, 6, 0, // Skip to: 8056
/* 6496 */    MCD_OPC_Decode, 130, 5, 8, // Opcode: SMACrr
/* 6500 */    MCD_OPC_FilterValue, 1, 15, 6, 0, // Skip to: 8056
/* 6505 */    MCD_OPC_Decode, 129, 5, 9, // Opcode: SMACri
/* 6509 */    MCD_OPC_FilterValue, 3, 6, 6, 0, // Skip to: 8056
/* 6514 */    MCD_OPC_ExtractField, 19, 6,  // Inst{24-19} ...
/* 6517 */    MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 6550
/* 6522 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6525 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6541
/* 6530 */    MCD_OPC_CheckField, 5, 8, 0, 239, 5, 0, // Skip to: 8056
/* 6537 */    MCD_OPC_Decode, 177, 4, 69, // Opcode: LDrr
/* 6541 */    MCD_OPC_FilterValue, 1, 230, 5, 0, // Skip to: 8056
/* 6546 */    MCD_OPC_Decode, 176, 4, 69, // Opcode: LDri
/* 6550 */    MCD_OPC_FilterValue, 1, 28, 0, 0, // Skip to: 6583
/* 6555 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6558 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6574
/* 6563 */    MCD_OPC_CheckField, 5, 8, 0, 206, 5, 0, // Skip to: 8056
/* 6570 */    MCD_OPC_Decode, 168, 4, 69, // Opcode: LDUBrr
/* 6574 */    MCD_OPC_FilterValue, 1, 197, 5, 0, // Skip to: 8056
/* 6579 */    MCD_OPC_Decode, 167, 4, 69, // Opcode: LDUBri
/* 6583 */    MCD_OPC_FilterValue, 2, 28, 0, 0, // Skip to: 6616
/* 6588 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6591 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6607
/* 6596 */    MCD_OPC_CheckField, 5, 8, 0, 173, 5, 0, // Skip to: 8056
/* 6603 */    MCD_OPC_Decode, 171, 4, 69, // Opcode: LDUHrr
/* 6607 */    MCD_OPC_FilterValue, 1, 164, 5, 0, // Skip to: 8056
/* 6612 */    MCD_OPC_Decode, 170, 4, 69, // Opcode: LDUHri
/* 6616 */    MCD_OPC_FilterValue, 3, 28, 0, 0, // Skip to: 6649
/* 6621 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6624 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6640
/* 6629 */    MCD_OPC_CheckField, 5, 8, 0, 140, 5, 0, // Skip to: 8056
/* 6636 */    MCD_OPC_Decode, 146, 4, 70, // Opcode: LDDrr
/* 6640 */    MCD_OPC_FilterValue, 1, 131, 5, 0, // Skip to: 8056
/* 6645 */    MCD_OPC_Decode, 145, 4, 70, // Opcode: LDDri
/* 6649 */    MCD_OPC_FilterValue, 4, 28, 0, 0, // Skip to: 6682
/* 6654 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6657 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6673
/* 6662 */    MCD_OPC_CheckField, 5, 8, 0, 107, 5, 0, // Skip to: 8056
/* 6669 */    MCD_OPC_Decode, 180, 5, 71, // Opcode: STrr
/* 6673 */    MCD_OPC_FilterValue, 1, 98, 5, 0, // Skip to: 8056
/* 6678 */    MCD_OPC_Decode, 179, 5, 71, // Opcode: STri
/* 6682 */    MCD_OPC_FilterValue, 5, 28, 0, 0, // Skip to: 6715
/* 6687 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6690 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6706
/* 6695 */    MCD_OPC_CheckField, 5, 8, 0, 74, 5, 0, // Skip to: 8056
/* 6702 */    MCD_OPC_Decode, 147, 5, 71, // Opcode: STBrr
/* 6706 */    MCD_OPC_FilterValue, 1, 65, 5, 0, // Skip to: 8056
/* 6711 */    MCD_OPC_Decode, 146, 5, 71, // Opcode: STBri
/* 6715 */    MCD_OPC_FilterValue, 6, 28, 0, 0, // Skip to: 6748
/* 6720 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6723 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6739
/* 6728 */    MCD_OPC_CheckField, 5, 8, 0, 41, 5, 0, // Skip to: 8056
/* 6735 */    MCD_OPC_Decode, 171, 5, 71, // Opcode: STHrr
/* 6739 */    MCD_OPC_FilterValue, 1, 32, 5, 0, // Skip to: 8056
/* 6744 */    MCD_OPC_Decode, 170, 5, 71, // Opcode: STHri
/* 6748 */    MCD_OPC_FilterValue, 7, 28, 0, 0, // Skip to: 6781
/* 6753 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6756 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6772
/* 6761 */    MCD_OPC_CheckField, 5, 8, 0, 8, 5, 0, // Skip to: 8056
/* 6768 */    MCD_OPC_Decode, 163, 5, 72, // Opcode: STDrr
/* 6772 */    MCD_OPC_FilterValue, 1, 255, 4, 0, // Skip to: 8056
/* 6777 */    MCD_OPC_Decode, 162, 5, 72, // Opcode: STDri
/* 6781 */    MCD_OPC_FilterValue, 8, 28, 0, 0, // Skip to: 6814
/* 6786 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6789 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6805
/* 6794 */    MCD_OPC_CheckField, 5, 8, 0, 231, 4, 0, // Skip to: 8056
/* 6801 */    MCD_OPC_Decode, 165, 4, 69, // Opcode: LDSWrr
/* 6805 */    MCD_OPC_FilterValue, 1, 222, 4, 0, // Skip to: 8056
/* 6810 */    MCD_OPC_Decode, 164, 4, 69, // Opcode: LDSWri
/* 6814 */    MCD_OPC_FilterValue, 9, 28, 0, 0, // Skip to: 6847
/* 6819 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6822 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6838
/* 6827 */    MCD_OPC_CheckField, 5, 8, 0, 198, 4, 0, // Skip to: 8056
/* 6834 */    MCD_OPC_Decode, 157, 4, 69, // Opcode: LDSBrr
/* 6838 */    MCD_OPC_FilterValue, 1, 189, 4, 0, // Skip to: 8056
/* 6843 */    MCD_OPC_Decode, 156, 4, 69, // Opcode: LDSBri
/* 6847 */    MCD_OPC_FilterValue, 10, 28, 0, 0, // Skip to: 6880
/* 6852 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6855 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6871
/* 6860 */    MCD_OPC_CheckField, 5, 8, 0, 165, 4, 0, // Skip to: 8056
/* 6867 */    MCD_OPC_Decode, 160, 4, 69, // Opcode: LDSHrr
/* 6871 */    MCD_OPC_FilterValue, 1, 156, 4, 0, // Skip to: 8056
/* 6876 */    MCD_OPC_Decode, 159, 4, 69, // Opcode: LDSHri
/* 6880 */    MCD_OPC_FilterValue, 11, 28, 0, 0, // Skip to: 6913
/* 6885 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6888 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6904
/* 6893 */    MCD_OPC_CheckField, 5, 8, 0, 132, 4, 0, // Skip to: 8056
/* 6900 */    MCD_OPC_Decode, 175, 4, 69, // Opcode: LDXrr
/* 6904 */    MCD_OPC_FilterValue, 1, 123, 4, 0, // Skip to: 8056
/* 6909 */    MCD_OPC_Decode, 174, 4, 69, // Opcode: LDXri
/* 6913 */    MCD_OPC_FilterValue, 13, 28, 0, 0, // Skip to: 6946
/* 6918 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6921 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6937
/* 6926 */    MCD_OPC_CheckField, 5, 8, 0, 99, 4, 0, // Skip to: 8056
/* 6933 */    MCD_OPC_Decode, 163, 4, 4, // Opcode: LDSTUBrr
/* 6937 */    MCD_OPC_FilterValue, 1, 90, 4, 0, // Skip to: 8056
/* 6942 */    MCD_OPC_Decode, 162, 4, 4, // Opcode: LDSTUBri
/* 6946 */    MCD_OPC_FilterValue, 14, 28, 0, 0, // Skip to: 6979
/* 6951 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6954 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6970
/* 6959 */    MCD_OPC_CheckField, 5, 8, 0, 66, 4, 0, // Skip to: 8056
/* 6966 */    MCD_OPC_Decode, 178, 5, 71, // Opcode: STXrr
/* 6970 */    MCD_OPC_FilterValue, 1, 57, 4, 0, // Skip to: 8056
/* 6975 */    MCD_OPC_Decode, 177, 5, 71, // Opcode: STXri
/* 6979 */    MCD_OPC_FilterValue, 15, 28, 0, 0, // Skip to: 7012
/* 6984 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6987 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7003
/* 6992 */    MCD_OPC_CheckField, 5, 8, 0, 33, 4, 0, // Skip to: 8056
/* 6999 */    MCD_OPC_Decode, 193, 5, 73, // Opcode: SWAPrr
/* 7003 */    MCD_OPC_FilterValue, 1, 24, 4, 0, // Skip to: 8056
/* 7008 */    MCD_OPC_Decode, 192, 5, 73, // Opcode: SWAPri
/* 7012 */    MCD_OPC_FilterValue, 16, 11, 0, 0, // Skip to: 7028
/* 7017 */    MCD_OPC_CheckField, 13, 1, 0, 8, 4, 0, // Skip to: 8056
/* 7024 */    MCD_OPC_Decode, 134, 4, 69, // Opcode: LDArr
/* 7028 */    MCD_OPC_FilterValue, 17, 11, 0, 0, // Skip to: 7044
/* 7033 */    MCD_OPC_CheckField, 13, 1, 0, 248, 3, 0, // Skip to: 8056
/* 7040 */    MCD_OPC_Decode, 166, 4, 69, // Opcode: LDUBArr
/* 7044 */    MCD_OPC_FilterValue, 18, 11, 0, 0, // Skip to: 7060
/* 7049 */    MCD_OPC_CheckField, 13, 1, 0, 232, 3, 0, // Skip to: 8056
/* 7056 */    MCD_OPC_Decode, 169, 4, 69, // Opcode: LDUHArr
/* 7060 */    MCD_OPC_FilterValue, 19, 11, 0, 0, // Skip to: 7076
/* 7065 */    MCD_OPC_CheckField, 13, 1, 0, 216, 3, 0, // Skip to: 8056
/* 7072 */    MCD_OPC_Decode, 139, 4, 70, // Opcode: LDDArr
/* 7076 */    MCD_OPC_FilterValue, 20, 11, 0, 0, // Skip to: 7092
/* 7081 */    MCD_OPC_CheckField, 13, 1, 0, 200, 3, 0, // Skip to: 8056
/* 7088 */    MCD_OPC_Decode, 143, 5, 71, // Opcode: STArr
/* 7092 */    MCD_OPC_FilterValue, 21, 11, 0, 0, // Skip to: 7108
/* 7097 */    MCD_OPC_CheckField, 13, 1, 0, 184, 3, 0, // Skip to: 8056
/* 7104 */    MCD_OPC_Decode, 145, 5, 71, // Opcode: STBArr
/* 7108 */    MCD_OPC_FilterValue, 22, 11, 0, 0, // Skip to: 7124
/* 7113 */    MCD_OPC_CheckField, 13, 1, 0, 168, 3, 0, // Skip to: 8056
/* 7120 */    MCD_OPC_Decode, 169, 5, 71, // Opcode: STHArr
/* 7124 */    MCD_OPC_FilterValue, 23, 11, 0, 0, // Skip to: 7140
/* 7129 */    MCD_OPC_CheckField, 13, 1, 0, 152, 3, 0, // Skip to: 8056
/* 7136 */    MCD_OPC_Decode, 152, 5, 72, // Opcode: STDArr
/* 7140 */    MCD_OPC_FilterValue, 25, 11, 0, 0, // Skip to: 7156
/* 7145 */    MCD_OPC_CheckField, 13, 1, 0, 136, 3, 0, // Skip to: 8056
/* 7152 */    MCD_OPC_Decode, 155, 4, 69, // Opcode: LDSBArr
/* 7156 */    MCD_OPC_FilterValue, 26, 11, 0, 0, // Skip to: 7172
/* 7161 */    MCD_OPC_CheckField, 13, 1, 0, 120, 3, 0, // Skip to: 8056
/* 7168 */    MCD_OPC_Decode, 158, 4, 69, // Opcode: LDSHArr
/* 7172 */    MCD_OPC_FilterValue, 29, 11, 0, 0, // Skip to: 7188
/* 7177 */    MCD_OPC_CheckField, 13, 1, 0, 104, 3, 0, // Skip to: 8056
/* 7184 */    MCD_OPC_Decode, 161, 4, 74, // Opcode: LDSTUBArr
/* 7188 */    MCD_OPC_FilterValue, 31, 11, 0, 0, // Skip to: 7204
/* 7193 */    MCD_OPC_CheckField, 13, 1, 0, 88, 3, 0, // Skip to: 8056
/* 7200 */    MCD_OPC_Decode, 191, 5, 73, // Opcode: SWAPArr
/* 7204 */    MCD_OPC_FilterValue, 32, 28, 0, 0, // Skip to: 7237
/* 7209 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7212 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7228
/* 7217 */    MCD_OPC_CheckField, 5, 8, 0, 64, 3, 0, // Skip to: 8056
/* 7224 */    MCD_OPC_Decode, 151, 4, 75, // Opcode: LDFrr
/* 7228 */    MCD_OPC_FilterValue, 1, 55, 3, 0, // Skip to: 8056
/* 7233 */    MCD_OPC_Decode, 150, 4, 75, // Opcode: LDFri
/* 7237 */    MCD_OPC_FilterValue, 33, 79, 0, 0, // Skip to: 7321
/* 7242 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7245 */    MCD_OPC_FilterValue, 0, 40, 0, 0, // Skip to: 7290
/* 7250 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7253 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7269
/* 7258 */    MCD_OPC_CheckField, 5, 8, 0, 23, 3, 0, // Skip to: 8056
/* 7265 */    MCD_OPC_Decode, 149, 4, 75, // Opcode: LDFSRrr
/* 7269 */    MCD_OPC_FilterValue, 1, 14, 3, 0, // Skip to: 8056
/* 7274 */    MCD_OPC_CheckPredicate, 0, 9, 3, 0, // Skip to: 8056
/* 7279 */    MCD_OPC_CheckField, 5, 8, 0, 2, 3, 0, // Skip to: 8056
/* 7286 */    MCD_OPC_Decode, 173, 4, 75, // Opcode: LDXFSRrr
/* 7290 */    MCD_OPC_FilterValue, 1, 249, 2, 0, // Skip to: 8056
/* 7295 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7298 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7307
/* 7303 */    MCD_OPC_Decode, 148, 4, 75, // Opcode: LDFSRri
/* 7307 */    MCD_OPC_FilterValue, 1, 232, 2, 0, // Skip to: 8056
/* 7312 */    MCD_OPC_CheckPredicate, 0, 227, 2, 0, // Skip to: 8056
/* 7317 */    MCD_OPC_Decode, 172, 4, 75, // Opcode: LDXFSRri
/* 7321 */    MCD_OPC_FilterValue, 34, 38, 0, 0, // Skip to: 7364
/* 7326 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7329 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 7350
/* 7334 */    MCD_OPC_CheckPredicate, 0, 205, 2, 0, // Skip to: 8056
/* 7339 */    MCD_OPC_CheckField, 5, 8, 0, 198, 2, 0, // Skip to: 8056
/* 7346 */    MCD_OPC_Decode, 154, 4, 76, // Opcode: LDQFrr
/* 7350 */    MCD_OPC_FilterValue, 1, 189, 2, 0, // Skip to: 8056
/* 7355 */    MCD_OPC_CheckPredicate, 0, 184, 2, 0, // Skip to: 8056
/* 7360 */    MCD_OPC_Decode, 153, 4, 76, // Opcode: LDQFri
/* 7364 */    MCD_OPC_FilterValue, 35, 28, 0, 0, // Skip to: 7397
/* 7369 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7372 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7388
/* 7377 */    MCD_OPC_CheckField, 5, 8, 0, 160, 2, 0, // Skip to: 8056
/* 7384 */    MCD_OPC_Decode, 144, 4, 77, // Opcode: LDDFrr
/* 7388 */    MCD_OPC_FilterValue, 1, 151, 2, 0, // Skip to: 8056
/* 7393 */    MCD_OPC_Decode, 143, 4, 77, // Opcode: LDDFri
/* 7397 */    MCD_OPC_FilterValue, 36, 28, 0, 0, // Skip to: 7430
/* 7402 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7405 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7421
/* 7410 */    MCD_OPC_CheckField, 5, 8, 0, 127, 2, 0, // Skip to: 8056
/* 7417 */    MCD_OPC_Decode, 168, 5, 78, // Opcode: STFrr
/* 7421 */    MCD_OPC_FilterValue, 1, 118, 2, 0, // Skip to: 8056
/* 7426 */    MCD_OPC_Decode, 167, 5, 78, // Opcode: STFri
/* 7430 */    MCD_OPC_FilterValue, 37, 79, 0, 0, // Skip to: 7514
/* 7435 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7438 */    MCD_OPC_FilterValue, 0, 40, 0, 0, // Skip to: 7483
/* 7443 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7446 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7462
/* 7451 */    MCD_OPC_CheckField, 5, 8, 0, 86, 2, 0, // Skip to: 8056
/* 7458 */    MCD_OPC_Decode, 166, 5, 78, // Opcode: STFSRrr
/* 7462 */    MCD_OPC_FilterValue, 1, 77, 2, 0, // Skip to: 8056
/* 7467 */    MCD_OPC_CheckPredicate, 0, 72, 2, 0, // Skip to: 8056
/* 7472 */    MCD_OPC_CheckField, 5, 8, 0, 65, 2, 0, // Skip to: 8056
/* 7479 */    MCD_OPC_Decode, 176, 5, 78, // Opcode: STXFSRrr
/* 7483 */    MCD_OPC_FilterValue, 1, 56, 2, 0, // Skip to: 8056
/* 7488 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7491 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7500
/* 7496 */    MCD_OPC_Decode, 165, 5, 78, // Opcode: STFSRri
/* 7500 */    MCD_OPC_FilterValue, 1, 39, 2, 0, // Skip to: 8056
/* 7505 */    MCD_OPC_CheckPredicate, 0, 34, 2, 0, // Skip to: 8056
/* 7510 */    MCD_OPC_Decode, 175, 5, 78, // Opcode: STXFSRri
/* 7514 */    MCD_OPC_FilterValue, 38, 61, 0, 0, // Skip to: 7580
/* 7519 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7522 */    MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 7555
/* 7527 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 7530 */    MCD_OPC_FilterValue, 0, 9, 2, 0, // Skip to: 8056
/* 7535 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 7546
/* 7542 */    MCD_OPC_Decode, 159, 5, 78, // Opcode: STDFQrr
/* 7546 */    MCD_OPC_CheckPredicate, 0, 249, 1, 0, // Skip to: 8056
/* 7551 */    MCD_OPC_Decode, 174, 5, 79, // Opcode: STQFrr
/* 7555 */    MCD_OPC_FilterValue, 1, 240, 1, 0, // Skip to: 8056
/* 7560 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 7571
/* 7567 */    MCD_OPC_Decode, 158, 5, 78, // Opcode: STDFQri
/* 7571 */    MCD_OPC_CheckPredicate, 0, 224, 1, 0, // Skip to: 8056
/* 7576 */    MCD_OPC_Decode, 173, 5, 79, // Opcode: STQFri
/* 7580 */    MCD_OPC_FilterValue, 39, 28, 0, 0, // Skip to: 7613
/* 7585 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7588 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7604
/* 7593 */    MCD_OPC_CheckField, 5, 8, 0, 200, 1, 0, // Skip to: 8056
/* 7600 */    MCD_OPC_Decode, 161, 5, 80, // Opcode: STDFrr
/* 7604 */    MCD_OPC_FilterValue, 1, 191, 1, 0, // Skip to: 8056
/* 7609 */    MCD_OPC_Decode, 160, 5, 80, // Opcode: STDFri
/* 7613 */    MCD_OPC_FilterValue, 45, 38, 0, 0, // Skip to: 7656
/* 7618 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7621 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 7642
/* 7626 */    MCD_OPC_CheckPredicate, 0, 169, 1, 0, // Skip to: 8056
/* 7631 */    MCD_OPC_CheckField, 5, 8, 0, 162, 1, 0, // Skip to: 8056
/* 7638 */    MCD_OPC_Decode, 225, 4, 81, // Opcode: PREFETCHr
/* 7642 */    MCD_OPC_FilterValue, 1, 153, 1, 0, // Skip to: 8056
/* 7647 */    MCD_OPC_CheckPredicate, 0, 148, 1, 0, // Skip to: 8056
/* 7652 */    MCD_OPC_Decode, 224, 4, 81, // Opcode: PREFETCHi
/* 7656 */    MCD_OPC_FilterValue, 48, 37, 0, 0, // Skip to: 7698
/* 7661 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7664 */    MCD_OPC_FilterValue, 0, 20, 0, 0, // Skip to: 7689
/* 7669 */    MCD_OPC_CheckField, 5, 8, 0, 4, 0, 0, // Skip to: 7680
/* 7676 */    MCD_OPC_Decode, 138, 4, 82, // Opcode: LDCrr
/* 7680 */    MCD_OPC_CheckPredicate, 0, 115, 1, 0, // Skip to: 8056
/* 7685 */    MCD_OPC_Decode, 147, 4, 75, // Opcode: LDFArr
/* 7689 */    MCD_OPC_FilterValue, 1, 106, 1, 0, // Skip to: 8056
/* 7694 */    MCD_OPC_Decode, 137, 4, 82, // Opcode: LDCri
/* 7698 */    MCD_OPC_FilterValue, 49, 42, 0, 0, // Skip to: 7745
/* 7703 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7706 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 7729
/* 7711 */    MCD_OPC_CheckField, 25, 5, 0, 82, 1, 0, // Skip to: 8056
/* 7718 */    MCD_OPC_CheckField, 5, 8, 0, 75, 1, 0, // Skip to: 8056
/* 7725 */    MCD_OPC_Decode, 136, 4, 82, // Opcode: LDCSRrr
/* 7729 */    MCD_OPC_FilterValue, 1, 66, 1, 0, // Skip to: 8056
/* 7734 */    MCD_OPC_CheckField, 25, 5, 0, 59, 1, 0, // Skip to: 8056
/* 7741 */    MCD_OPC_Decode, 135, 4, 82, // Opcode: LDCSRri
/* 7745 */    MCD_OPC_FilterValue, 50, 16, 0, 0, // Skip to: 7766
/* 7750 */    MCD_OPC_CheckPredicate, 0, 45, 1, 0, // Skip to: 8056
/* 7755 */    MCD_OPC_CheckField, 13, 1, 0, 38, 1, 0, // Skip to: 8056
/* 7762 */    MCD_OPC_Decode, 152, 4, 76, // Opcode: LDQFArr
/* 7766 */    MCD_OPC_FilterValue, 51, 37, 0, 0, // Skip to: 7808
/* 7771 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7774 */    MCD_OPC_FilterValue, 0, 20, 0, 0, // Skip to: 7799
/* 7779 */    MCD_OPC_CheckField, 5, 8, 0, 4, 0, 0, // Skip to: 7790
/* 7786 */    MCD_OPC_Decode, 141, 4, 83, // Opcode: LDDCrr
/* 7790 */    MCD_OPC_CheckPredicate, 0, 5, 1, 0, // Skip to: 8056
/* 7795 */    MCD_OPC_Decode, 142, 4, 77, // Opcode: LDDFArr
/* 7799 */    MCD_OPC_FilterValue, 1, 252, 0, 0, // Skip to: 8056
/* 7804 */    MCD_OPC_Decode, 140, 4, 83, // Opcode: LDDCri
/* 7808 */    MCD_OPC_FilterValue, 52, 37, 0, 0, // Skip to: 7850
/* 7813 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7816 */    MCD_OPC_FilterValue, 0, 20, 0, 0, // Skip to: 7841
/* 7821 */    MCD_OPC_CheckField, 5, 8, 0, 4, 0, 0, // Skip to: 7832
/* 7828 */    MCD_OPC_Decode, 151, 5, 84, // Opcode: STCrr
/* 7832 */    MCD_OPC_CheckPredicate, 0, 219, 0, 0, // Skip to: 8056
/* 7837 */    MCD_OPC_Decode, 164, 5, 78, // Opcode: STFArr
/* 7841 */    MCD_OPC_FilterValue, 1, 210, 0, 0, // Skip to: 8056
/* 7846 */    MCD_OPC_Decode, 150, 5, 84, // Opcode: STCri
/* 7850 */    MCD_OPC_FilterValue, 53, 42, 0, 0, // Skip to: 7897
/* 7855 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7858 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 7881
/* 7863 */    MCD_OPC_CheckField, 25, 5, 0, 186, 0, 0, // Skip to: 8056
/* 7870 */    MCD_OPC_CheckField, 5, 8, 0, 179, 0, 0, // Skip to: 8056
/* 7877 */    MCD_OPC_Decode, 149, 5, 84, // Opcode: STCSRrr
/* 7881 */    MCD_OPC_FilterValue, 1, 170, 0, 0, // Skip to: 8056
/* 7886 */    MCD_OPC_CheckField, 25, 5, 0, 163, 0, 0, // Skip to: 8056
/* 7893 */    MCD_OPC_Decode, 148, 5, 84, // Opcode: STCSRri
/* 7897 */    MCD_OPC_FilterValue, 54, 51, 0, 0, // Skip to: 7953
/* 7902 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7905 */    MCD_OPC_FilterValue, 0, 27, 0, 0, // Skip to: 7937
/* 7910 */    MCD_OPC_CheckField, 25, 5, 0, 11, 0, 0, // Skip to: 7928
/* 7917 */    MCD_OPC_CheckField, 5, 8, 0, 4, 0, 0, // Skip to: 7928
/* 7924 */    MCD_OPC_Decode, 154, 5, 84, // Opcode: STDCQrr
/* 7928 */    MCD_OPC_CheckPredicate, 0, 123, 0, 0, // Skip to: 8056
/* 7933 */    MCD_OPC_Decode, 172, 5, 79, // Opcode: STQFArr
/* 7937 */    MCD_OPC_FilterValue, 1, 114, 0, 0, // Skip to: 8056
/* 7942 */    MCD_OPC_CheckField, 25, 5, 0, 107, 0, 0, // Skip to: 8056
/* 7949 */    MCD_OPC_Decode, 153, 5, 84, // Opcode: STDCQri
/* 7953 */    MCD_OPC_FilterValue, 55, 37, 0, 0, // Skip to: 7995
/* 7958 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7961 */    MCD_OPC_FilterValue, 0, 20, 0, 0, // Skip to: 7986
/* 7966 */    MCD_OPC_CheckField, 5, 8, 0, 4, 0, 0, // Skip to: 7977
/* 7973 */    MCD_OPC_Decode, 156, 5, 85, // Opcode: STDCrr
/* 7977 */    MCD_OPC_CheckPredicate, 0, 74, 0, 0, // Skip to: 8056
/* 7982 */    MCD_OPC_Decode, 157, 5, 80, // Opcode: STDFArr
/* 7986 */    MCD_OPC_FilterValue, 1, 65, 0, 0, // Skip to: 8056
/* 7991 */    MCD_OPC_Decode, 155, 5, 85, // Opcode: STDCri
/* 7995 */    MCD_OPC_FilterValue, 60, 39, 0, 0, // Skip to: 8039
/* 8000 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 8003 */    MCD_OPC_FilterValue, 0, 48, 0, 0, // Skip to: 8056
/* 8008 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 8011 */    MCD_OPC_FilterValue, 10, 4, 0, 0, // Skip to: 8020
/* 8016 */    MCD_OPC_Decode, 200, 2, 86, // Opcode: CASAasi10
/* 8020 */    MCD_OPC_FilterValue, 128, 1, 9, 0, 0, // Skip to: 8035
/* 8026 */    MCD_OPC_CheckPredicate, 0, 4, 0, 0, // Skip to: 8035
/* 8031 */    MCD_OPC_Decode, 203, 2, 86, // Opcode: CASrr
/* 8035 */    MCD_OPC_Decode, 201, 2, 87, // Opcode: CASArr
/* 8039 */    MCD_OPC_FilterValue, 62, 12, 0, 0, // Skip to: 8056
/* 8044 */    MCD_OPC_CheckField, 5, 9, 128, 1, 4, 0, 0, // Skip to: 8056
/* 8052 */    MCD_OPC_Decode, 202, 2, 88, // Opcode: CASXrr
/* 8056 */    MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableSparcV832[] = {
/* 0 */       MCD_OPC_ExtractField, 8, 6,  // Inst{13-8} ...
/* 3 */       MCD_OPC_FilterValue, 0, 25, 0, 0, // Skip to: 33
/* 8 */       MCD_OPC_CheckField, 29, 3, 4, 41, 0, 0, // Skip to: 56
/* 15 */      MCD_OPC_CheckField, 19, 6, 58, 34, 0, 0, // Skip to: 56
/* 22 */      MCD_OPC_CheckField, 5, 3, 0, 27, 0, 0, // Skip to: 56
/* 29 */      MCD_OPC_Decode, 209, 5, 89, // Opcode: TRAPrr
/* 33 */      MCD_OPC_FilterValue, 32, 18, 0, 0, // Skip to: 56
/* 38 */      MCD_OPC_CheckField, 29, 3, 4, 11, 0, 0, // Skip to: 56
/* 45 */      MCD_OPC_CheckField, 19, 6, 58, 4, 0, 0, // Skip to: 56
/* 52 */      MCD_OPC_Decode, 208, 5, 89, // Opcode: TRAPri
/* 56 */      MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableSparcV932[] = {
/* 0 */       MCD_OPC_ExtractField, 8, 6,  // Inst{13-8} ...
/* 3 */       MCD_OPC_FilterValue, 0, 30, 0, 0, // Skip to: 38
/* 8 */       MCD_OPC_CheckPredicate, 0, 53, 0, 0, // Skip to: 66
/* 13 */      MCD_OPC_CheckField, 29, 3, 4, 46, 0, 0, // Skip to: 66
/* 20 */      MCD_OPC_CheckField, 19, 6, 58, 39, 0, 0, // Skip to: 66
/* 27 */      MCD_OPC_CheckField, 5, 3, 0, 32, 0, 0, // Skip to: 66
/* 34 */      MCD_OPC_Decode, 202, 5, 89, // Opcode: TICCrr
/* 38 */      MCD_OPC_FilterValue, 32, 23, 0, 0, // Skip to: 66
/* 43 */      MCD_OPC_CheckPredicate, 0, 18, 0, 0, // Skip to: 66
/* 48 */      MCD_OPC_CheckField, 29, 3, 4, 11, 0, 0, // Skip to: 66
/* 55 */      MCD_OPC_CheckField, 19, 6, 58, 4, 0, 0, // Skip to: 66
/* 62 */      MCD_OPC_Decode, 201, 5, 89, // Opcode: TICCri
/* 66 */      MCD_OPC_Fail,
  0
};

static bool getbool(uint64_t b)
{
	return b != 0;
}
static bool checkDecoderPredicate(unsigned Idx, uint64_t Bits) {
  switch (Idx) {
  default: llvm_unreachable("Invalid index!");
  case 0:
    return getbool(checkFeatureRequired(Bits, Sparc_FeatureV9, 1));
  case 1:
    return getbool(checkFeatureRequired(Bits, Sparc_FeaturePWRPSR, 1));
  case 2:
    return getbool(checkFeatureRequired(Bits, Sparc_FeatureVIS3, 1));
  case 3:
    return getbool(checkFeatureRequired(Bits, Sparc_FeatureVIS, 1));
  case 4:
    return getbool(checkFeatureRequired(Bits, Sparc_FeatureVIS2, 1));
  }
}

#define DecodeToMCInst(fname, fieldname, InsnType) \
static DecodeStatus fname(DecodeStatus S, unsigned Idx, InsnType insn, MCInst *MI, \
                uint64_t Address, bool *Decoder) {\
  InsnType tmp;\
  switch (Idx) {\
  default: llvm_unreachable("Invalid index!");\
  case 0:\
    tmp = fieldFromInstruction(insn, 0, 22);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 1:\
    tmp = fieldFromInstruction(insn, 0, 19);\
    MCOperand_CreateImm0(MI, tmp);\
    tmp = fieldFromInstruction(insn, 25, 4);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 2:\
    tmp = fieldFromInstruction(insn, 0, 22);\
    MCOperand_CreateImm0(MI, tmp);\
    tmp = fieldFromInstruction(insn, 25, 4);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 3:\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = 0x0;\
    tmp |= fieldFromInstruction(insn, 0, 14) << 0;\
    tmp |= fieldFromInstruction(insn, 20, 2) << 14;\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 4:\
    return S;\
  case 5:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 22);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 6:\
    tmp = fieldFromInstruction(insn, 0, 19);\
    MCOperand_CreateImm0(MI, tmp);\
    tmp = fieldFromInstruction(insn, 25, 4);\
    MCOperand_CreateImm0(MI, tmp);\
    tmp = fieldFromInstruction(insn, 20, 2);\
    if (DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 7:\
    tmp = fieldFromInstruction(insn, 0, 30);\
    if (DecodeCall(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 8:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 9:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 13);\
    if (DecodeSIMM13(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 10:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 11:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 13);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 12:\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 13:\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 13);\
    if (DecodeSIMM13(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 14:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 15:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 6);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 16:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 6);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 17:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 18:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeASRRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 19:\
    tmp = fieldFromInstruction(insn, 0, 13);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 20:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodePRRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 21:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 4);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 22:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 11, 2);\
    if (DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 4);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 23:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 11);\
    MCOperand_CreateImm0(MI, tmp);\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 4);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 24:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 11, 2);\
    if (DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 11);\
    MCOperand_CreateImm0(MI, tmp);\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 4);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 25:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 26:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 10);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 27:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeASRRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 28:\
    tmp = fieldFromInstruction(insn, 0, 13);\
    if (DecodeSIMM13(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 29:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeASRRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 13);\
    if (DecodeSIMM13(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 30:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodePRRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 31:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodePRRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 13);\
    if (DecodeSIMM13(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 32:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 33:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 34:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 35:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 36:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 37:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 38:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 39:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 40:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 41:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 42:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 43:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 44:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 45:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 46:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 4);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 47:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 11, 2);\
    if (DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 4);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 48:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 4);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 49:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 11, 2);\
    if (DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 4);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 50:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 4);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 51:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 11, 2);\
    if (DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 4);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 52:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 53:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 54:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 55:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeFCCRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeQFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 56:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 57:\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 58:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 59:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 60:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 61:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 62:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 63:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 64:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeDFPRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 65:\
    if (DecodeJMPL(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 66:\
    if (DecodeReturn(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 67:\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 25, 4);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 68:\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 8);\
    MCOperand_CreateImm0(MI, tmp);\
    tmp = fieldFromInstruction(insn, 25, 4);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 69:\
    if (DecodeLoadInt(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 70:\
    if (DecodeLoadIntPair(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 71:\
    if (DecodeStoreInt(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 72:\
    if (DecodeStoreIntPair(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 73:\
    if (DecodeSWAP(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 74:\
    tmp = fieldFromInstruction(insn, 5, 8);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 75:\
    if (DecodeLoadFP(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 76:\
    if (DecodeLoadQFP(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 77:\
    if (DecodeLoadDFP(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 78:\
    if (DecodeStoreFP(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 79:\
    if (DecodeStoreQFP(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 80:\
    if (DecodeStoreDFP(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 81:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 82:\
    if (DecodeLoadCP(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 83:\
    if (DecodeLoadCPPair(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 84:\
    if (DecodeStoreCP(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 85:\
    if (DecodeStoreCPPair(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 86:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 87:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 5, 8);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 88:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 89:\
    if (DecodeTRAP(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
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

#define SP_CANRESTORE 1
#define SP_CANSAVE 2
#define SP_CLEANWIN 3
#define SP_CPQ 4
#define SP_CPSR 5
#define SP_CWP 6
#define SP_FQ 7
#define SP_FSR 8
#define SP_ICC 9
#define SP_OTHERWIN 10
#define SP_PC 11
#define SP_PIL 12
#define SP_PSR 13
#define SP_PSTATE 14
#define SP_TBA 15
#define SP_TBR 16
#define SP_TICK 17
#define SP_TL 18
#define SP_TNPC 19
#define SP_TPC 20
#define SP_TSTATE 21
#define SP_TT 22
#define SP_WIM 23
#define SP_WSTATE 24
#define SP_Y 25
#define SP_ASR1 26
#define SP_ASR2 27
#define SP_ASR3 28
#define SP_ASR4 29
#define SP_ASR5 30
#define SP_ASR6 31
#define SP_ASR7 32
#define SP_ASR8 33
#define SP_ASR9 34
#define SP_ASR10 35
#define SP_ASR11 36
#define SP_ASR12 37
#define SP_ASR13 38
#define SP_ASR14 39
#define SP_ASR15 40
#define SP_ASR16 41
#define SP_ASR17 42
#define SP_ASR18 43
#define SP_ASR19 44
#define SP_ASR20 45
#define SP_ASR21 46
#define SP_ASR22 47
#define SP_ASR23 48
#define SP_ASR24 49
#define SP_ASR25 50
#define SP_ASR26 51
#define SP_ASR27 52
#define SP_ASR28 53
#define SP_ASR29 54
#define SP_ASR30 55
#define SP_ASR31 56
#define SP_C0 57
#define SP_C1 58
#define SP_C2 59
#define SP_C3 60
#define SP_C4 61
#define SP_C5 62
#define SP_C6 63
#define SP_C7 64
#define SP_C8 65
#define SP_C9 66
#define SP_C10 67
#define SP_C11 68
#define SP_C12 69
#define SP_C13 70
#define SP_C14 71
#define SP_C15 72
#define SP_C16 73
#define SP_C17 74
#define SP_C18 75
#define SP_C19 76
#define SP_C20 77
#define SP_C21 78
#define SP_C22 79
#define SP_C23 80
#define SP_C24 81
#define SP_C25 82
#define SP_C26 83
#define SP_C27 84
#define SP_C28 85
#define SP_C29 86
#define SP_C30 87
#define SP_C31 88
#define SP_D0 89
#define SP_D1 90
#define SP_D2 91
#define SP_D3 92
#define SP_D4 93
#define SP_D5 94
#define SP_D6 95
#define SP_D7 96
#define SP_D8 97
#define SP_D9 98
#define SP_D10 99
#define SP_D11 100
#define SP_D12 101
#define SP_D13 102
#define SP_D14 103
#define SP_D15 104
#define SP_D16 105
#define SP_D17 106
#define SP_D18 107
#define SP_D19 108
#define SP_D20 109
#define SP_D21 110
#define SP_D22 111
#define SP_D23 112
#define SP_D24 113
#define SP_D25 114
#define SP_D26 115
#define SP_D27 116
#define SP_D28 117
#define SP_D29 118
#define SP_D30 119
#define SP_D31 120
#define SP_F0 121
#define SP_F1 122
#define SP_F2 123
#define SP_F3 124
#define SP_F4 125
#define SP_F5 126
#define SP_F6 127
#define SP_F7 128
#define SP_F8 129
#define SP_F9 130
#define SP_F10 131
#define SP_F11 132
#define SP_F12 133
#define SP_F13 134
#define SP_F14 135
#define SP_F15 136
#define SP_F16 137
#define SP_F17 138
#define SP_F18 139
#define SP_F19 140
#define SP_F20 141
#define SP_F21 142
#define SP_F22 143
#define SP_F23 144
#define SP_F24 145
#define SP_F25 146
#define SP_F26 147
#define SP_F27 148
#define SP_F28 149
#define SP_F29 150
#define SP_F30 151
#define SP_F31 152
#define SP_FCC0 153
#define SP_FCC1 154
#define SP_FCC2 155
#define SP_FCC3 156
#define SP_G0 157
#define SP_G1 158
#define SP_G2 159
#define SP_G3 160
#define SP_G4 161
#define SP_G5 162
#define SP_G6 163
#define SP_G7 164
#define SP_I0 165
#define SP_I1 166
#define SP_I2 167
#define SP_I3 168
#define SP_I4 169
#define SP_I5 170
#define SP_I6 171
#define SP_I7 172
#define SP_L0 173
#define SP_L1 174
#define SP_L2 175
#define SP_L3 176
#define SP_L4 177
#define SP_L5 178
#define SP_L6 179
#define SP_L7 180
#define SP_O0 181
#define SP_O1 182
#define SP_O2 183
#define SP_O3 184
#define SP_O4 185
#define SP_O5 186
#define SP_O6 187
#define SP_O7 188
#define SP_Q0 189
#define SP_Q1 190
#define SP_Q2 191
#define SP_Q3 192
#define SP_Q4 193
#define SP_Q5 194
#define SP_Q6 195
#define SP_Q7 196
#define SP_Q8 197
#define SP_Q9 198
#define SP_Q10 199
#define SP_Q11 200
#define SP_Q12 201
#define SP_Q13 202
#define SP_Q14 203
#define SP_Q15 204
#define SP_C0_C1 205
#define SP_C2_C3 206
#define SP_C4_C5 207
#define SP_C6_C7 208
#define SP_C8_C9 209
#define SP_C10_C11 210
#define SP_C12_C13 211
#define SP_C14_C15 212
#define SP_C16_C17 213
#define SP_C18_C19 214
#define SP_C20_C21 215
#define SP_C22_C23 216
#define SP_C24_C25 217
#define SP_C26_C27 218
#define SP_C28_C29 219
#define SP_C30_C31 220
#define SP_G0_G1 221
#define SP_G2_G3 222
#define SP_G4_G5 223
#define SP_G6_G7 224
#define SP_I0_I1 225
#define SP_I2_I3 226
#define SP_I4_I5 227
#define SP_I6_I7 228
#define SP_L0_L1 229
#define SP_L2_L3 230
#define SP_L4_L5 231
#define SP_L6_L7 232
#define SP_O0_O1 233
#define SP_O2_O3 234
#define SP_O4_O5 235
#define SP_O6_O7 236
#define SP_NUM_TARGET_REGS 237


// Register classes

#define SP_FCCRegsRegClassID 0
#define SP_ASRRegsRegClassID 1
#define SP_CoprocRegsRegClassID 2
#define SP_FPRegsRegClassID 3
#define SP_IntRegsRegClassID 4
#define SP_DFPRegsRegClassID 5
#define SP_I64RegsRegClassID 6
#define SP_CoprocPairRegClassID 7
#define SP_IntPairRegClassID 8
#define SP_LowDFPRegsRegClassID 9
#define SP_PRRegsRegClassID 10
#define SP_QFPRegsRegClassID 11
#define SP_LowQFPRegsRegClassID 12

#endif // GET_REGINFO_ENUM

#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM
#define SP_PHI	 0
#define SP_INLINEASM	 1
#define SP_INLINEASM_BR	 2
#define SP_CFI_INSTRUCTION	 3
#define SP_EH_LABEL	 4
#define SP_GC_LABEL	 5
#define SP_ANNOTATION_LABEL	 6
#define SP_KILL	 7
#define SP_EXTRACT_SUBREG	 8
#define SP_INSERT_SUBREG	 9
#define SP_IMPLICIT_DEF	 10
#define SP_SUBREG_TO_REG	 11
#define SP_COPY_TO_REGCLASS	 12
#define SP_DBG_VALUE	 13
#define SP_DBG_VALUE_LIST	 14
#define SP_DBG_INSTR_REF	 15
#define SP_DBG_PHI	 16
#define SP_DBG_LABEL	 17
#define SP_REG_SEQUENCE	 18
#define SP_COPY	 19
#define SP_BUNDLE	 20
#define SP_LIFETIME_START	 21
#define SP_LIFETIME_END	 22
#define SP_PSEUDO_PROBE	 23
#define SP_ARITH_FENCE	 24
#define SP_STACKMAP	 25
#define SP_FENTRY_CALL	 26
#define SP_PATCHPOINT	 27
#define SP_LOAD_STACK_GUARD	 28
#define SP_PREALLOCATED_SETUP	 29
#define SP_PREALLOCATED_ARG	 30
#define SP_STATEPOINT	 31
#define SP_LOCAL_ESCAPE	 32
#define SP_FAULTING_OP	 33
#define SP_PATCHABLE_OP	 34
#define SP_PATCHABLE_FUNCTION_ENTER	 35
#define SP_PATCHABLE_RET	 36
#define SP_PATCHABLE_FUNCTION_EXIT	 37
#define SP_PATCHABLE_TAIL_CALL	 38
#define SP_PATCHABLE_EVENT_CALL	 39
#define SP_PATCHABLE_TYPED_EVENT_CALL	 40
#define SP_ICALL_BRANCH_FUNNEL	 41
#define SP_G_ASSERT_SEXT	 42
#define SP_G_ASSERT_ZEXT	 43
#define SP_G_ADD	 44
#define SP_G_SUB	 45
#define SP_G_MUL	 46
#define SP_G_SDIV	 47
#define SP_G_UDIV	 48
#define SP_G_SREM	 49
#define SP_G_UREM	 50
#define SP_G_SDIVREM	 51
#define SP_G_UDIVREM	 52
#define SP_G_AND	 53
#define SP_G_OR	 54
#define SP_G_XOR	 55
#define SP_G_IMPLICIT_DEF	 56
#define SP_G_PHI	 57
#define SP_G_FRAME_INDEX	 58
#define SP_G_GLOBAL_VALUE	 59
#define SP_G_EXTRACT	 60
#define SP_G_UNMERGE_VALUES	 61
#define SP_G_INSERT	 62
#define SP_G_MERGE_VALUES	 63
#define SP_G_BUILD_VECTOR	 64
#define SP_G_BUILD_VECTOR_TRUNC	 65
#define SP_G_CONCAT_VECTORS	 66
#define SP_G_PTRTOINT	 67
#define SP_G_INTTOPTR	 68
#define SP_G_BITCAST	 69
#define SP_G_FREEZE	 70
#define SP_G_INTRINSIC_TRUNC	 71
#define SP_G_INTRINSIC_ROUND	 72
#define SP_G_INTRINSIC_LRINT	 73
#define SP_G_INTRINSIC_ROUNDEVEN	 74
#define SP_G_READCYCLECOUNTER	 75
#define SP_G_LOAD	 76
#define SP_G_SEXTLOAD	 77
#define SP_G_ZEXTLOAD	 78
#define SP_G_INDEXED_LOAD	 79
#define SP_G_INDEXED_SEXTLOAD	 80
#define SP_G_INDEXED_ZEXTLOAD	 81
#define SP_G_STORE	 82
#define SP_G_INDEXED_STORE	 83
#define SP_G_ATOMIC_CMPXCHG_WITH_SUCCESS	 84
#define SP_G_ATOMIC_CMPXCHG	 85
#define SP_G_ATOMICRMW_XCHG	 86
#define SP_G_ATOMICRMW_ADD	 87
#define SP_G_ATOMICRMW_SUB	 88
#define SP_G_ATOMICRMW_AND	 89
#define SP_G_ATOMICRMW_NAND	 90
#define SP_G_ATOMICRMW_OR	 91
#define SP_G_ATOMICRMW_XOR	 92
#define SP_G_ATOMICRMW_MAX	 93
#define SP_G_ATOMICRMW_MIN	 94
#define SP_G_ATOMICRMW_UMAX	 95
#define SP_G_ATOMICRMW_UMIN	 96
#define SP_G_ATOMICRMW_FADD	 97
#define SP_G_ATOMICRMW_FSUB	 98
#define SP_G_FENCE	 99
#define SP_G_BRCOND	 100
#define SP_G_BRINDIRECT	 101
#define SP_G_INTRINSIC	 102
#define SP_G_INTRINSIC_W_SIDE_EFFECTS	 103
#define SP_G_ANYEXT	 104
#define SP_G_TRUNC	 105
#define SP_G_CONSTANT	 106
#define SP_G_FCONSTANT	 107
#define SP_G_VASTART	 108
#define SP_G_VAARG	 109
#define SP_G_SEXT	 110
#define SP_G_SEXT_INREG	 111
#define SP_G_ZEXT	 112
#define SP_G_SHL	 113
#define SP_G_LSHR	 114
#define SP_G_ASHR	 115
#define SP_G_FSHL	 116
#define SP_G_FSHR	 117
#define SP_G_ROTR	 118
#define SP_G_ROTL	 119
#define SP_G_ICMP	 120
#define SP_G_FCMP	 121
#define SP_G_SELECT	 122
#define SP_G_UADDO	 123
#define SP_G_UADDE	 124
#define SP_G_USUBO	 125
#define SP_G_USUBE	 126
#define SP_G_SADDO	 127
#define SP_G_SADDE	 128
#define SP_G_SSUBO	 129
#define SP_G_SSUBE	 130
#define SP_G_UMULO	 131
#define SP_G_SMULO	 132
#define SP_G_UMULH	 133
#define SP_G_SMULH	 134
#define SP_G_UADDSAT	 135
#define SP_G_SADDSAT	 136
#define SP_G_USUBSAT	 137
#define SP_G_SSUBSAT	 138
#define SP_G_USHLSAT	 139
#define SP_G_SSHLSAT	 140
#define SP_G_SMULFIX	 141
#define SP_G_UMULFIX	 142
#define SP_G_SMULFIXSAT	 143
#define SP_G_UMULFIXSAT	 144
#define SP_G_SDIVFIX	 145
#define SP_G_UDIVFIX	 146
#define SP_G_SDIVFIXSAT	 147
#define SP_G_UDIVFIXSAT	 148
#define SP_G_FADD	 149
#define SP_G_FSUB	 150
#define SP_G_FMUL	 151
#define SP_G_FMA	 152
#define SP_G_FMAD	 153
#define SP_G_FDIV	 154
#define SP_G_FREM	 155
#define SP_G_FPOW	 156
#define SP_G_FPOWI	 157
#define SP_G_FEXP	 158
#define SP_G_FEXP2	 159
#define SP_G_FLOG	 160
#define SP_G_FLOG2	 161
#define SP_G_FLOG10	 162
#define SP_G_FNEG	 163
#define SP_G_FPEXT	 164
#define SP_G_FPTRUNC	 165
#define SP_G_FPTOSI	 166
#define SP_G_FPTOUI	 167
#define SP_G_SITOFP	 168
#define SP_G_UITOFP	 169
#define SP_G_FABS	 170
#define SP_G_FCOPYSIGN	 171
#define SP_G_FCANONICALIZE	 172
#define SP_G_FMINNUM	 173
#define SP_G_FMAXNUM	 174
#define SP_G_FMINNUM_IEEE	 175
#define SP_G_FMAXNUM_IEEE	 176
#define SP_G_FMINIMUM	 177
#define SP_G_FMAXIMUM	 178
#define SP_G_PTR_ADD	 179
#define SP_G_PTRMASK	 180
#define SP_G_SMIN	 181
#define SP_G_SMAX	 182
#define SP_G_UMIN	 183
#define SP_G_UMAX	 184
#define SP_G_ABS	 185
#define SP_G_LROUND	 186
#define SP_G_LLROUND	 187
#define SP_G_BR	 188
#define SP_G_BRJT	 189
#define SP_G_INSERT_VECTOR_ELT	 190
#define SP_G_EXTRACT_VECTOR_ELT	 191
#define SP_G_SHUFFLE_VECTOR	 192
#define SP_G_CTTZ	 193
#define SP_G_CTTZ_ZERO_UNDEF	 194
#define SP_G_CTLZ	 195
#define SP_G_CTLZ_ZERO_UNDEF	 196
#define SP_G_CTPOP	 197
#define SP_G_BSWAP	 198
#define SP_G_BITREVERSE	 199
#define SP_G_FCEIL	 200
#define SP_G_FCOS	 201
#define SP_G_FSIN	 202
#define SP_G_FSQRT	 203
#define SP_G_FFLOOR	 204
#define SP_G_FRINT	 205
#define SP_G_FNEARBYINT	 206
#define SP_G_ADDRSPACE_CAST	 207
#define SP_G_BLOCK_ADDR	 208
#define SP_G_JUMP_TABLE	 209
#define SP_G_DYN_STACKALLOC	 210
#define SP_G_STRICT_FADD	 211
#define SP_G_STRICT_FSUB	 212
#define SP_G_STRICT_FMUL	 213
#define SP_G_STRICT_FDIV	 214
#define SP_G_STRICT_FREM	 215
#define SP_G_STRICT_FMA	 216
#define SP_G_STRICT_FSQRT	 217
#define SP_G_READ_REGISTER	 218
#define SP_G_WRITE_REGISTER	 219
#define SP_G_MEMCPY	 220
#define SP_G_MEMCPY_INLINE	 221
#define SP_G_MEMMOVE	 222
#define SP_G_MEMSET	 223
#define SP_G_BZERO	 224
#define SP_G_VECREDUCE_SEQ_FADD	 225
#define SP_G_VECREDUCE_SEQ_FMUL	 226
#define SP_G_VECREDUCE_FADD	 227
#define SP_G_VECREDUCE_FMUL	 228
#define SP_G_VECREDUCE_FMAX	 229
#define SP_G_VECREDUCE_FMIN	 230
#define SP_G_VECREDUCE_ADD	 231
#define SP_G_VECREDUCE_MUL	 232
#define SP_G_VECREDUCE_AND	 233
#define SP_G_VECREDUCE_OR	 234
#define SP_G_VECREDUCE_XOR	 235
#define SP_G_VECREDUCE_SMAX	 236
#define SP_G_VECREDUCE_SMIN	 237
#define SP_G_VECREDUCE_UMAX	 238
#define SP_G_VECREDUCE_UMIN	 239
#define SP_G_SBFX	 240
#define SP_G_UBFX	 241
#define SP_ADJCALLSTACKDOWN	 242
#define SP_ADJCALLSTACKUP	 243
#define SP_GETPCX	 244
#define SP_SELECT_CC_DFP_FCC	 245
#define SP_SELECT_CC_DFP_ICC	 246
#define SP_SELECT_CC_FP_FCC	 247
#define SP_SELECT_CC_FP_ICC	 248
#define SP_SELECT_CC_Int_FCC	 249
#define SP_SELECT_CC_Int_ICC	 250
#define SP_SELECT_CC_QFP_FCC	 251
#define SP_SELECT_CC_QFP_ICC	 252
#define SP_SET	 253
#define SP_ADDCCri	 254
#define SP_ADDCCrr	 255
#define SP_ADDCri	 256
#define SP_ADDCrr	 257
#define SP_ADDEri	 258
#define SP_ADDErr	 259
#define SP_ADDXC	 260
#define SP_ADDXCCC	 261
#define SP_ADDXri	 262
#define SP_ADDXrr	 263
#define SP_ADDri	 264
#define SP_ADDrr	 265
#define SP_ALIGNADDR	 266
#define SP_ALIGNADDRL	 267
#define SP_ANDCCri	 268
#define SP_ANDCCrr	 269
#define SP_ANDNCCri	 270
#define SP_ANDNCCrr	 271
#define SP_ANDNri	 272
#define SP_ANDNrr	 273
#define SP_ANDXNrr	 274
#define SP_ANDXri	 275
#define SP_ANDXrr	 276
#define SP_ANDri	 277
#define SP_ANDrr	 278
#define SP_ARRAY16	 279
#define SP_ARRAY32	 280
#define SP_ARRAY8	 281
#define SP_BA	 282
#define SP_BCOND	 283
#define SP_BCONDA	 284
#define SP_BINDri	 285
#define SP_BINDrr	 286
#define SP_BMASK	 287
#define SP_BPFCC	 288
#define SP_BPFCCA	 289
#define SP_BPFCCANT	 290
#define SP_BPFCCNT	 291
#define SP_BPGEZapn	 292
#define SP_BPGEZapt	 293
#define SP_BPGEZnapn	 294
#define SP_BPGEZnapt	 295
#define SP_BPGZapn	 296
#define SP_BPGZapt	 297
#define SP_BPGZnapn	 298
#define SP_BPGZnapt	 299
#define SP_BPICC	 300
#define SP_BPICCA	 301
#define SP_BPICCANT	 302
#define SP_BPICCNT	 303
#define SP_BPLEZapn	 304
#define SP_BPLEZapt	 305
#define SP_BPLEZnapn	 306
#define SP_BPLEZnapt	 307
#define SP_BPLZapn	 308
#define SP_BPLZapt	 309
#define SP_BPLZnapn	 310
#define SP_BPLZnapt	 311
#define SP_BPNZapn	 312
#define SP_BPNZapt	 313
#define SP_BPNZnapn	 314
#define SP_BPNZnapt	 315
#define SP_BPXCC	 316
#define SP_BPXCCA	 317
#define SP_BPXCCANT	 318
#define SP_BPXCCNT	 319
#define SP_BPZapn	 320
#define SP_BPZapt	 321
#define SP_BPZnapn	 322
#define SP_BPZnapt	 323
#define SP_BSHUFFLE	 324
#define SP_CALL	 325
#define SP_CALLri	 326
#define SP_CALLrr	 327
#define SP_CASAasi10	 328
#define SP_CASArr	 329
#define SP_CASXrr	 330
#define SP_CASrr	 331
#define SP_CBCOND	 332
#define SP_CBCONDA	 333
#define SP_CMASK16	 334
#define SP_CMASK32	 335
#define SP_CMASK8	 336
#define SP_CMPri	 337
#define SP_CMPrr	 338
#define SP_EDGE16	 339
#define SP_EDGE16L	 340
#define SP_EDGE16LN	 341
#define SP_EDGE16N	 342
#define SP_EDGE32	 343
#define SP_EDGE32L	 344
#define SP_EDGE32LN	 345
#define SP_EDGE32N	 346
#define SP_EDGE8	 347
#define SP_EDGE8L	 348
#define SP_EDGE8LN	 349
#define SP_EDGE8N	 350
#define SP_FABSD	 351
#define SP_FABSQ	 352
#define SP_FABSS	 353
#define SP_FADDD	 354
#define SP_FADDQ	 355
#define SP_FADDS	 356
#define SP_FALIGNADATA	 357
#define SP_FAND	 358
#define SP_FANDNOT1	 359
#define SP_FANDNOT1S	 360
#define SP_FANDNOT2	 361
#define SP_FANDNOT2S	 362
#define SP_FANDS	 363
#define SP_FBCOND	 364
#define SP_FBCONDA	 365
#define SP_FCHKSM16	 366
#define SP_FCMPD	 367
#define SP_FCMPEQ16	 368
#define SP_FCMPEQ32	 369
#define SP_FCMPGT16	 370
#define SP_FCMPGT32	 371
#define SP_FCMPLE16	 372
#define SP_FCMPLE32	 373
#define SP_FCMPNE16	 374
#define SP_FCMPNE32	 375
#define SP_FCMPQ	 376
#define SP_FCMPS	 377
#define SP_FDIVD	 378
#define SP_FDIVQ	 379
#define SP_FDIVS	 380
#define SP_FDMULQ	 381
#define SP_FDTOI	 382
#define SP_FDTOQ	 383
#define SP_FDTOS	 384
#define SP_FDTOX	 385
#define SP_FEXPAND	 386
#define SP_FHADDD	 387
#define SP_FHADDS	 388
#define SP_FHSUBD	 389
#define SP_FHSUBS	 390
#define SP_FITOD	 391
#define SP_FITOQ	 392
#define SP_FITOS	 393
#define SP_FLCMPD	 394
#define SP_FLCMPS	 395
#define SP_FLUSH	 396
#define SP_FLUSHW	 397
#define SP_FLUSHri	 398
#define SP_FLUSHrr	 399
#define SP_FMEAN16	 400
#define SP_FMOVD	 401
#define SP_FMOVD_FCC	 402
#define SP_FMOVD_ICC	 403
#define SP_FMOVD_XCC	 404
#define SP_FMOVQ	 405
#define SP_FMOVQ_FCC	 406
#define SP_FMOVQ_ICC	 407
#define SP_FMOVQ_XCC	 408
#define SP_FMOVRGEZD	 409
#define SP_FMOVRGEZQ	 410
#define SP_FMOVRGEZS	 411
#define SP_FMOVRGZD	 412
#define SP_FMOVRGZQ	 413
#define SP_FMOVRGZS	 414
#define SP_FMOVRLEZD	 415
#define SP_FMOVRLEZQ	 416
#define SP_FMOVRLEZS	 417
#define SP_FMOVRLZD	 418
#define SP_FMOVRLZQ	 419
#define SP_FMOVRLZS	 420
#define SP_FMOVRNZD	 421
#define SP_FMOVRNZQ	 422
#define SP_FMOVRNZS	 423
#define SP_FMOVRZD	 424
#define SP_FMOVRZQ	 425
#define SP_FMOVRZS	 426
#define SP_FMOVS	 427
#define SP_FMOVS_FCC	 428
#define SP_FMOVS_ICC	 429
#define SP_FMOVS_XCC	 430
#define SP_FMUL8SUX16	 431
#define SP_FMUL8ULX16	 432
#define SP_FMUL8X16	 433
#define SP_FMUL8X16AL	 434
#define SP_FMUL8X16AU	 435
#define SP_FMULD	 436
#define SP_FMULD8SUX16	 437
#define SP_FMULD8ULX16	 438
#define SP_FMULQ	 439
#define SP_FMULS	 440
#define SP_FNADDD	 441
#define SP_FNADDS	 442
#define SP_FNAND	 443
#define SP_FNANDS	 444
#define SP_FNEGD	 445
#define SP_FNEGQ	 446
#define SP_FNEGS	 447
#define SP_FNHADDD	 448
#define SP_FNHADDS	 449
#define SP_FNMULD	 450
#define SP_FNMULS	 451
#define SP_FNOR	 452
#define SP_FNORS	 453
#define SP_FNOT1	 454
#define SP_FNOT1S	 455
#define SP_FNOT2	 456
#define SP_FNOT2S	 457
#define SP_FNSMULD	 458
#define SP_FONE	 459
#define SP_FONES	 460
#define SP_FOR	 461
#define SP_FORNOT1	 462
#define SP_FORNOT1S	 463
#define SP_FORNOT2	 464
#define SP_FORNOT2S	 465
#define SP_FORS	 466
#define SP_FPACK16	 467
#define SP_FPACK32	 468
#define SP_FPACKFIX	 469
#define SP_FPADD16	 470
#define SP_FPADD16S	 471
#define SP_FPADD32	 472
#define SP_FPADD32S	 473
#define SP_FPADD64	 474
#define SP_FPMERGE	 475
#define SP_FPSUB16	 476
#define SP_FPSUB16S	 477
#define SP_FPSUB32	 478
#define SP_FPSUB32S	 479
#define SP_FQTOD	 480
#define SP_FQTOI	 481
#define SP_FQTOS	 482
#define SP_FQTOX	 483
#define SP_FSLAS16	 484
#define SP_FSLAS32	 485
#define SP_FSLL16	 486
#define SP_FSLL32	 487
#define SP_FSMULD	 488
#define SP_FSQRTD	 489
#define SP_FSQRTQ	 490
#define SP_FSQRTS	 491
#define SP_FSRA16	 492
#define SP_FSRA32	 493
#define SP_FSRC1	 494
#define SP_FSRC1S	 495
#define SP_FSRC2	 496
#define SP_FSRC2S	 497
#define SP_FSRL16	 498
#define SP_FSRL32	 499
#define SP_FSTOD	 500
#define SP_FSTOI	 501
#define SP_FSTOQ	 502
#define SP_FSTOX	 503
#define SP_FSUBD	 504
#define SP_FSUBQ	 505
#define SP_FSUBS	 506
#define SP_FXNOR	 507
#define SP_FXNORS	 508
#define SP_FXOR	 509
#define SP_FXORS	 510
#define SP_FXTOD	 511
#define SP_FXTOQ	 512
#define SP_FXTOS	 513
#define SP_FZERO	 514
#define SP_FZEROS	 515
#define SP_JMPLri	 516
#define SP_JMPLrr	 517
#define SP_LDArr	 518
#define SP_LDCSRri	 519
#define SP_LDCSRrr	 520
#define SP_LDCri	 521
#define SP_LDCrr	 522
#define SP_LDDArr	 523
#define SP_LDDCri	 524
#define SP_LDDCrr	 525
#define SP_LDDFArr	 526
#define SP_LDDFri	 527
#define SP_LDDFrr	 528
#define SP_LDDri	 529
#define SP_LDDrr	 530
#define SP_LDFArr	 531
#define SP_LDFSRri	 532
#define SP_LDFSRrr	 533
#define SP_LDFri	 534
#define SP_LDFrr	 535
#define SP_LDQFArr	 536
#define SP_LDQFri	 537
#define SP_LDQFrr	 538
#define SP_LDSBArr	 539
#define SP_LDSBri	 540
#define SP_LDSBrr	 541
#define SP_LDSHArr	 542
#define SP_LDSHri	 543
#define SP_LDSHrr	 544
#define SP_LDSTUBArr	 545
#define SP_LDSTUBri	 546
#define SP_LDSTUBrr	 547
#define SP_LDSWri	 548
#define SP_LDSWrr	 549
#define SP_LDUBArr	 550
#define SP_LDUBri	 551
#define SP_LDUBrr	 552
#define SP_LDUHArr	 553
#define SP_LDUHri	 554
#define SP_LDUHrr	 555
#define SP_LDXFSRri	 556
#define SP_LDXFSRrr	 557
#define SP_LDXri	 558
#define SP_LDXrr	 559
#define SP_LDri	 560
#define SP_LDrr	 561
#define SP_LEAX_ADDri	 562
#define SP_LEA_ADDri	 563
#define SP_LZCNT	 564
#define SP_MEMBARi	 565
#define SP_MOVDTOX	 566
#define SP_MOVFCCri	 567
#define SP_MOVFCCrr	 568
#define SP_MOVICCri	 569
#define SP_MOVICCrr	 570
#define SP_MOVRGEZri	 571
#define SP_MOVRGEZrr	 572
#define SP_MOVRGZri	 573
#define SP_MOVRGZrr	 574
#define SP_MOVRLEZri	 575
#define SP_MOVRLEZrr	 576
#define SP_MOVRLZri	 577
#define SP_MOVRLZrr	 578
#define SP_MOVRNZri	 579
#define SP_MOVRNZrr	 580
#define SP_MOVRRZri	 581
#define SP_MOVRRZrr	 582
#define SP_MOVSTOSW	 583
#define SP_MOVSTOUW	 584
#define SP_MOVWTOS	 585
#define SP_MOVXCCri	 586
#define SP_MOVXCCrr	 587
#define SP_MOVXTOD	 588
#define SP_MULSCCri	 589
#define SP_MULSCCrr	 590
#define SP_MULXri	 591
#define SP_MULXrr	 592
#define SP_NOP	 593
#define SP_ORCCri	 594
#define SP_ORCCrr	 595
#define SP_ORNCCri	 596
#define SP_ORNCCrr	 597
#define SP_ORNri	 598
#define SP_ORNrr	 599
#define SP_ORXNrr	 600
#define SP_ORXri	 601
#define SP_ORXrr	 602
#define SP_ORri	 603
#define SP_ORrr	 604
#define SP_PDIST	 605
#define SP_PDISTN	 606
#define SP_POPCrr	 607
#define SP_PREFETCHi	 608
#define SP_PREFETCHr	 609
#define SP_PWRPSRri	 610
#define SP_PWRPSRrr	 611
#define SP_RDASR	 612
#define SP_RDPC	 613
#define SP_RDPR	 614
#define SP_RDPSR	 615
#define SP_RDTBR	 616
#define SP_RDWIM	 617
#define SP_RESTOREri	 618
#define SP_RESTORErr	 619
#define SP_RET	 620
#define SP_RETL	 621
#define SP_RETTri	 622
#define SP_RETTrr	 623
#define SP_SAVEri	 624
#define SP_SAVErr	 625
#define SP_SDIVCCri	 626
#define SP_SDIVCCrr	 627
#define SP_SDIVXri	 628
#define SP_SDIVXrr	 629
#define SP_SDIVri	 630
#define SP_SDIVrr	 631
#define SP_SETHIXi	 632
#define SP_SETHIi	 633
#define SP_SHUTDOWN	 634
#define SP_SIAM	 635
#define SP_SIR	 636
#define SP_SLLXri	 637
#define SP_SLLXrr	 638
#define SP_SLLri	 639
#define SP_SLLrr	 640
#define SP_SMACri	 641
#define SP_SMACrr	 642
#define SP_SMULCCri	 643
#define SP_SMULCCrr	 644
#define SP_SMULri	 645
#define SP_SMULrr	 646
#define SP_SRAXri	 647
#define SP_SRAXrr	 648
#define SP_SRAri	 649
#define SP_SRArr	 650
#define SP_SRLXri	 651
#define SP_SRLXrr	 652
#define SP_SRLri	 653
#define SP_SRLrr	 654
#define SP_STArr	 655
#define SP_STBAR	 656
#define SP_STBArr	 657
#define SP_STBri	 658
#define SP_STBrr	 659
#define SP_STCSRri	 660
#define SP_STCSRrr	 661
#define SP_STCri	 662
#define SP_STCrr	 663
#define SP_STDArr	 664
#define SP_STDCQri	 665
#define SP_STDCQrr	 666
#define SP_STDCri	 667
#define SP_STDCrr	 668
#define SP_STDFArr	 669
#define SP_STDFQri	 670
#define SP_STDFQrr	 671
#define SP_STDFri	 672
#define SP_STDFrr	 673
#define SP_STDri	 674
#define SP_STDrr	 675
#define SP_STFArr	 676
#define SP_STFSRri	 677
#define SP_STFSRrr	 678
#define SP_STFri	 679
#define SP_STFrr	 680
#define SP_STHArr	 681
#define SP_STHri	 682
#define SP_STHrr	 683
#define SP_STQFArr	 684
#define SP_STQFri	 685
#define SP_STQFrr	 686
#define SP_STXFSRri	 687
#define SP_STXFSRrr	 688
#define SP_STXri	 689
#define SP_STXrr	 690
#define SP_STri	 691
#define SP_STrr	 692
#define SP_SUBCCri	 693
#define SP_SUBCCrr	 694
#define SP_SUBCri	 695
#define SP_SUBCrr	 696
#define SP_SUBEri	 697
#define SP_SUBErr	 698
#define SP_SUBXri	 699
#define SP_SUBXrr	 700
#define SP_SUBri	 701
#define SP_SUBrr	 702
#define SP_SWAPArr	 703
#define SP_SWAPri	 704
#define SP_SWAPrr	 705
#define SP_TA1	 706
#define SP_TA3	 707
#define SP_TA5	 708
#define SP_TADDCCTVri	 709
#define SP_TADDCCTVrr	 710
#define SP_TADDCCri	 711
#define SP_TADDCCrr	 712
#define SP_TICCri	 713
#define SP_TICCrr	 714
#define SP_TLS_ADDXrr	 715
#define SP_TLS_ADDrr	 716
#define SP_TLS_CALL	 717
#define SP_TLS_LDXrr	 718
#define SP_TLS_LDrr	 719
#define SP_TRAPri	 720
#define SP_TRAPrr	 721
#define SP_TSUBCCTVri	 722
#define SP_TSUBCCTVrr	 723
#define SP_TSUBCCri	 724
#define SP_TSUBCCrr	 725
#define SP_TXCCri	 726
#define SP_TXCCrr	 727
#define SP_UDIVCCri	 728
#define SP_UDIVCCrr	 729
#define SP_UDIVXri	 730
#define SP_UDIVXrr	 731
#define SP_UDIVri	 732
#define SP_UDIVrr	 733
#define SP_UMACri	 734
#define SP_UMACrr	 735
#define SP_UMULCCri	 736
#define SP_UMULCCrr	 737
#define SP_UMULXHI	 738
#define SP_UMULri	 739
#define SP_UMULrr	 740
#define SP_UNIMP	 741
#define SP_V9FCMPD	 742
#define SP_V9FCMPED	 743
#define SP_V9FCMPEQ	 744
#define SP_V9FCMPES	 745
#define SP_V9FCMPQ	 746
#define SP_V9FCMPS	 747
#define SP_V9FMOVD_FCC	 748
#define SP_V9FMOVQ_FCC	 749
#define SP_V9FMOVS_FCC	 750
#define SP_V9MOVFCCri	 751
#define SP_V9MOVFCCrr	 752
#define SP_WRASRri	 753
#define SP_WRASRrr	 754
#define SP_WRPRri	 755
#define SP_WRPRrr	 756
#define SP_WRPSRri	 757
#define SP_WRPSRrr	 758
#define SP_WRTBRri	 759
#define SP_WRTBRrr	 760
#define SP_WRWIMri	 761
#define SP_WRWIMrr	 762
#define SP_XMULX	 763
#define SP_XMULXHI	 764
#define SP_XNORCCri	 765
#define SP_XNORCCrr	 766
#define SP_XNORXrr	 767
#define SP_XNORri	 768
#define SP_XNORrr	 769
#define SP_XORCCri	 770
#define SP_XORCCrr	 771
#define SP_XORXri	 772
#define SP_XORXrr	 773
#define SP_XORri	 774
#define SP_XORrr	 775
#endif // GET_INSTRINFO_ENUM

#ifdef GET_REGINFO_EXTRA
#undef GET_REGINFO_EXTRA

// Subregister indices

enum {
  NoSubRegister,
  SP_sub_even,	// 1
    SP_sub_even64,	// 2
    SP_sub_odd,	// 3
    SP_sub_odd64,	// 4
    SP_sub_odd64_then_sub_even,	// 5
    SP_sub_odd64_then_sub_odd,	// 6
  SP_NUM_TARGET_SUBREGS
};
#endif // GET_REGINFO_EXTRA


#ifdef GET_REGINFO_MC_DESC
#undef GET_REGINFO_MC_DESC



static const MCPhysReg SparcRegDiffLists[] = {
  /* 0 */ 64868, 1, 1, 1, 0,
  /* 5 */ 32, 1, 0,
  /* 8 */ 65436, 32, 1, 65504, 33, 1, 0,
  /* 15 */ 34, 1, 0,
  /* 18 */ 65437, 34, 1, 65502, 35, 1, 0,
  /* 25 */ 36, 1, 0,
  /* 28 */ 65438, 36, 1, 65500, 37, 1, 0,
  /* 35 */ 38, 1, 0,
  /* 38 */ 65439, 38, 1, 65498, 39, 1, 0,
  /* 45 */ 40, 1, 0,
  /* 48 */ 65440, 40, 1, 65496, 41, 1, 0,
  /* 55 */ 42, 1, 0,
  /* 58 */ 65441, 42, 1, 65494, 43, 1, 0,
  /* 65 */ 44, 1, 0,
  /* 68 */ 65442, 44, 1, 65492, 45, 1, 0,
  /* 75 */ 46, 1, 0,
  /* 78 */ 65443, 46, 1, 65490, 47, 1, 0,
  /* 85 */ 65182, 1, 0,
  /* 88 */ 65234, 1, 0,
  /* 91 */ 65262, 1, 0,
  /* 94 */ 65388, 1, 0,
  /* 97 */ 65389, 1, 0,
  /* 100 */ 65390, 1, 0,
  /* 103 */ 65391, 1, 0,
  /* 106 */ 65392, 1, 0,
  /* 109 */ 65393, 1, 0,
  /* 112 */ 65394, 1, 0,
  /* 115 */ 65395, 1, 0,
  /* 118 */ 65396, 1, 0,
  /* 121 */ 65397, 1, 0,
  /* 124 */ 65398, 1, 0,
  /* 127 */ 65399, 1, 0,
  /* 130 */ 65400, 1, 0,
  /* 133 */ 65401, 1, 0,
  /* 136 */ 65402, 1, 0,
  /* 139 */ 65403, 1, 0,
  /* 142 */ 65444, 1, 0,
  /* 145 */ 65445, 1, 0,
  /* 148 */ 65446, 1, 0,
  /* 151 */ 65447, 1, 0,
  /* 154 */ 65448, 1, 0,
  /* 157 */ 65449, 1, 0,
  /* 160 */ 65450, 1, 0,
  /* 163 */ 65451, 1, 0,
  /* 166 */ 65472, 1, 0,
  /* 169 */ 65473, 1, 0,
  /* 172 */ 65474, 1, 0,
  /* 175 */ 65475, 1, 0,
  /* 178 */ 65476, 1, 0,
  /* 181 */ 65477, 1, 0,
  /* 184 */ 65478, 1, 0,
  /* 187 */ 65479, 1, 0,
  /* 190 */ 65480, 1, 0,
  /* 193 */ 65481, 1, 0,
  /* 196 */ 65482, 1, 0,
  /* 199 */ 65483, 1, 0,
  /* 202 */ 65484, 1, 0,
  /* 205 */ 65485, 1, 0,
  /* 208 */ 65486, 1, 0,
  /* 211 */ 65487, 1, 0,
  /* 214 */ 15, 0,
  /* 216 */ 48, 0,
  /* 218 */ 49, 0,
  /* 220 */ 50, 0,
  /* 222 */ 51, 0,
  /* 224 */ 52, 0,
  /* 226 */ 53, 0,
  /* 228 */ 54, 0,
  /* 230 */ 55, 0,
  /* 232 */ 56, 0,
  /* 234 */ 57, 0,
  /* 236 */ 58, 0,
  /* 238 */ 59, 0,
  /* 240 */ 60, 0,
  /* 242 */ 61, 0,
  /* 244 */ 62, 0,
  /* 246 */ 63, 0,
  /* 248 */ 64, 0,
  /* 250 */ 84, 0,
  /* 252 */ 85, 0,
  /* 254 */ 86, 0,
  /* 256 */ 87, 0,
  /* 258 */ 88, 0,
  /* 260 */ 89, 0,
  /* 262 */ 90, 0,
  /* 264 */ 91, 0,
  /* 266 */ 65488, 92, 0,
  /* 269 */ 65489, 92, 0,
  /* 272 */ 65489, 93, 0,
  /* 275 */ 65490, 93, 0,
  /* 278 */ 65491, 93, 0,
  /* 281 */ 65491, 94, 0,
  /* 284 */ 65492, 94, 0,
  /* 287 */ 65493, 94, 0,
  /* 290 */ 65493, 95, 0,
  /* 293 */ 65494, 95, 0,
  /* 296 */ 65495, 95, 0,
  /* 299 */ 65495, 96, 0,
  /* 302 */ 65496, 96, 0,
  /* 305 */ 65497, 96, 0,
  /* 308 */ 65497, 97, 0,
  /* 311 */ 65498, 97, 0,
  /* 314 */ 65499, 97, 0,
  /* 317 */ 65499, 98, 0,
  /* 320 */ 65500, 98, 0,
  /* 323 */ 65501, 98, 0,
  /* 326 */ 65501, 99, 0,
  /* 329 */ 65502, 99, 0,
  /* 332 */ 65503, 99, 0,
  /* 335 */ 65503, 100, 0,
  /* 338 */ 65504, 100, 0,
  /* 341 */ 132, 0,
  /* 343 */ 133, 0,
  /* 345 */ 134, 0,
  /* 347 */ 135, 0,
  /* 349 */ 136, 0,
  /* 351 */ 137, 0,
  /* 353 */ 138, 0,
  /* 355 */ 139, 0,
  /* 357 */ 140, 0,
  /* 359 */ 141, 0,
  /* 361 */ 142, 0,
  /* 363 */ 143, 0,
  /* 365 */ 144, 0,
  /* 367 */ 145, 0,
  /* 369 */ 146, 0,
  /* 371 */ 147, 0,
  /* 373 */ 148, 0,
  /* 375 */ 65503, 0,
  /* 377 */ 65519, 0,
  /* 379 */ 65535, 0,
};

static const uint16_t SparcSubRegIdxLists[] = {
  /* 0 */ 1, 3, 0,
  /* 3 */ 2, 4, 0,
  /* 6 */ 2, 1, 3, 4, 5, 6, 0,
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
static const char SparcRegStrings[] = {
  /* 0 */ "C10\0"
  /* 4 */ "D10\0"
  /* 8 */ "F10\0"
  /* 12 */ "Q10\0"
  /* 16 */ "ASR10\0"
  /* 22 */ "C20\0"
  /* 26 */ "D20\0"
  /* 30 */ "F20\0"
  /* 34 */ "ASR20\0"
  /* 40 */ "C30\0"
  /* 44 */ "D30\0"
  /* 48 */ "F30\0"
  /* 52 */ "ASR30\0"
  /* 58 */ "FCC0\0"
  /* 63 */ "D0\0"
  /* 66 */ "F0\0"
  /* 69 */ "G0\0"
  /* 72 */ "I0\0"
  /* 75 */ "L0\0"
  /* 78 */ "O0\0"
  /* 81 */ "Q0\0"
  /* 84 */ "C10_C11\0"
  /* 92 */ "D11\0"
  /* 96 */ "F11\0"
  /* 100 */ "Q11\0"
  /* 104 */ "ASR11\0"
  /* 110 */ "C20_C21\0"
  /* 118 */ "D21\0"
  /* 122 */ "F21\0"
  /* 126 */ "ASR21\0"
  /* 132 */ "C30_C31\0"
  /* 140 */ "D31\0"
  /* 144 */ "F31\0"
  /* 148 */ "ASR31\0"
  /* 154 */ "FCC1\0"
  /* 159 */ "C0_C1\0"
  /* 165 */ "D1\0"
  /* 168 */ "F1\0"
  /* 171 */ "G0_G1\0"
  /* 177 */ "I0_I1\0"
  /* 183 */ "L0_L1\0"
  /* 189 */ "O0_O1\0"
  /* 195 */ "Q1\0"
  /* 198 */ "ASR1\0"
  /* 203 */ "C12\0"
  /* 207 */ "D12\0"
  /* 211 */ "F12\0"
  /* 215 */ "Q12\0"
  /* 219 */ "ASR12\0"
  /* 225 */ "C22\0"
  /* 229 */ "D22\0"
  /* 233 */ "F22\0"
  /* 237 */ "ASR22\0"
  /* 243 */ "FCC2\0"
  /* 248 */ "D2\0"
  /* 251 */ "F2\0"
  /* 254 */ "G2\0"
  /* 257 */ "I2\0"
  /* 260 */ "L2\0"
  /* 263 */ "O2\0"
  /* 266 */ "Q2\0"
  /* 269 */ "ASR2\0"
  /* 274 */ "C12_C13\0"
  /* 282 */ "D13\0"
  /* 286 */ "F13\0"
  /* 290 */ "Q13\0"
  /* 294 */ "ASR13\0"
  /* 300 */ "C22_C23\0"
  /* 308 */ "D23\0"
  /* 312 */ "F23\0"
  /* 316 */ "ASR23\0"
  /* 322 */ "FCC3\0"
  /* 327 */ "C2_C3\0"
  /* 333 */ "D3\0"
  /* 336 */ "F3\0"
  /* 339 */ "G2_G3\0"
  /* 345 */ "I2_I3\0"
  /* 351 */ "L2_L3\0"
  /* 357 */ "O2_O3\0"
  /* 363 */ "Q3\0"
  /* 366 */ "ASR3\0"
  /* 371 */ "C14\0"
  /* 375 */ "D14\0"
  /* 379 */ "F14\0"
  /* 383 */ "Q14\0"
  /* 387 */ "ASR14\0"
  /* 393 */ "C24\0"
  /* 397 */ "D24\0"
  /* 401 */ "F24\0"
  /* 405 */ "ASR24\0"
  /* 411 */ "C4\0"
  /* 414 */ "D4\0"
  /* 417 */ "F4\0"
  /* 420 */ "G4\0"
  /* 423 */ "I4\0"
  /* 426 */ "L4\0"
  /* 429 */ "O4\0"
  /* 432 */ "Q4\0"
  /* 435 */ "ASR4\0"
  /* 440 */ "C14_C15\0"
  /* 448 */ "D15\0"
  /* 452 */ "F15\0"
  /* 456 */ "Q15\0"
  /* 460 */ "ASR15\0"
  /* 466 */ "C24_C25\0"
  /* 474 */ "D25\0"
  /* 478 */ "F25\0"
  /* 482 */ "ASR25\0"
  /* 488 */ "C4_C5\0"
  /* 494 */ "D5\0"
  /* 497 */ "F5\0"
  /* 500 */ "G4_G5\0"
  /* 506 */ "I4_I5\0"
  /* 512 */ "L4_L5\0"
  /* 518 */ "O4_O5\0"
  /* 524 */ "Q5\0"
  /* 527 */ "ASR5\0"
  /* 532 */ "C16\0"
  /* 536 */ "D16\0"
  /* 540 */ "F16\0"
  /* 544 */ "ASR16\0"
  /* 550 */ "C26\0"
  /* 554 */ "D26\0"
  /* 558 */ "F26\0"
  /* 562 */ "ASR26\0"
  /* 568 */ "C6\0"
  /* 571 */ "D6\0"
  /* 574 */ "F6\0"
  /* 577 */ "G6\0"
  /* 580 */ "I6\0"
  /* 583 */ "L6\0"
  /* 586 */ "O6\0"
  /* 589 */ "Q6\0"
  /* 592 */ "ASR6\0"
  /* 597 */ "C16_C17\0"
  /* 605 */ "D17\0"
  /* 609 */ "F17\0"
  /* 613 */ "ASR17\0"
  /* 619 */ "C26_C27\0"
  /* 627 */ "D27\0"
  /* 631 */ "F27\0"
  /* 635 */ "ASR27\0"
  /* 641 */ "C6_C7\0"
  /* 647 */ "D7\0"
  /* 650 */ "F7\0"
  /* 653 */ "G6_G7\0"
  /* 659 */ "I6_I7\0"
  /* 665 */ "L6_L7\0"
  /* 671 */ "O6_O7\0"
  /* 677 */ "Q7\0"
  /* 680 */ "ASR7\0"
  /* 685 */ "C18\0"
  /* 689 */ "D18\0"
  /* 693 */ "F18\0"
  /* 697 */ "ASR18\0"
  /* 703 */ "C28\0"
  /* 707 */ "D28\0"
  /* 711 */ "F28\0"
  /* 715 */ "ASR28\0"
  /* 721 */ "C8\0"
  /* 724 */ "D8\0"
  /* 727 */ "F8\0"
  /* 730 */ "Q8\0"
  /* 733 */ "ASR8\0"
  /* 738 */ "C18_C19\0"
  /* 746 */ "D19\0"
  /* 750 */ "F19\0"
  /* 754 */ "ASR19\0"
  /* 760 */ "C28_C29\0"
  /* 768 */ "D29\0"
  /* 772 */ "F29\0"
  /* 776 */ "ASR29\0"
  /* 782 */ "C8_C9\0"
  /* 788 */ "D9\0"
  /* 791 */ "F9\0"
  /* 794 */ "Q9\0"
  /* 797 */ "ASR9\0"
  /* 802 */ "TBA\0"
  /* 806 */ "ICC\0"
  /* 810 */ "TNPC\0"
  /* 815 */ "TPC\0"
  /* 819 */ "CANRESTORE\0"
  /* 830 */ "PSTATE\0"
  /* 837 */ "TSTATE\0"
  /* 844 */ "WSTATE\0"
  /* 851 */ "CANSAVE\0"
  /* 859 */ "TICK\0"
  /* 864 */ "PIL\0"
  /* 868 */ "TL\0"
  /* 871 */ "WIM\0"
  /* 875 */ "CLEANWIN\0"
  /* 884 */ "OTHERWIN\0"
  /* 893 */ "CWP\0"
  /* 897 */ "FQ\0"
  /* 900 */ "CPQ\0"
  /* 904 */ "TBR\0"
  /* 908 */ "FSR\0"
  /* 912 */ "CPSR\0"
  /* 917 */ "TT\0"
  /* 920 */ "Y\0"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

static const MCRegisterDesc SparcRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0 },
  { 819, 4, 4, 2, 6065, 3 },
  { 851, 4, 4, 2, 6065, 84 },
  { 875, 4, 4, 2, 6065, 334 },
  { 900, 4, 4, 2, 6065, 121 },
  { 912, 4, 4, 2, 6065, 351 },
  { 893, 4, 4, 2, 6065, 279 },
  { 897, 4, 4, 2, 6065, 3 },
  { 908, 4, 4, 2, 6065, 336 },
  { 806, 4, 4, 2, 6065, 3 },
  { 884, 4, 4, 2, 6065, 36 },
  { 812, 4, 4, 2, 6065, 349 },
  { 864, 4, 4, 2, 6065, 252 },
  { 913, 4, 4, 2, 6065, 258 },
  { 830, 4, 4, 2, 6065, 79 },
  { 802, 4, 4, 2, 6065, 6 },
  { 904, 4, 4, 2, 6065, 3 },
  { 859, 4, 4, 2, 6065, 273 },
  { 868, 4, 4, 2, 6065, 16 },
  { 810, 4, 4, 2, 6065, 275 },
  { 815, 4, 4, 2, 6065, 277 },
  { 837, 4, 4, 2, 6065, 126 },
  { 917, 4, 4, 2, 6065, 128 },
  { 871, 4, 4, 2, 6065, 130 },
  { 844, 4, 4, 2, 6065, 3 },
  { 920, 4, 4, 2, 6065, 3 },
  { 198, 4, 4, 2, 6065, 3 },
  { 269, 4, 4, 2, 6065, 330 },
  { 366, 4, 4, 2, 6065, 332 },
  { 435, 4, 4, 2, 6065, 20 },
  { 527, 4, 4, 2, 6065, 349 },
  { 592, 4, 4, 2, 6065, 79 },
  { 680, 4, 4, 2, 6065, 132 },
  { 733, 4, 4, 2, 6065, 34 },
  { 797, 4, 4, 2, 6065, 117 },
  { 16, 4, 4, 2, 6065, 60 },
  { 104, 4, 4, 2, 6065, 43 },
  { 219, 4, 4, 2, 6065, 195 },
  { 294, 4, 4, 2, 6065, 264 },
  { 387, 4, 4, 2, 6065, 79 },
  { 460, 4, 4, 2, 6065, 84 },
  { 544, 4, 4, 2, 6065, 262 },
  { 613, 4, 4, 2, 6065, 3 },
  { 697, 4, 4, 2, 6065, 260 },
  { 754, 4, 4, 2, 6065, 3 },
  { 34, 4, 4, 2, 6065, 3 },
  { 126, 4, 4, 2, 6065, 311 },
  { 237, 4, 4, 2, 6065, 36 },
  { 316, 4, 4, 2, 6065, 73 },
  { 405, 4, 4, 2, 6065, 269 },
  { 482, 4, 4, 2, 6065, 349 },
  { 562, 4, 4, 2, 6065, 313 },
  { 635, 4, 4, 2, 6065, 315 },
  { 715, 4, 4, 2, 6065, 36 },
  { 776, 4, 4, 2, 6065, 256 },
  { 52, 4, 4, 2, 6065, 3 },
  { 148, 4, 4, 2, 6065, 84 },
  { 60, 4, 373, 2, 6065, 320 },
  { 156, 4, 371, 2, 6065, 3 },
  { 245, 4, 371, 2, 6065, 62 },
  { 324, 4, 369, 2, 6065, 349 },
  { 411, 4, 369, 2, 6065, 338 },
  { 491, 4, 367, 2, 6065, 269 },
  { 568, 4, 367, 2, 6065, 64 },
  { 644, 4, 365, 2, 6065, 328 },
  { 721, 4, 365, 2, 6065, 338 },
  { 785, 4, 363, 2, 6065, 84 },
  { 0, 4, 363, 2, 6065, 60 },
  { 88, 4, 361, 2, 6065, 84 },
  { 203, 4, 361, 2, 6065, 3 },
  { 278, 4, 359, 2, 6065, 84 },
  { 371, 4, 359, 2, 6065, 3 },
  { 444, 4, 357, 2, 6065, 84 },
  { 532, 4, 357, 2, 6065, 283 },
  { 601, 4, 355, 2, 6065, 281 },
  { 685, 4, 355, 2, 6065, 36 },
  { 742, 4, 353, 2, 6065, 3 },
  { 22, 4, 353, 2, 6065, 84 },
  { 114, 4, 351, 2, 6065, 288 },
  { 225, 4, 351, 2, 6065, 81 },
  { 304, 4, 349, 2, 6065, 6 },
  { 393, 4, 349, 2, 6065, 3 },
  { 470, 4, 347, 2, 6065, 290 },
  { 550, 4, 347, 2, 6065, 84 },
  { 623, 4, 345, 2, 6065, 292 },
  { 703, 4, 345, 2, 6065, 75 },
  { 764, 4, 343, 2, 6065, 14 },
  { 40, 4, 343, 2, 6065, 84 },
  { 136, 4, 341, 2, 6065, 271 },
  { 63, 5, 336, 0, 2370, 89 },
  { 165, 12, 327, 0, 2370, 52 },
  { 248, 15, 327, 0, 2370, 302 },
  { 333, 22, 318, 0, 2370, 97 },
  { 414, 25, 318, 0, 2370, 40 },
  { 494, 32, 309, 0, 2370, 299 },
  { 571, 35, 309, 0, 2370, 100 },
  { 647, 42, 300, 0, 2370, 305 },
  { 724, 45, 300, 0, 2370, 322 },
  { 788, 52, 291, 0, 2370, 325 },
  { 4, 55, 291, 0, 2370, 317 },
  { 92, 62, 282, 0, 2370, 346 },
  { 207, 65, 282, 0, 2370, 72 },
  { 282, 72, 273, 0, 2370, 308 },
  { 375, 75, 273, 0, 2370, 10 },
  { 448, 82, 267, 0, 2370, 108 },
  { 536, 4, 267, 2, 3425, 138 },
  { 605, 4, 264, 2, 3425, 84 },
  { 689, 4, 264, 2, 3425, 254 },
  { 746, 4, 262, 2, 3425, 3 },
  { 26, 4, 262, 2, 3425, 3 },
  { 118, 4, 260, 2, 3425, 140 },
  { 229, 4, 260, 2, 3425, 84 },
  { 308, 4, 258, 2, 3425, 142 },
  { 397, 4, 258, 2, 3425, 84 },
  { 474, 4, 256, 2, 3425, 3 },
  { 554, 4, 256, 2, 3425, 79 },
  { 627, 4, 254, 2, 3425, 144 },
  { 707, 4, 254, 2, 3425, 84 },
  { 768, 4, 252, 2, 3425, 146 },
  { 44, 4, 252, 2, 3425, 136 },
  { 140, 4, 250, 2, 3425, 84 },
  { 66, 4, 338, 2, 6001, 150 },
  { 168, 4, 335, 2, 6001, 38 },
  { 251, 4, 332, 2, 6001, 103 },
  { 336, 4, 329, 2, 6001, 148 },
  { 417, 4, 329, 2, 6001, 148 },
  { 497, 4, 326, 2, 6001, 84 },
  { 574, 4, 323, 2, 6001, 84 },
  { 650, 4, 320, 2, 6001, 8 },
  { 727, 4, 320, 2, 6001, 84 },
  { 791, 4, 317, 2, 6001, 155 },
  { 8, 4, 314, 2, 6001, 132 },
  { 96, 4, 311, 2, 6001, 3 },
  { 211, 4, 311, 2, 6001, 349 },
  { 286, 4, 308, 2, 6001, 3 },
  { 379, 4, 305, 2, 6001, 157 },
  { 452, 4, 302, 2, 6001, 159 },
  { 540, 4, 302, 2, 6001, 166 },
  { 609, 4, 299, 2, 6001, 36 },
  { 693, 4, 296, 2, 6001, 3 },
  { 750, 4, 293, 2, 6001, 6 },
  { 30, 4, 293, 2, 6001, 3 },
  { 122, 4, 290, 2, 6001, 73 },
  { 233, 4, 287, 2, 6001, 168 },
  { 312, 4, 284, 2, 6001, 84 },
  { 401, 4, 284, 2, 6001, 170 },
  { 478, 4, 281, 2, 6001, 84 },
  { 558, 4, 278, 2, 6001, 70 },
  { 631, 4, 275, 2, 6001, 77 },
  { 711, 4, 275, 2, 6001, 3 },
  { 772, 4, 272, 2, 6001, 172 },
  { 48, 4, 269, 2, 6001, 45 },
  { 144, 4, 266, 2, 6001, 38 },
  { 58, 4, 4, 2, 6033, 58 },
  { 154, 4, 4, 2, 6033, 174 },
  { 243, 4, 4, 2, 6033, 3 },
  { 322, 4, 4, 2, 6033, 50 },
  { 69, 4, 248, 2, 6033, 178 },
  { 174, 4, 246, 2, 6033, 176 },
  { 254, 4, 246, 2, 6033, 134 },
  { 342, 4, 244, 2, 6033, 111 },
  { 420, 4, 244, 2, 6033, 115 },
  { 503, 4, 242, 2, 6033, 119 },
  { 577, 4, 242, 2, 6033, 3 },
  { 656, 4, 240, 2, 6033, 3 },
  { 72, 4, 240, 2, 6033, 3 },
  { 180, 4, 238, 2, 6033, 113 },
  { 257, 4, 238, 2, 6033, 3 },
  { 348, 4, 236, 2, 6033, 180 },
  { 423, 4, 236, 2, 6033, 193 },
  { 509, 4, 234, 2, 6033, 184 },
  { 580, 4, 234, 2, 6033, 18 },
  { 662, 4, 232, 2, 6033, 14 },
  { 75, 4, 232, 2, 6033, 197 },
  { 186, 4, 230, 2, 6033, 20 },
  { 260, 4, 230, 2, 6033, 182 },
  { 354, 4, 228, 2, 6033, 3 },
  { 426, 4, 228, 2, 6033, 191 },
  { 515, 4, 226, 2, 6033, 3 },
  { 583, 4, 226, 2, 6033, 201 },
  { 668, 4, 224, 2, 6033, 199 },
  { 78, 4, 224, 2, 6033, 66 },
  { 192, 4, 222, 2, 6033, 203 },
  { 263, 4, 222, 2, 6033, 11 },
  { 360, 4, 220, 2, 6033, 68 },
  { 429, 4, 220, 2, 6033, 3 },
  { 521, 4, 218, 2, 6033, 207 },
  { 586, 4, 218, 2, 6033, 205 },
  { 674, 4, 216, 2, 6033, 3 },
  { 81, 8, 4, 6, 4, 209 },
  { 195, 18, 4, 6, 4, 214 },
  { 266, 28, 4, 6, 4, 25 },
  { 363, 38, 4, 6, 4, 0 },
  { 432, 48, 4, 6, 4, 294 },
  { 524, 58, 4, 6, 4, 161 },
  { 589, 68, 4, 6, 4, 92 },
  { 677, 78, 4, 6, 4, 186 },
  { 730, 142, 4, 3, 1458, 285 },
  { 794, 145, 4, 3, 1458, 94 },
  { 12, 148, 4, 3, 1458, 219 },
  { 100, 151, 4, 3, 1458, 222 },
  { 215, 154, 4, 3, 1458, 27 },
  { 290, 157, 4, 3, 1458, 2 },
  { 383, 160, 4, 3, 1458, 225 },
  { 456, 163, 4, 3, 1458, 228 },
  { 159, 94, 4, 0, 1362, 2 },
  { 327, 97, 4, 0, 1362, 30 },
  { 488, 100, 4, 0, 1362, 231 },
  { 641, 103, 4, 0, 1362, 123 },
  { 782, 106, 4, 0, 1362, 22 },
  { 84, 109, 4, 0, 1362, 13 },
  { 274, 112, 4, 0, 1362, 89 },
  { 440, 115, 4, 0, 1362, 89 },
  { 597, 118, 4, 0, 1362, 234 },
  { 738, 121, 4, 0, 1362, 105 },
  { 110, 124, 4, 0, 1362, 266 },
  { 300, 127, 4, 0, 1362, 152 },
  { 466, 130, 4, 0, 1362, 2 },
  { 619, 133, 4, 0, 1362, 86 },
  { 760, 136, 4, 0, 1362, 343 },
  { 132, 139, 4, 0, 1362, 2 },
  { 171, 166, 4, 0, 1410, 55 },
  { 339, 169, 4, 0, 1410, 10 },
  { 500, 172, 4, 0, 1410, 33 },
  { 653, 175, 4, 0, 1410, 89 },
  { 177, 178, 4, 0, 1410, 237 },
  { 345, 181, 4, 0, 1410, 89 },
  { 506, 184, 4, 0, 1410, 240 },
  { 659, 187, 4, 0, 1410, 89 },
  { 183, 190, 4, 0, 1410, 243 },
  { 351, 193, 4, 0, 1410, 340 },
  { 512, 196, 4, 0, 1410, 22 },
  { 665, 199, 4, 0, 1410, 47 },
  { 189, 202, 4, 0, 1410, 5 },
  { 357, 205, 4, 0, 1410, 246 },
  { 518, 208, 4, 0, 1410, 83 },
  { 671, 211, 4, 0, 1410, 249 },
};

  // FCCRegs Register Class...
  static const MCPhysReg FCCRegs[] = {
    SP_FCC0, SP_FCC1, SP_FCC2, SP_FCC3, 
  };

  // FCCRegs Bit set.
  static const uint8_t FCCRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 
  };

  // ASRRegs Register Class...
  static const MCPhysReg ASRRegs[] = {
    SP_Y, SP_ASR1, SP_ASR2, SP_ASR3, SP_ASR4, SP_ASR5, SP_ASR6, SP_ASR7, SP_ASR8, SP_ASR9, SP_ASR10, SP_ASR11, SP_ASR12, SP_ASR13, SP_ASR14, SP_ASR15, SP_ASR16, SP_ASR17, SP_ASR18, SP_ASR19, SP_ASR20, SP_ASR21, SP_ASR22, SP_ASR23, SP_ASR24, SP_ASR25, SP_ASR26, SP_ASR27, SP_ASR28, SP_ASR29, SP_ASR30, SP_ASR31, 
  };

  // ASRRegs Bit set.
  static const uint8_t ASRRegsBits[] = {
    0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // CoprocRegs Register Class...
  static const MCPhysReg CoprocRegs[] = {
    SP_C0, SP_C1, SP_C2, SP_C3, SP_C4, SP_C5, SP_C6, SP_C7, SP_C8, SP_C9, SP_C10, SP_C11, SP_C12, SP_C13, SP_C14, SP_C15, SP_C16, SP_C17, SP_C18, SP_C19, SP_C20, SP_C21, SP_C22, SP_C23, SP_C24, SP_C25, SP_C26, SP_C27, SP_C28, SP_C29, SP_C30, SP_C31, 
  };

  // CoprocRegs Bit set.
  static const uint8_t CoprocRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // FPRegs Register Class...
  static const MCPhysReg FPRegs[] = {
    SP_F0, SP_F1, SP_F2, SP_F3, SP_F4, SP_F5, SP_F6, SP_F7, SP_F8, SP_F9, SP_F10, SP_F11, SP_F12, SP_F13, SP_F14, SP_F15, SP_F16, SP_F17, SP_F18, SP_F19, SP_F20, SP_F21, SP_F22, SP_F23, SP_F24, SP_F25, SP_F26, SP_F27, SP_F28, SP_F29, SP_F30, SP_F31, 
  };

  // FPRegs Bit set.
  static const uint8_t FPRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // IntRegs Register Class...
  static const MCPhysReg IntRegs[] = {
    SP_I0, SP_I1, SP_I2, SP_I3, SP_I4, SP_I5, SP_I6, SP_I7, SP_G0, SP_G1, SP_G2, SP_G3, SP_G4, SP_G5, SP_G6, SP_G7, SP_L0, SP_L1, SP_L2, SP_L3, SP_L4, SP_L5, SP_L6, SP_L7, SP_O0, SP_O1, SP_O2, SP_O3, SP_O4, SP_O5, SP_O6, SP_O7, 
  };

  // IntRegs Bit set.
  static const uint8_t IntRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x1f, 
  };

  // DFPRegs Register Class...
  static const MCPhysReg DFPRegs[] = {
    SP_D0, SP_D1, SP_D2, SP_D3, SP_D4, SP_D5, SP_D6, SP_D7, SP_D8, SP_D9, SP_D10, SP_D11, SP_D12, SP_D13, SP_D14, SP_D15, SP_D16, SP_D17, SP_D18, SP_D19, SP_D20, SP_D21, SP_D22, SP_D23, SP_D24, SP_D25, SP_D26, SP_D27, SP_D28, SP_D29, SP_D30, SP_D31, 
  };

  // DFPRegs Bit set.
  static const uint8_t DFPRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // I64Regs Register Class...
  static const MCPhysReg I64Regs[] = {
    SP_I0, SP_I1, SP_I2, SP_I3, SP_I4, SP_I5, SP_I6, SP_I7, SP_G0, SP_G1, SP_G2, SP_G3, SP_G4, SP_G5, SP_G6, SP_G7, SP_L0, SP_L1, SP_L2, SP_L3, SP_L4, SP_L5, SP_L6, SP_L7, SP_O0, SP_O1, SP_O2, SP_O3, SP_O4, SP_O5, SP_O6, SP_O7, 
  };

  // I64Regs Bit set.
  static const uint8_t I64RegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x1f, 
  };

  // CoprocPair Register Class...
  static const MCPhysReg CoprocPair[] = {
    SP_C0_C1, SP_C2_C3, SP_C4_C5, SP_C6_C7, SP_C8_C9, SP_C10_C11, SP_C12_C13, SP_C14_C15, SP_C16_C17, SP_C18_C19, SP_C20_C21, SP_C22_C23, SP_C24_C25, SP_C26_C27, SP_C28_C29, SP_C30_C31, 
  };

  // CoprocPair Bit set.
  static const uint8_t CoprocPairBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x1f, 
  };

  // IntPair Register Class...
  static const MCPhysReg IntPair[] = {
    SP_I0_I1, SP_I2_I3, SP_I4_I5, SP_I6_I7, SP_G0_G1, SP_G2_G3, SP_G4_G5, SP_G6_G7, SP_L0_L1, SP_L2_L3, SP_L4_L5, SP_L6_L7, SP_O0_O1, SP_O2_O3, SP_O4_O5, SP_O6_O7, 
  };

  // IntPair Bit set.
  static const uint8_t IntPairBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x1f, 
  };

  // LowDFPRegs Register Class...
  static const MCPhysReg LowDFPRegs[] = {
    SP_D0, SP_D1, SP_D2, SP_D3, SP_D4, SP_D5, SP_D6, SP_D7, SP_D8, SP_D9, SP_D10, SP_D11, SP_D12, SP_D13, SP_D14, SP_D15, 
  };

  // LowDFPRegs Bit set.
  static const uint8_t LowDFPRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0x01, 
  };

  // PRRegs Register Class...
  static const MCPhysReg PRRegs[] = {
    SP_TPC, SP_TNPC, SP_TSTATE, SP_TT, SP_TICK, SP_TBA, SP_PSTATE, SP_TL, SP_PIL, SP_CWP, SP_CANSAVE, SP_CANRESTORE, SP_CLEANWIN, SP_OTHERWIN, SP_WSTATE, 
  };

  // PRRegs Bit set.
  static const uint8_t PRRegsBits[] = {
    0x4e, 0xd4, 0x7e, 0x01, 
  };

  // QFPRegs Register Class...
  static const MCPhysReg QFPRegs[] = {
    SP_Q0, SP_Q1, SP_Q2, SP_Q3, SP_Q4, SP_Q5, SP_Q6, SP_Q7, SP_Q8, SP_Q9, SP_Q10, SP_Q11, SP_Q12, SP_Q13, SP_Q14, SP_Q15, 
  };

  // QFPRegs Bit set.
  static const uint8_t QFPRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x1f, 
  };

  // LowQFPRegs Register Class...
  static const MCPhysReg LowQFPRegs[] = {
    SP_Q0, SP_Q1, SP_Q2, SP_Q3, SP_Q4, SP_Q5, SP_Q6, SP_Q7, 
  };

  // LowQFPRegs Bit set.
  static const uint8_t LowQFPRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x1f, 
  };

// end of register classes misc


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
static const char SparcRegClassStrings[] = {
  /* 0 */ "CoprocPair\0"
  /* 11 */ "IntPair\0"
  /* 19 */ "I64Regs\0"
  /* 27 */ "FCCRegs\0"
  /* 35 */ "LowDFPRegs\0"
  /* 46 */ "LowQFPRegs\0"
  /* 57 */ "PRRegs\0"
  /* 64 */ "ASRRegs\0"
  /* 72 */ "CoprocRegs\0"
  /* 83 */ "IntRegs\0"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

static const MCRegisterClass SparcMCRegisterClasses[] = {
  { FCCRegs, FCCRegsBits, sizeof(FCCRegsBits) },
  { ASRRegs, ASRRegsBits, sizeof(ASRRegsBits) },
  { CoprocRegs, CoprocRegsBits, sizeof(CoprocRegsBits) },
  { FPRegs, FPRegsBits, sizeof(FPRegsBits) },
  { IntRegs, IntRegsBits, sizeof(IntRegsBits) },
  { DFPRegs, DFPRegsBits, sizeof(DFPRegsBits) },
  { I64Regs, I64RegsBits, sizeof(I64RegsBits) },
  { CoprocPair, CoprocPairBits, sizeof(CoprocPairBits) },
  { IntPair, IntPairBits, sizeof(IntPairBits) },
  { LowDFPRegs, LowDFPRegsBits, sizeof(LowDFPRegsBits) },
  { PRRegs, PRRegsBits, sizeof(PRRegsBits) },
  { QFPRegs, QFPRegsBits, sizeof(QFPRegsBits) },
  { LowQFPRegs, LowQFPRegsBits, sizeof(LowQFPRegsBits) },
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
MCMnemonic Sparc_getMnemonic(const MCInst *MI) {

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
  static const char AsmStrs[] = {
  /* 0 */ "rd %pc, \0"
  /* 9 */ "rd %wim, \0"
  /* 19 */ "rd %tbr, \0"
  /* 29 */ "rd %psr, \0"
  /* 39 */ "fsrc1 \0"
  /* 46 */ "fandnot1 \0"
  /* 56 */ "fnot1 \0"
  /* 63 */ "fornot1 \0"
  /* 72 */ "fsra32 \0"
  /* 80 */ "fpsub32 \0"
  /* 89 */ "fpadd32 \0"
  /* 98 */ "edge32 \0"
  /* 106 */ "fcmple32 \0"
  /* 116 */ "fcmpne32 \0"
  /* 126 */ "fpack32 \0"
  /* 135 */ "cmask32 \0"
  /* 144 */ "fsll32 \0"
  /* 152 */ "fsrl32 \0"
  /* 160 */ "fcmpeq32 \0"
  /* 170 */ "fslas32 \0"
  /* 179 */ "fcmpgt32 \0"
  /* 189 */ "array32 \0"
  /* 198 */ "fsrc2 \0"
  /* 205 */ "fandnot2 \0"
  /* 215 */ "fnot2 \0"
  /* 222 */ "fornot2 \0"
  /* 231 */ "fpadd64 \0"
  /* 240 */ "fsra16 \0"
  /* 248 */ "fpsub16 \0"
  /* 257 */ "fpadd16 \0"
  /* 266 */ "edge16 \0"
  /* 274 */ "fcmple16 \0"
  /* 284 */ "fcmpne16 \0"
  /* 294 */ "fpack16 \0"
  /* 303 */ "cmask16 \0"
  /* 312 */ "fsll16 \0"
  /* 320 */ "fsrl16 \0"
  /* 328 */ "fchksm16 \0"
  /* 338 */ "fmean16 \0"
  /* 347 */ "fcmpeq16 \0"
  /* 357 */ "fslas16 \0"
  /* 366 */ "fcmpgt16 \0"
  /* 376 */ "fmul8x16 \0"
  /* 386 */ "fmuld8ulx16 \0"
  /* 399 */ "fmul8ulx16 \0"
  /* 411 */ "fmuld8sux16 \0"
  /* 424 */ "fmul8sux16 \0"
  /* 436 */ "array16 \0"
  /* 445 */ "edge8 \0"
  /* 452 */ "cmask8 \0"
  /* 460 */ "array8 \0"
  /* 468 */ "!ADJCALLSTACKDOWN \0"
  /* 487 */ "!ADJCALLSTACKUP \0"
  /* 504 */ "fpsub32S \0"
  /* 514 */ "fpsub16S \0"
  /* 524 */ "brgez,a \0"
  /* 533 */ "brlez,a \0"
  /* 542 */ "brgz,a \0"
  /* 550 */ "brlz,a \0"
  /* 558 */ "brnz,a \0"
  /* 566 */ "brz,a \0"
  /* 573 */ "stba \0"
  /* 579 */ "stda \0"
  /* 585 */ "stha \0"
  /* 591 */ "stqa \0"
  /* 597 */ "sra \0"
  /* 602 */ "faligndata \0"
  /* 614 */ "sta \0"
  /* 619 */ "stb \0"
  /* 624 */ "sub \0"
  /* 629 */ "smac \0"
  /* 635 */ "umac \0"
  /* 641 */ "tsubcc \0"
  /* 649 */ "addxccc \0"
  /* 658 */ "taddcc \0"
  /* 666 */ "andcc \0"
  /* 673 */ "smulcc \0"
  /* 681 */ "umulcc \0"
  /* 689 */ "andncc \0"
  /* 697 */ "orncc \0"
  /* 704 */ "xnorcc \0"
  /* 712 */ "xorcc \0"
  /* 719 */ "mulscc \0"
  /* 727 */ "sdivcc \0"
  /* 735 */ "udivcc \0"
  /* 743 */ "subxcc \0"
  /* 751 */ "addxcc \0"
  /* 759 */ "popc \0"
  /* 765 */ "addxc \0"
  /* 772 */ "fsubd \0"
  /* 779 */ "fhsubd \0"
  /* 787 */ "add \0"
  /* 792 */ "faddd \0"
  /* 799 */ "fhaddd \0"
  /* 807 */ "fnhaddd \0"
  /* 816 */ "fnaddd \0"
  /* 824 */ "fcmped \0"
  /* 832 */ "fnegd \0"
  /* 839 */ "fmuld \0"
  /* 846 */ "fsmuld \0"
  /* 854 */ "fand \0"
  /* 860 */ "fnand \0"
  /* 867 */ "fexpand \0"
  /* 876 */ "fitod \0"
  /* 883 */ "fqtod \0"
  /* 890 */ "fstod \0"
  /* 897 */ "fxtod \0"
  /* 904 */ "fcmpd \0"
  /* 911 */ "flcmpd \0"
  /* 919 */ "rd \0"
  /* 923 */ "fabsd \0"
  /* 930 */ "fsqrtd \0"
  /* 938 */ "std \0"
  /* 943 */ "fdivd \0"
  /* 950 */ "fmovd \0"
  /* 957 */ "fpmerge \0"
  /* 966 */ "bshuffle \0"
  /* 976 */ "fone \0"
  /* 982 */ "restore \0"
  /* 991 */ "save \0"
  /* 997 */ "flush \0"
  /* 1004 */ "sth \0"
  /* 1009 */ "sethi \0"
  /* 1016 */ "umulxhi \0"
  /* 1025 */ "xmulxhi \0"
  /* 1034 */ "fdtoi \0"
  /* 1041 */ "fqtoi \0"
  /* 1048 */ "fstoi \0"
  /* 1055 */ "bmask \0"
  /* 1062 */ "edge32l \0"
  /* 1071 */ "edge16l \0"
  /* 1080 */ "edge8l \0"
  /* 1088 */ "fmul8x16al \0"
  /* 1100 */ "call \0"
  /* 1106 */ "sll \0"
  /* 1111 */ "jmpl \0"
  /* 1117 */ "alignaddrl \0"
  /* 1129 */ "srl \0"
  /* 1134 */ "smul \0"
  /* 1140 */ "umul \0"
  /* 1146 */ "edge32n \0"
  /* 1155 */ "edge16n \0"
  /* 1164 */ "edge8n \0"
  /* 1172 */ "andn \0"
  /* 1178 */ "edge32ln \0"
  /* 1188 */ "edge16ln \0"
  /* 1198 */ "edge8ln \0"
  /* 1207 */ "brgez,a,pn \0"
  /* 1219 */ "brlez,a,pn \0"
  /* 1231 */ "brgz,a,pn \0"
  /* 1242 */ "brlz,a,pn \0"
  /* 1253 */ "brnz,a,pn \0"
  /* 1264 */ "brz,a,pn \0"
  /* 1274 */ "brgez,pn \0"
  /* 1284 */ "brlez,pn \0"
  /* 1294 */ "brgz,pn \0"
  /* 1303 */ "brlz,pn \0"
  /* 1312 */ "brnz,pn \0"
  /* 1321 */ "brz,pn \0"
  /* 1329 */ "orn \0"
  /* 1334 */ "pdistn \0"
  /* 1342 */ "fzero \0"
  /* 1349 */ "cmp \0"
  /* 1354 */ "unimp \0"
  /* 1361 */ "jmp \0"
  /* 1366 */ "fsubq \0"
  /* 1373 */ "faddq \0"
  /* 1380 */ "fcmpeq \0"
  /* 1388 */ "fnegq \0"
  /* 1395 */ "fdmulq \0"
  /* 1403 */ "fmulq \0"
  /* 1410 */ "fdtoq \0"
  /* 1417 */ "fitoq \0"
  /* 1424 */ "fstoq \0"
  /* 1431 */ "fxtoq \0"
  /* 1438 */ "fcmpq \0"
  /* 1445 */ "fabsq \0"
  /* 1452 */ "fsqrtq \0"
  /* 1460 */ "stq \0"
  /* 1465 */ "fdivq \0"
  /* 1472 */ "fmovq \0"
  /* 1479 */ "membar \0"
  /* 1487 */ "alignaddr \0"
  /* 1498 */ "sir \0"
  /* 1503 */ "for \0"
  /* 1508 */ "fnor \0"
  /* 1514 */ "fxnor \0"
  /* 1521 */ "fxor \0"
  /* 1527 */ "rdpr \0"
  /* 1533 */ "wrpr \0"
  /* 1539 */ "pwr \0"
  /* 1544 */ "fsrc1s \0"
  /* 1552 */ "fandnot1s \0"
  /* 1563 */ "fnot1s \0"
  /* 1571 */ "fornot1s \0"
  /* 1581 */ "fpadd32s \0"
  /* 1591 */ "fsrc2s \0"
  /* 1599 */ "fandnot2s \0"
  /* 1610 */ "fnot2s \0"
  /* 1618 */ "fornot2s \0"
  /* 1628 */ "fpadd16s \0"
  /* 1638 */ "fsubs \0"
  /* 1645 */ "fhsubs \0"
  /* 1653 */ "fadds \0"
  /* 1660 */ "fhadds \0"
  /* 1668 */ "fnhadds \0"
  /* 1677 */ "fnadds \0"
  /* 1685 */ "fands \0"
  /* 1692 */ "fnands \0"
  /* 1700 */ "fones \0"
  /* 1707 */ "fcmpes \0"
  /* 1715 */ "fnegs \0"
  /* 1722 */ "fmuls \0"
  /* 1729 */ "fzeros \0"
  /* 1737 */ "fdtos \0"
  /* 1744 */ "fitos \0"
  /* 1751 */ "fqtos \0"
  /* 1758 */ "fxtos \0"
  /* 1765 */ "fcmps \0"
  /* 1772 */ "flcmps \0"
  /* 1780 */ "fors \0"
  /* 1786 */ "fnors \0"
  /* 1793 */ "fxnors \0"
  /* 1801 */ "fxors \0"
  /* 1808 */ "fabss \0"
  /* 1815 */ "fsqrts \0"
  /* 1823 */ "fdivs \0"
  /* 1830 */ "fmovs \0"
  /* 1837 */ "set \0"
  /* 1842 */ "lzcnt \0"
  /* 1849 */ "pdist \0"
  /* 1856 */ "rett \0"
  /* 1862 */ "fmul8x16au \0"
  /* 1874 */ "sdiv \0"
  /* 1880 */ "udiv \0"
  /* 1886 */ "tsubcctv \0"
  /* 1896 */ "taddcctv \0"
  /* 1906 */ "movstosw \0"
  /* 1916 */ "movstouw \0"
  /* 1926 */ "srax \0"
  /* 1932 */ "subx \0"
  /* 1938 */ "addx \0"
  /* 1944 */ "fpackfix \0"
  /* 1954 */ "sllx \0"
  /* 1960 */ "srlx \0"
  /* 1966 */ "xmulx \0"
  /* 1973 */ "fdtox \0"
  /* 1980 */ "movdtox \0"
  /* 1989 */ "fqtox \0"
  /* 1996 */ "fstox \0"
  /* 2003 */ "stx \0"
  /* 2008 */ "sdivx \0"
  /* 2015 */ "udivx \0"
  /* 2022 */ "fmovrdz \0"
  /* 2031 */ "fmovrdgez \0"
  /* 2042 */ "fmovrqgez \0"
  /* 2053 */ "brgez \0"
  /* 2060 */ "movrgez \0"
  /* 2069 */ "fmovrsgez \0"
  /* 2080 */ "fmovrdlez \0"
  /* 2091 */ "fmovrqlez \0"
  /* 2102 */ "brlez \0"
  /* 2109 */ "movrlez \0"
  /* 2118 */ "fmovrslez \0"
  /* 2129 */ "fmovrdgz \0"
  /* 2139 */ "fmovrqgz \0"
  /* 2149 */ "brgz \0"
  /* 2155 */ "movrgz \0"
  /* 2163 */ "fmovrsgz \0"
  /* 2173 */ "fmovrdlz \0"
  /* 2183 */ "fmovrqlz \0"
  /* 2193 */ "brlz \0"
  /* 2199 */ "movrlz \0"
  /* 2207 */ "fmovrslz \0"
  /* 2217 */ "fmovrdnz \0"
  /* 2227 */ "fmovrqnz \0"
  /* 2237 */ "brnz \0"
  /* 2243 */ "movrnz \0"
  /* 2251 */ "fmovrsnz \0"
  /* 2261 */ "fmovrqz \0"
  /* 2270 */ "brz \0"
  /* 2275 */ "movrz \0"
  /* 2282 */ "fmovrsz \0"
  /* 2291 */ "; SELECT_CC_DFP_FCC PSEUDO!\0"
  /* 2319 */ "; SELECT_CC_QFP_FCC PSEUDO!\0"
  /* 2347 */ "; SELECT_CC_FP_FCC PSEUDO!\0"
  /* 2374 */ "; SELECT_CC_Int_FCC PSEUDO!\0"
  /* 2402 */ "; SELECT_CC_DFP_ICC PSEUDO!\0"
  /* 2430 */ "; SELECT_CC_QFP_ICC PSEUDO!\0"
  /* 2458 */ "; SELECT_CC_FP_ICC PSEUDO!\0"
  /* 2485 */ "; SELECT_CC_Int_ICC PSEUDO!\0"
  /* 2513 */ "jmp %i7+\0"
  /* 2522 */ "jmp %o7+\0"
  /* 2531 */ "# XRay Function Patchable RET.\0"
  /* 2562 */ "# XRay Typed Event Log.\0"
  /* 2586 */ "# XRay Custom Event Log.\0"
  /* 2611 */ "# XRay Function Enter.\0"
  /* 2634 */ "# XRay Tail Call Exit.\0"
  /* 2657 */ "# XRay Function Exit.\0"
  /* 2679 */ "flush %g0\0"
  /* 2689 */ "ta 1\0"
  /* 2694 */ "ta 3\0"
  /* 2699 */ "ta 5\0"
  /* 2704 */ "LIFETIME_END\0"
  /* 2717 */ "PSEUDO_PROBE\0"
  /* 2730 */ "BUNDLE\0"
  /* 2737 */ "DBG_VALUE\0"
  /* 2747 */ "DBG_INSTR_REF\0"
  /* 2761 */ "DBG_PHI\0"
  /* 2769 */ "DBG_LABEL\0"
  /* 2779 */ "LIFETIME_START\0"
  /* 2794 */ "DBG_VALUE_LIST\0"
  /* 2809 */ "std %cq, [\0"
  /* 2820 */ "std %fq, [\0"
  /* 2831 */ "st %csr, [\0"
  /* 2842 */ "st %fsr, [\0"
  /* 2853 */ "stx %fsr, [\0"
  /* 2865 */ "ldsba [\0"
  /* 2873 */ "lduba [\0"
  /* 2881 */ "ldstuba [\0"
  /* 2891 */ "ldda [\0"
  /* 2898 */ "lda [\0"
  /* 2904 */ "ldsha [\0"
  /* 2912 */ "lduha [\0"
  /* 2920 */ "swapa [\0"
  /* 2928 */ "ldqa [\0"
  /* 2935 */ "casa [\0"
  /* 2942 */ "ldsb [\0"
  /* 2949 */ "ldub [\0"
  /* 2956 */ "ldstub [\0"
  /* 2965 */ "ldd [\0"
  /* 2971 */ "ld [\0"
  /* 2976 */ "prefetch [\0"
  /* 2987 */ "ldsh [\0"
  /* 2994 */ "lduh [\0"
  /* 3001 */ "swap [\0"
  /* 3008 */ "ldq [\0"
  /* 3014 */ "cas [\0"
  /* 3020 */ "ldsw [\0"
  /* 3027 */ "ldx [\0"
  /* 3033 */ "casx [\0"
  /* 3040 */ "cb\0"
  /* 3043 */ "fb\0"
  /* 3046 */ "fmovd\0"
  /* 3052 */ "# FEntry call\0"
  /* 3066 */ "siam\0"
  /* 3071 */ "shutdown\0"
  /* 3080 */ "nop\0"
  /* 3084 */ "fmovq\0"
  /* 3090 */ "stbar\0"
  /* 3096 */ "fmovs\0"
  /* 3102 */ "t\0"
  /* 3104 */ "mov\0"
  /* 3108 */ "flushw\0"
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
    2738U,	// DBG_VALUE
    2795U,	// DBG_VALUE_LIST
    2748U,	// DBG_INSTR_REF
    2762U,	// DBG_PHI
    2770U,	// DBG_LABEL
    0U,	// REG_SEQUENCE
    0U,	// COPY
    2731U,	// BUNDLE
    2780U,	// LIFETIME_START
    2705U,	// LIFETIME_END
    2718U,	// PSEUDO_PROBE
    0U,	// ARITH_FENCE
    0U,	// STACKMAP
    3053U,	// FENTRY_CALL
    0U,	// PATCHPOINT
    0U,	// LOAD_STACK_GUARD
    0U,	// PREALLOCATED_SETUP
    0U,	// PREALLOCATED_ARG
    0U,	// STATEPOINT
    0U,	// LOCAL_ESCAPE
    0U,	// FAULTING_OP
    0U,	// PATCHABLE_OP
    2612U,	// PATCHABLE_FUNCTION_ENTER
    2532U,	// PATCHABLE_RET
    2658U,	// PATCHABLE_FUNCTION_EXIT
    2635U,	// PATCHABLE_TAIL_CALL
    2587U,	// PATCHABLE_EVENT_CALL
    2563U,	// PATCHABLE_TYPED_EVENT_CALL
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
    4565U,	// ADJCALLSTACKDOWN
    70120U,	// ADJCALLSTACKUP
    8201U,	// GETPCX
    2292U,	// SELECT_CC_DFP_FCC
    2403U,	// SELECT_CC_DFP_ICC
    2348U,	// SELECT_CC_FP_FCC
    2459U,	// SELECT_CC_FP_ICC
    2375U,	// SELECT_CC_Int_FCC
    2486U,	// SELECT_CC_Int_ICC
    2320U,	// SELECT_CC_QFP_FCC
    2431U,	// SELECT_CC_QFP_ICC
    2111278U,	// SET
    20984468U,	// ADDCCri
    20984468U,	// ADDCCrr
    20985747U,	// ADDCri
    20985747U,	// ADDCrr
    20984560U,	// ADDEri
    20984560U,	// ADDErr
    20984574U,	// ADDXC
    20984458U,	// ADDXCCC
    20984596U,	// ADDXri
    20984596U,	// ADDXrr
    20984596U,	// ADDri
    20984596U,	// ADDrr
    20985296U,	// ALIGNADDR
    20984926U,	// ALIGNADDRL
    20984475U,	// ANDCCri
    20984475U,	// ANDCCrr
    20984498U,	// ANDNCCri
    20984498U,	// ANDNCCrr
    20984981U,	// ANDNri
    20984981U,	// ANDNrr
    20984981U,	// ANDXNrr
    20984664U,	// ANDXri
    20984664U,	// ANDXrr
    20984664U,	// ANDri
    20984664U,	// ANDrr
    20984245U,	// ARRAY16
    20983998U,	// ARRAY32
    20984269U,	// ARRAY8
    70208U,	// BA
    2247650U,	// BCOND
    2313186U,	// BCONDA
    87378U,	// BINDri
    87378U,	// BINDrr
    20984864U,	// BMASK
    21122020U,	// BPFCC
    21187556U,	// BPFCCA
    281572U,	// BPFCCANT
    347108U,	// BPFCCNT
    5304U,	// BPGEZapn
    4621U,	// BPGEZapt
    5371U,	// BPGEZnapn
    6150U,	// BPGEZnapt
    5328U,	// BPGZapn
    4639U,	// BPGZapt
    5391U,	// BPGZnapn
    6246U,	// BPGZnapt
    2509794U,	// BPICC
    478178U,	// BPICCA
    543714U,	// BPICCANT
    609250U,	// BPICCNT
    5316U,	// BPLEZapn
    4630U,	// BPLEZapt
    5381U,	// BPLEZnapn
    6199U,	// BPLEZnapt
    5339U,	// BPLZapn
    4647U,	// BPLZapt
    5400U,	// BPLZnapn
    6290U,	// BPLZnapt
    5350U,	// BPNZapn
    4655U,	// BPNZapt
    5409U,	// BPNZnapn
    6334U,	// BPNZnapt
    2771938U,	// BPXCC
    740322U,	// BPXCCA
    805858U,	// BPXCCANT
    871394U,	// BPXCCNT
    5361U,	// BPZapn
    4663U,	// BPZapt
    5418U,	// BPZnapn
    6367U,	// BPZnapt
    20984775U,	// BSHUFFLE
    70733U,	// CALL
    87117U,	// CALLri
    87117U,	// CALLrr
    932728U,	// CASAasi10
    7289720U,	// CASArr
    22035418U,	// CASXrr
    22035399U,	// CASrr
    2247649U,	// CBCOND
    2313185U,	// CBCONDA
    69936U,	// CMASK16
    69768U,	// CMASK32
    70085U,	// CMASK8
    5446U,	// CMPri
    5446U,	// CMPrr
    20984075U,	// EDGE16
    20984880U,	// EDGE16L
    20984997U,	// EDGE16LN
    20984964U,	// EDGE16N
    20983907U,	// EDGE32
    20984871U,	// EDGE32L
    20984987U,	// EDGE32LN
    20984955U,	// EDGE32N
    20984254U,	// EDGE8
    20984889U,	// EDGE8L
    20985007U,	// EDGE8LN
    20984973U,	// EDGE8N
    2110364U,	// FABSD
    2110886U,	// FABSQ
    2111249U,	// FABSS
    20984601U,	// FADDD
    20985182U,	// FADDQ
    20985462U,	// FADDS
    20984411U,	// FALIGNADATA
    20984663U,	// FAND
    20983855U,	// FANDNOT1
    20985361U,	// FANDNOT1S
    20984014U,	// FANDNOT2
    20985408U,	// FANDNOT2S
    20985494U,	// FANDS
    2247652U,	// FBCOND
    2313188U,	// FBCONDA
    20984137U,	// FCHKSM16
    5001U,	// FCMPD
    20984156U,	// FCMPEQ16
    20983969U,	// FCMPEQ32
    20984175U,	// FCMPGT16
    20983988U,	// FCMPGT32
    20984083U,	// FCMPLE16
    20983915U,	// FCMPLE32
    20984093U,	// FCMPNE16
    20983925U,	// FCMPNE32
    5535U,	// FCMPQ
    5862U,	// FCMPS
    20984752U,	// FDIVD
    20985274U,	// FDIVQ
    20985632U,	// FDIVS
    20985204U,	// FDMULQ
    2110475U,	// FDTOI
    2110851U,	// FDTOQ
    2111178U,	// FDTOS
    2111414U,	// FDTOX
    2110308U,	// FEXPAND
    20984608U,	// FHADDD
    20985469U,	// FHADDS
    20984588U,	// FHSUBD
    20985454U,	// FHSUBS
    2110317U,	// FITOD
    2110858U,	// FITOQ
    2111185U,	// FITOS
    150999952U,	// FLCMPD
    151000813U,	// FLCMPS
    2680U,	// FLUSH
    3109U,	// FLUSHW
    87014U,	// FLUSHri
    87014U,	// FLUSHrr
    20984147U,	// FMEAN16
    2110391U,	// FMOVD
    1141735U,	// FMOVD_FCC
    17198055U,	// FMOVD_ICC
    17460199U,	// FMOVD_XCC
    2110913U,	// FMOVQ
    1141773U,	// FMOVQ_FCC
    17198093U,	// FMOVQ_ICC
    17460237U,	// FMOVQ_XCC
    20985840U,	// FMOVRGEZD
    20985851U,	// FMOVRGEZQ
    20985878U,	// FMOVRGEZS
    20985938U,	// FMOVRGZD
    20985948U,	// FMOVRGZQ
    20985972U,	// FMOVRGZS
    20985889U,	// FMOVRLEZD
    20985900U,	// FMOVRLEZQ
    20985927U,	// FMOVRLEZS
    20985982U,	// FMOVRLZD
    20985992U,	// FMOVRLZQ
    20986016U,	// FMOVRLZS
    20986026U,	// FMOVRNZD
    20986036U,	// FMOVRNZQ
    20986060U,	// FMOVRNZS
    20985831U,	// FMOVRZD
    20986070U,	// FMOVRZQ
    20986091U,	// FMOVRZS
    2111271U,	// FMOVS
    1141785U,	// FMOVS_FCC
    17198105U,	// FMOVS_ICC
    17460249U,	// FMOVS_XCC
    20984233U,	// FMUL8SUX16
    20984208U,	// FMUL8ULX16
    20984185U,	// FMUL8X16
    20984897U,	// FMUL8X16AL
    20985671U,	// FMUL8X16AU
    20984648U,	// FMULD
    20984220U,	// FMULD8SUX16
    20984195U,	// FMULD8ULX16
    20985212U,	// FMULQ
    20985531U,	// FMULS
    20984625U,	// FNADDD
    20985486U,	// FNADDS
    20984669U,	// FNAND
    20985501U,	// FNANDS
    2110273U,	// FNEGD
    2110829U,	// FNEGQ
    2111156U,	// FNEGS
    20984616U,	// FNHADDD
    20985477U,	// FNHADDS
    20984616U,	// FNMULD
    20985477U,	// FNMULS
    20985317U,	// FNOR
    20985595U,	// FNORS
    2109497U,	// FNOT1
    2111004U,	// FNOT1S
    2109656U,	// FNOT2
    2111051U,	// FNOT2S
    20985477U,	// FNSMULD
    70609U,	// FONE
    71333U,	// FONES
    20985312U,	// FOR
    20983872U,	// FORNOT1
    20985380U,	// FORNOT1S
    20984031U,	// FORNOT2
    20985427U,	// FORNOT2S
    20985589U,	// FORS
    2109735U,	// FPACK16
    20983935U,	// FPACK32
    2111385U,	// FPACKFIX
    20984066U,	// FPADD16
    20985437U,	// FPADD16S
    20983898U,	// FPADD32
    20985390U,	// FPADD32S
    20984040U,	// FPADD64
    20984766U,	// FPMERGE
    20984057U,	// FPSUB16
    20984323U,	// FPSUB16S
    20983889U,	// FPSUB32
    20984313U,	// FPSUB32S
    2110324U,	// FQTOD
    2110482U,	// FQTOI
    2111192U,	// FQTOS
    2111430U,	// FQTOX
    20984166U,	// FSLAS16
    20983979U,	// FSLAS32
    20984121U,	// FSLL16
    20983953U,	// FSLL32
    20984655U,	// FSMULD
    2110371U,	// FSQRTD
    2110893U,	// FSQRTQ
    2111256U,	// FSQRTS
    20984049U,	// FSRA16
    20983881U,	// FSRA32
    2109480U,	// FSRC1
    2110985U,	// FSRC1S
    2109639U,	// FSRC2
    2111032U,	// FSRC2S
    20984129U,	// FSRL16
    20983961U,	// FSRL32
    2110331U,	// FSTOD
    2110489U,	// FSTOI
    2110865U,	// FSTOQ
    2111437U,	// FSTOX
    20984581U,	// FSUBD
    20985175U,	// FSUBQ
    20985447U,	// FSUBS
    20985323U,	// FXNOR
    20985602U,	// FXNORS
    20985330U,	// FXOR
    20985610U,	// FXORS
    2110338U,	// FXTOD
    2110872U,	// FXTOQ
    2111199U,	// FXTOS
    70975U,	// FZERO
    71362U,	// FZEROS
    2126936U,	// JMPLri
    2126936U,	// JMPLrr
    26180435U,	// LDArr
    1203100U,	// LDCSRri
    1203100U,	// LDCSRrr
    3177372U,	// LDCri
    3177372U,	// LDCrr
    26180428U,	// LDDArr
    3177366U,	// LDDCri
    3177366U,	// LDDCrr
    26180428U,	// LDDFArr
    3177366U,	// LDDFri
    3177366U,	// LDDFrr
    3177366U,	// LDDri
    3177366U,	// LDDrr
    26180435U,	// LDFArr
    1268636U,	// LDFSRri
    1268636U,	// LDFSRrr
    3177372U,	// LDFri
    3177372U,	// LDFrr
    26180465U,	// LDQFArr
    3177409U,	// LDQFri
    3177409U,	// LDQFrr
    26180402U,	// LDSBArr
    3177343U,	// LDSBri
    3177343U,	// LDSBrr
    26180441U,	// LDSHArr
    3177388U,	// LDSHri
    3177388U,	// LDSHrr
    26180418U,	// LDSTUBArr
    3177357U,	// LDSTUBri
    3177357U,	// LDSTUBrr
    3177421U,	// LDSWri
    3177421U,	// LDSWrr
    26180410U,	// LDUBArr
    3177350U,	// LDUBri
    3177350U,	// LDUBrr
    26180449U,	// LDUHArr
    3177395U,	// LDUHri
    3177395U,	// LDUHrr
    1268692U,	// LDXFSRri
    1268692U,	// LDXFSRrr
    3177428U,	// LDXri
    3177428U,	// LDXrr
    3177372U,	// LDri
    3177372U,	// LDrr
    33556U,	// LEAX_ADDri
    33556U,	// LEA_ADDri
    2111283U,	// LZCNT
    38344U,	// MEMBARi
    2111421U,	// MOVDTOX
    1141793U,	// MOVFCCri
    1141793U,	// MOVFCCrr
    17198113U,	// MOVICCri
    17198113U,	// MOVICCrr
    20985869U,	// MOVRGEZri
    20985869U,	// MOVRGEZrr
    20985964U,	// MOVRGZri
    20985964U,	// MOVRGZrr
    20985918U,	// MOVRLEZri
    20985918U,	// MOVRLEZrr
    20986008U,	// MOVRLZri
    20986008U,	// MOVRLZrr
    20986052U,	// MOVRNZri
    20986052U,	// MOVRNZrr
    20986084U,	// MOVRRZri
    20986084U,	// MOVRRZrr
    2111347U,	// MOVSTOSW
    2111357U,	// MOVSTOUW
    2111421U,	// MOVWTOS
    17460257U,	// MOVXCCri
    17460257U,	// MOVXCCrr
    2111421U,	// MOVXTOD
    20984528U,	// MULSCCri
    20984528U,	// MULSCCrr
    20985776U,	// MULXri
    20985776U,	// MULXrr
    3081U,	// NOP
    20984515U,	// ORCCri
    20984515U,	// ORCCrr
    20984506U,	// ORNCCri
    20984506U,	// ORNCCrr
    20985138U,	// ORNri
    20985138U,	// ORNrr
    20985138U,	// ORXNrr
    20985313U,	// ORXri
    20985313U,	// ORXrr
    20985313U,	// ORri
    20985313U,	// ORrr
    20985658U,	// PDIST
    20985143U,	// PDISTN
    2110200U,	// POPCrr
    5266337U,	// PREFETCHi
    5266337U,	// PREFETCHr
    33560068U,	// PWRPSRri
    33560068U,	// PWRPSRrr
    2110360U,	// RDASR
    69633U,	// RDPC
    2110968U,	// RDPR
    69662U,	// RDPSR
    69652U,	// RDTBR
    69642U,	// RDWIM
    20984791U,	// RESTOREri
    20984791U,	// RESTORErr
    72146U,	// RET
    72155U,	// RETL
    87873U,	// RETTri
    87873U,	// RETTrr
    20984800U,	// SAVEri
    20984800U,	// SAVErr
    20984536U,	// SDIVCCri
    20984536U,	// SDIVCCrr
    20985817U,	// SDIVXri
    20985817U,	// SDIVXrr
    20985683U,	// SDIVri
    20985683U,	// SDIVrr
    2110450U,	// SETHIXi
    2110450U,	// SETHIi
    3072U,	// SHUTDOWN
    3067U,	// SIAM
    71131U,	// SIR
    20985763U,	// SLLXri
    20985763U,	// SLLXrr
    20984915U,	// SLLri
    20984915U,	// SLLrr
    20984438U,	// SMACri
    20984438U,	// SMACrr
    20984482U,	// SMULCCri
    20984482U,	// SMULCCrr
    20984943U,	// SMULri
    20984943U,	// SMULrr
    20985735U,	// SRAXri
    20985735U,	// SRAXrr
    20984406U,	// SRAri
    20984406U,	// SRArr
    20985769U,	// SRLXri
    20985769U,	// SRLXrr
    20984938U,	// SRLri
    20984938U,	// SRLrr
    9413223U,	// STArr
    3091U,	// STBAR
    9413182U,	// STBArr
    1352300U,	// STBri
    1352300U,	// STBrr
    1334032U,	// STCSRri
    1334032U,	// STCSRrr
    1353533U,	// STCri
    1353533U,	// STCrr
    9413188U,	// STDArr
    1334010U,	// STDCQri
    1334010U,	// STDCQrr
    1352619U,	// STDCri
    1352619U,	// STDCrr
    9413188U,	// STDFArr
    1334021U,	// STDFQri
    1334021U,	// STDFQrr
    1352619U,	// STDFri
    1352619U,	// STDFrr
    1352619U,	// STDri
    1352619U,	// STDrr
    9413223U,	// STFArr
    1334043U,	// STFSRri
    1334043U,	// STFSRrr
    1353533U,	// STFri
    1353533U,	// STFrr
    9413194U,	// STHArr
    1352685U,	// STHri
    1352685U,	// STHrr
    9413200U,	// STQFArr
    1353141U,	// STQFri
    1353141U,	// STQFrr
    1334054U,	// STXFSRri
    1334054U,	// STXFSRrr
    1353684U,	// STXri
    1353684U,	// STXrr
    1353533U,	// STri
    1353533U,	// STrr
    20984451U,	// SUBCCri
    20984451U,	// SUBCCrr
    20985741U,	// SUBCri
    20985741U,	// SUBCrr
    20984552U,	// SUBEri
    20984552U,	// SUBErr
    20984433U,	// SUBXri
    20984433U,	// SUBXrr
    20984433U,	// SUBri
    20984433U,	// SUBrr
    26180457U,	// SWAPArr
    3177402U,	// SWAPri
    3177402U,	// SWAPrr
    2690U,	// TA1
    2695U,	// TA3
    2700U,	// TA5
    20985705U,	// TADDCCTVri
    20985705U,	// TADDCCTVrr
    20984467U,	// TADDCCri
    20984467U,	// TADDCCrr
    52870175U,	// TICCri
    52870175U,	// TICCrr
    557855508U,	// TLS_ADDXrr
    557855508U,	// TLS_ADDrr
    5197U,	// TLS_CALL
    288390100U,	// TLS_LDXrr
    288390044U,	// TLS_LDrr
    52608031U,	// TRAPri
    52608031U,	// TRAPrr
    20985695U,	// TSUBCCTVri
    20985695U,	// TSUBCCTVrr
    20984450U,	// TSUBCCri
    20984450U,	// TSUBCCrr
    53132319U,	// TXCCri
    53132319U,	// TXCCrr
    20984544U,	// UDIVCCri
    20984544U,	// UDIVCCrr
    20985824U,	// UDIVXri
    20985824U,	// UDIVXrr
    20985689U,	// UDIVri
    20985689U,	// UDIVrr
    20984444U,	// UMACri
    20984444U,	// UMACrr
    20984490U,	// UMULCCri
    20984490U,	// UMULCCrr
    20984825U,	// UMULXHI
    20984949U,	// UMULri
    20984949U,	// UMULrr
    70987U,	// UNIMP
    150999945U,	// V9FCMPD
    150999865U,	// V9FCMPED
    151000421U,	// V9FCMPEQ
    151000748U,	// V9FCMPES
    151000479U,	// V9FCMPQ
    151000806U,	// V9FCMPS
    52199U,	// V9FMOVD_FCC
    52237U,	// V9FMOVQ_FCC
    52249U,	// V9FMOVS_FCC
    52257U,	// V9MOVFCCri
    52257U,	// V9MOVFCCrr
    20985349U,	// WRASRri
    20985349U,	// WRASRrr
    20985342U,	// WRPRri
    20985342U,	// WRPRrr
    33560069U,	// WRPSRri
    33560069U,	// WRPSRrr
    67114501U,	// WRTBRri
    67114501U,	// WRTBRrr
    83891717U,	// WRWIMri
    83891717U,	// WRWIMrr
    20985775U,	// XMULX
    20984834U,	// XMULXHI
    20984513U,	// XNORCCri
    20984513U,	// XNORCCrr
    20985324U,	// XNORXrr
    20985324U,	// XNORri
    20985324U,	// XNORrr
    20984521U,	// XORCCri
    20984521U,	// XORCCrr
    20985331U,	// XORXri
    20985331U,	// XORXrr
    20985331U,	// XORri
    20985331U,	// XORrr
  };

  // Emit the opcode for the instruction.
  uint32_t Bits = 0;
  Bits |= OpInfo0[MCInst_getOpcode(MI)] << 0;
  return createMnemonic(AsmStrs+(Bits & 4095)-1, Bits);

}
/// printInstruction - This method is automatically generated by tablegen
/// from the instruction set description.
static void printInstruction(MCInst *MI, SStream *O) {
  MCMnemonic MnemonicInfo =Sparc_getMnemonic(MI);

#ifndef CAPSTONE_DIET

  SStream_concat0(O, MnemonicInfo.first);
#endif

  uint32_t Bits = MnemonicInfo.second;
  assert(Bits != 0 && "Cannot print this instruction.");

  // Fragment 0 encoded into 4 bits for 13 unique commands.
  switch ((Bits >> 12) & 15) {
  default: llvm_unreachable("Invalid command number.");
  case 0:
    // DBG_VALUE, DBG_VALUE_LIST, DBG_INSTR_REF, DBG_PHI, DBG_LABEL, BUNDLE, ...
    return;
    break;
  case 1:
    // ADJCALLSTACKDOWN, ADJCALLSTACKUP, BA, BPGEZapn, BPGEZapt, BPGEZnapn, B...
    printOperand/* printOperand (+ ) */(MI, 0, O);
    break;
  case 2:
    // GETPCX
    printGetPCX/* printGetPCX (+ ) */(MI, 0, O);
    return;
    break;
  case 3:
    // SET, ADDCCri, ADDCCrr, ADDCri, ADDCrr, ADDEri, ADDErr, ADDXC, ADDXCCC,...
    printOperand/* printOperand (+ ) */(MI, 1, O);
    break;
  case 4:
    // BCOND, BCONDA, BPFCC, BPFCCA, BPFCCANT, BPFCCNT, BPICC, BPICCA, BPICCA...
    printCCOperand/* printCCOperand (+ ) */(MI, 1, O);
    break;
  case 5:
    // BINDri, BINDrr, CALLri, CALLrr, FLUSHri, FLUSHrr, LDCSRri, LDCSRrr, LD...
    printMemOperand/* printMemOperand (+ ) */(MI, 0, O, "");
    break;
  case 6:
    // FMOVD_FCC, FMOVD_ICC, FMOVD_XCC, FMOVQ_FCC, FMOVQ_ICC, FMOVQ_XCC, FMOV...
    printCCOperand/* printCCOperand (+ ) */(MI, 3, O);
    break;
  case 7:
    // JMPLri, JMPLrr, LDArr, LDCri, LDCrr, LDDArr, LDDCri, LDDCrr, LDDFArr, ...
    printMemOperand/* printMemOperand (+ ) */(MI, 1, O, "");
    break;
  case 8:
    // LEAX_ADDri, LEA_ADDri
    printMemOperand/* printMemOperand (+ arith) */(MI, 1, O, "arith");
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  case 9:
    // MEMBARi
    printMembarTag/* printMembarTag (+ ) */(MI, 0, O);
    return;
    break;
  case 10:
    // STArr, STBArr, STBri, STBrr, STCri, STCrr, STDArr, STDCri, STDCrr, STD...
    printOperand/* printOperand (+ ) */(MI, 2, O);
    SStream_concat0(O, ", [");
    printMemOperand/* printMemOperand (+ ) */(MI, 0, O, "");
    break;
  case 11:
    // TICCri, TICCrr, TRAPri, TRAPrr, TXCCri, TXCCrr
    printCCOperand/* printCCOperand (+ ) */(MI, 2, O);
    break;
  case 12:
    // V9FMOVD_FCC, V9FMOVQ_FCC, V9FMOVS_FCC, V9MOVFCCri, V9MOVFCCrr
    printCCOperand/* printCCOperand (+ ) */(MI, 4, O);
    SStream_concat0(O, " ");
    printOperand/* printOperand (+ ) */(MI, 1, O);
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 2, O);
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  }


  // Fragment 1 encoded into 5 bits for 21 unique commands.
  switch ((Bits >> 16) & 31) {
  default: llvm_unreachable("Invalid command number.");
  case 0:
    // ADJCALLSTACKDOWN, SET, ADDCCri, ADDCCrr, ADDCri, ADDCrr, ADDEri, ADDEr...
    SStream_concat0(O, ", ");
    break;
  case 1:
    // ADJCALLSTACKUP, BA, BINDri, BINDrr, CALL, CALLri, CALLrr, CMASK16, CMA...
    return;
    break;
  case 2:
    // BCOND, BPFCC, CBCOND, FBCOND, TRAPri, TRAPrr
    SStream_concat0(O, " ");
    break;
  case 3:
    // BCONDA, BPFCCA, CBCONDA, FBCONDA
    SStream_concat0(O, ",a ");
    break;
  case 4:
    // BPFCCANT
    SStream_concat0(O, ",a,pn ");
    printOperand/* printOperand (+ ) */(MI, 2, O);
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  case 5:
    // BPFCCNT
    SStream_concat0(O, ",pn ");
    printOperand/* printOperand (+ ) */(MI, 2, O);
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  case 6:
    // BPICC, FMOVD_ICC, FMOVQ_ICC, FMOVS_ICC, MOVICCri, MOVICCrr, TICCri, TI...
    SStream_concat0(O, " %icc, ");
    break;
  case 7:
    // BPICCA
    SStream_concat0(O, ",a %icc, ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  case 8:
    // BPICCANT
    SStream_concat0(O, ",a,pn %icc, ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  case 9:
    // BPICCNT
    SStream_concat0(O, ",pn %icc, ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  case 10:
    // BPXCC, FMOVD_XCC, FMOVQ_XCC, FMOVS_XCC, MOVXCCri, MOVXCCrr, TXCCri, TX...
    SStream_concat0(O, " %xcc, ");
    break;
  case 11:
    // BPXCCA
    SStream_concat0(O, ",a %xcc, ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  case 12:
    // BPXCCANT
    SStream_concat0(O, ",a,pn %xcc, ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  case 13:
    // BPXCCNT
    SStream_concat0(O, ",pn %xcc, ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  case 14:
    // CASAasi10
    SStream_concat0(O, "] 10, ");
    printOperand/* printOperand (+ ) */(MI, 2, O);
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  case 15:
    // CASArr, LDArr, LDDArr, LDDFArr, LDFArr, LDQFArr, LDSBArr, LDSHArr, LDS...
    SStream_concat0(O, "] ");
    break;
  case 16:
    // CASXrr, CASrr, LDCri, LDCrr, LDDCri, LDDCrr, LDDFri, LDDFrr, LDDri, LD...
    SStream_concat0(O, "], ");
    break;
  case 17:
    // FMOVD_FCC, FMOVQ_FCC, FMOVS_FCC, MOVFCCri, MOVFCCrr
    SStream_concat0(O, " %fcc0, ");
    printOperand/* printOperand (+ ) */(MI, 1, O);
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  case 18:
    // LDCSRri, LDCSRrr
    SStream_concat0(O, "], %csr");
    return;
    break;
  case 19:
    // LDFSRri, LDFSRrr, LDXFSRri, LDXFSRrr
    SStream_concat0(O, "], %fsr");
    return;
    break;
  case 20:
    // STBri, STBrr, STCSRri, STCSRrr, STCri, STCrr, STDCQri, STDCQrr, STDCri...
    SStream_concat0(O, "]");
    return;
    break;
  }


  // Fragment 2 encoded into 3 bits for 5 unique commands.
  switch ((Bits >> 21) & 7) {
  default: llvm_unreachable("Invalid command number.");
  case 0:
    // ADJCALLSTACKDOWN, BPGEZapn, BPGEZapt, BPGEZnapn, BPGEZnapt, BPGZapn, B...
    printOperand/* printOperand (+ ) */(MI, 1, O);
    break;
  case 1:
    // SET, BCOND, BCONDA, BPICC, BPXCC, CBCOND, CBCONDA, FABSD, FABSQ, FABSS...
    printOperand/* printOperand (+ ) */(MI, 0, O);
    break;
  case 2:
    // ADDCCri, ADDCCrr, ADDCri, ADDCrr, ADDEri, ADDErr, ADDXC, ADDXCCC, ADDX...
    printOperand/* printOperand (+ ) */(MI, 2, O);
    break;
  case 3:
    // CASArr
    printOperand/* printOperand (+ ) */(MI, 4, O);
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 2, O);
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  case 4:
    // LDArr, LDDArr, LDDFArr, LDFArr, LDQFArr, LDSBArr, LDSHArr, LDSTUBArr, ...
    printOperand/* printOperand (+ ) */(MI, 3, O);
    break;
  }


  // Fragment 3 encoded into 3 bits for 6 unique commands.
  switch ((Bits >> 24) & 7) {
  default: llvm_unreachable("Invalid command number.");
  case 0:
    // ADJCALLSTACKDOWN, SET, BCOND, BCONDA, BPGEZapn, BPGEZapt, BPGEZnapn, B...
    return;
    break;
  case 1:
    // ADDCCri, ADDCCrr, ADDCri, ADDCrr, ADDEri, ADDErr, ADDXC, ADDXCCC, ADDX...
    SStream_concat0(O, ", ");
    break;
  case 2:
    // PWRPSRri, PWRPSRrr, WRPSRri, WRPSRrr
    SStream_concat0(O, ", %psr");
    return;
    break;
  case 3:
    // TICCri, TICCrr, TRAPri, TRAPrr, TXCCri, TXCCrr
    SStream_concat0(O, " + ");
    printOperand/* printOperand (+ ) */(MI, 1, O);
    return;
    break;
  case 4:
    // WRTBRri, WRTBRrr
    SStream_concat0(O, ", %tbr");
    return;
    break;
  case 5:
    // WRWIMri, WRWIMrr
    SStream_concat0(O, ", %wim");
    return;
    break;
  }


  // Fragment 4 encoded into 2 bits for 3 unique commands.
  switch ((Bits >> 27) & 3) {
  default: llvm_unreachable("Invalid command number.");
  case 0:
    // ADDCCri, ADDCCrr, ADDCri, ADDCrr, ADDEri, ADDErr, ADDXC, ADDXCCC, ADDX...
    printOperand/* printOperand (+ ) */(MI, 0, O);
    break;
  case 1:
    // FLCMPD, FLCMPS, V9FCMPD, V9FCMPED, V9FCMPEQ, V9FCMPES, V9FCMPQ, V9FCMP...
    printOperand/* printOperand (+ ) */(MI, 2, O);
    return;
    break;
  case 2:
    // TLS_LDXrr, TLS_LDrr
    printOperand/* printOperand (+ ) */(MI, 3, O);
    return;
    break;
  }


  // Fragment 5 encoded into 1 bits for 2 unique commands.
  if ((Bits >> 29) & 1) {
    // TLS_ADDXrr, TLS_ADDrr
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 3, O);
    return;
  } else {
    // ADDCCri, ADDCCrr, ADDCri, ADDCrr, ADDEri, ADDErr, ADDXC, ADDXCCC, ADDX...
    return;
  }

}


/// getRegisterName - This method is automatically generated by tblgen
/// from the register set description.  This returns the assembler name
/// for the specified register.
const char *getRegisterName(unsigned RegNo) {
  assert(RegNo && RegNo < 237 && "Invalid register number!");


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
  static const char AsmStrs[] = {
  /* 0 */ "C10\0"
  /* 4 */ "F10\0"
  /* 8 */ "ASR10\0"
  /* 14 */ "C20\0"
  /* 18 */ "F20\0"
  /* 22 */ "ASR20\0"
  /* 28 */ "C30\0"
  /* 32 */ "F30\0"
  /* 36 */ "ASR30\0"
  /* 42 */ "F40\0"
  /* 46 */ "F50\0"
  /* 50 */ "F60\0"
  /* 54 */ "FCC0\0"
  /* 59 */ "F0\0"
  /* 62 */ "G0\0"
  /* 65 */ "I0\0"
  /* 68 */ "L0\0"
  /* 71 */ "O0\0"
  /* 74 */ "C11\0"
  /* 78 */ "F11\0"
  /* 82 */ "ASR11\0"
  /* 88 */ "C21\0"
  /* 92 */ "F21\0"
  /* 96 */ "ASR21\0"
  /* 102 */ "C31\0"
  /* 106 */ "F31\0"
  /* 110 */ "ASR31\0"
  /* 116 */ "FCC1\0"
  /* 121 */ "F1\0"
  /* 124 */ "G1\0"
  /* 127 */ "I1\0"
  /* 130 */ "L1\0"
  /* 133 */ "O1\0"
  /* 136 */ "ASR1\0"
  /* 141 */ "C12\0"
  /* 145 */ "F12\0"
  /* 149 */ "ASR12\0"
  /* 155 */ "C22\0"
  /* 159 */ "F22\0"
  /* 163 */ "ASR22\0"
  /* 169 */ "F32\0"
  /* 173 */ "F42\0"
  /* 177 */ "F52\0"
  /* 181 */ "F62\0"
  /* 185 */ "FCC2\0"
  /* 190 */ "F2\0"
  /* 193 */ "G2\0"
  /* 196 */ "I2\0"
  /* 199 */ "L2\0"
  /* 202 */ "O2\0"
  /* 205 */ "ASR2\0"
  /* 210 */ "C13\0"
  /* 214 */ "F13\0"
  /* 218 */ "ASR13\0"
  /* 224 */ "C23\0"
  /* 228 */ "F23\0"
  /* 232 */ "ASR23\0"
  /* 238 */ "FCC3\0"
  /* 243 */ "F3\0"
  /* 246 */ "G3\0"
  /* 249 */ "I3\0"
  /* 252 */ "L3\0"
  /* 255 */ "O3\0"
  /* 258 */ "ASR3\0"
  /* 263 */ "C14\0"
  /* 267 */ "F14\0"
  /* 271 */ "ASR14\0"
  /* 277 */ "C24\0"
  /* 281 */ "F24\0"
  /* 285 */ "ASR24\0"
  /* 291 */ "F34\0"
  /* 295 */ "F44\0"
  /* 299 */ "F54\0"
  /* 303 */ "C4\0"
  /* 306 */ "F4\0"
  /* 309 */ "G4\0"
  /* 312 */ "I4\0"
  /* 315 */ "L4\0"
  /* 318 */ "O4\0"
  /* 321 */ "ASR4\0"
  /* 326 */ "C15\0"
  /* 330 */ "F15\0"
  /* 334 */ "ASR15\0"
  /* 340 */ "C25\0"
  /* 344 */ "F25\0"
  /* 348 */ "ASR25\0"
  /* 354 */ "C5\0"
  /* 357 */ "F5\0"
  /* 360 */ "G5\0"
  /* 363 */ "I5\0"
  /* 366 */ "L5\0"
  /* 369 */ "O5\0"
  /* 372 */ "ASR5\0"
  /* 377 */ "C16\0"
  /* 381 */ "F16\0"
  /* 385 */ "ASR16\0"
  /* 391 */ "C26\0"
  /* 395 */ "F26\0"
  /* 399 */ "ASR26\0"
  /* 405 */ "F36\0"
  /* 409 */ "F46\0"
  /* 413 */ "F56\0"
  /* 417 */ "C6\0"
  /* 420 */ "F6\0"
  /* 423 */ "G6\0"
  /* 426 */ "I6\0"
  /* 429 */ "L6\0"
  /* 432 */ "O6\0"
  /* 435 */ "ASR6\0"
  /* 440 */ "C17\0"
  /* 444 */ "F17\0"
  /* 448 */ "ASR17\0"
  /* 454 */ "C27\0"
  /* 458 */ "F27\0"
  /* 462 */ "ASR27\0"
  /* 468 */ "C7\0"
  /* 471 */ "F7\0"
  /* 474 */ "G7\0"
  /* 477 */ "I7\0"
  /* 480 */ "L7\0"
  /* 483 */ "O7\0"
  /* 486 */ "ASR7\0"
  /* 491 */ "C18\0"
  /* 495 */ "F18\0"
  /* 499 */ "ASR18\0"
  /* 505 */ "C28\0"
  /* 509 */ "F28\0"
  /* 513 */ "ASR28\0"
  /* 519 */ "F38\0"
  /* 523 */ "F48\0"
  /* 527 */ "F58\0"
  /* 531 */ "C8\0"
  /* 534 */ "F8\0"
  /* 537 */ "ASR8\0"
  /* 542 */ "C19\0"
  /* 546 */ "F19\0"
  /* 550 */ "ASR19\0"
  /* 556 */ "C29\0"
  /* 560 */ "F29\0"
  /* 564 */ "ASR29\0"
  /* 570 */ "C9\0"
  /* 573 */ "F9\0"
  /* 576 */ "ASR9\0"
  /* 581 */ "TBA\0"
  /* 585 */ "ICC\0"
  /* 589 */ "TNPC\0"
  /* 594 */ "TPC\0"
  /* 598 */ "CANRESTORE\0"
  /* 609 */ "PSTATE\0"
  /* 616 */ "TSTATE\0"
  /* 623 */ "WSTATE\0"
  /* 630 */ "CANSAVE\0"
  /* 638 */ "TICK\0"
  /* 643 */ "PIL\0"
  /* 647 */ "TL\0"
  /* 650 */ "WIM\0"
  /* 654 */ "CLEANWIN\0"
  /* 663 */ "OTHERWIN\0"
  /* 672 */ "FP\0"
  /* 675 */ "SP\0"
  /* 678 */ "CWP\0"
  /* 682 */ "FQ\0"
  /* 685 */ "CPQ\0"
  /* 689 */ "TBR\0"
  /* 693 */ "FSR\0"
  /* 697 */ "CPSR\0"
  /* 702 */ "TT\0"
  /* 705 */ "Y\0"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

  static const uint16_t RegAsmOffset[] = {
    598, 630, 654, 685, 697, 678, 682, 693, 585, 663, 591, 643, 698, 609, 
    581, 689, 638, 647, 589, 594, 616, 702, 650, 623, 705, 136, 205, 258, 
    321, 372, 435, 486, 537, 576, 8, 82, 149, 218, 271, 334, 385, 448, 
    499, 550, 22, 96, 163, 232, 285, 348, 399, 462, 513, 564, 36, 110, 
    56, 118, 187, 240, 303, 354, 417, 468, 531, 570, 0, 74, 141, 210, 
    263, 326, 377, 440, 491, 542, 14, 88, 155, 224, 277, 340, 391, 454, 
    505, 556, 28, 102, 59, 190, 306, 420, 534, 4, 145, 267, 381, 495, 
    18, 159, 281, 395, 509, 32, 169, 291, 405, 519, 42, 173, 295, 409, 
    523, 46, 177, 299, 413, 527, 50, 181, 59, 121, 190, 243, 306, 357, 
    420, 471, 534, 573, 4, 78, 145, 214, 267, 330, 381, 444, 495, 546, 
    18, 92, 159, 228, 281, 344, 395, 458, 509, 560, 32, 106, 54, 116, 
    185, 238, 62, 124, 193, 246, 309, 360, 423, 474, 65, 127, 196, 249, 
    312, 363, 672, 477, 68, 130, 199, 252, 315, 366, 429, 480, 71, 133, 
    202, 255, 318, 369, 675, 483, 59, 306, 534, 145, 381, 18, 281, 509, 
    169, 405, 42, 295, 523, 177, 413, 50, 56, 187, 303, 417, 531, 0, 
    141, 263, 377, 491, 14, 155, 277, 391, 505, 28, 62, 193, 309, 423, 
    65, 196, 312, 426, 68, 199, 315, 429, 71, 202, 318, 432, 
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
  static const PatternsForOpcode OpToPatterns[] = {
    {SP_BCOND, 0, 16 },
    {SP_BCONDA, 16, 16 },
    {SP_BPFCCANT, 32, 16 },
    {SP_BPFCCNT, 48, 16 },
    {SP_BPICCANT, 64, 16 },
    {SP_BPICCNT, 80, 16 },
    {SP_BPXCCANT, 96, 16 },
    {SP_BPXCCNT, 112, 16 },
    {SP_FMOVD_ICC, 128, 16 },
    {SP_FMOVD_XCC, 144, 16 },
    {SP_FMOVQ_ICC, 160, 16 },
    {SP_FMOVQ_XCC, 176, 16 },
    {SP_FMOVS_ICC, 192, 16 },
    {SP_FMOVS_XCC, 208, 16 },
    {SP_MOVICCri, 224, 16 },
    {SP_MOVICCrr, 240, 16 },
    {SP_MOVXCCri, 256, 16 },
    {SP_MOVXCCrr, 272, 16 },
    {SP_ORCCrr, 288, 1 },
    {SP_ORri, 289, 1 },
    {SP_ORrr, 290, 1 },
    {SP_RESTORErr, 291, 1 },
    {SP_RET, 292, 1 },
    {SP_RETL, 293, 1 },
    {SP_SAVErr, 294, 1 },
    {SP_TICCri, 295, 32 },
    {SP_TICCrr, 327, 32 },
    {SP_TRAPri, 359, 32 },
    {SP_TRAPrr, 391, 32 },
    {SP_TXCCri, 423, 32 },
    {SP_TXCCrr, 455, 32 },
    {SP_V9FCMPD, 487, 1 },
    {SP_V9FCMPED, 488, 1 },
    {SP_V9FCMPEQ, 489, 1 },
    {SP_V9FCMPES, 490, 1 },
    {SP_V9FCMPQ, 491, 1 },
    {SP_V9FCMPS, 492, 1 },
    {SP_V9FMOVD_FCC, 493, 16 },
    {SP_V9FMOVQ_FCC, 509, 16 },
    {SP_V9FMOVS_FCC, 525, 16 },
    {SP_V9MOVFCCri, 541, 16 },
    {SP_V9MOVFCCrr, 557, 16 },
  };

  static const AliasPattern Patterns[] = {
    // SP::BCOND - 0
    {0, 0, 2, 2 },
    {6, 2, 2, 2 },
    {12, 4, 2, 2 },
    {19, 6, 2, 2 },
    {25, 8, 2, 2 },
    {31, 10, 2, 2 },
    {38, 12, 2, 2 },
    {45, 14, 2, 2 },
    {51, 16, 2, 2 },
    {58, 18, 2, 2 },
    {66, 20, 2, 2 },
    {73, 22, 2, 2 },
    {80, 24, 2, 2 },
    {88, 26, 2, 2 },
    {96, 28, 2, 2 },
    {103, 30, 2, 2 },
    // SP::BCONDA - 16
    {110, 32, 2, 2 },
    {118, 34, 2, 2 },
    {126, 36, 2, 2 },
    {135, 38, 2, 2 },
    {143, 40, 2, 2 },
    {151, 42, 2, 2 },
    {160, 44, 2, 2 },
    {169, 46, 2, 2 },
    {177, 48, 2, 2 },
    {186, 50, 2, 2 },
    {196, 52, 2, 2 },
    {205, 54, 2, 2 },
    {214, 56, 2, 2 },
    {224, 58, 2, 2 },
    {234, 60, 2, 2 },
    {243, 62, 2, 2 },
    // SP::BPFCCANT - 32
    {252, 64, 3, 4 },
    {268, 68, 3, 4 },
    {284, 72, 3, 4 },
    {300, 76, 3, 4 },
    {316, 80, 3, 4 },
    {333, 84, 3, 4 },
    {349, 88, 3, 4 },
    {366, 92, 3, 4 },
    {383, 96, 3, 4 },
    {400, 100, 3, 4 },
    {416, 104, 3, 4 },
    {433, 108, 3, 4 },
    {450, 112, 3, 4 },
    {468, 116, 3, 4 },
    {485, 120, 3, 4 },
    {503, 124, 3, 4 },
    // SP::BPFCCNT - 48
    {519, 128, 3, 4 },
    {533, 132, 3, 4 },
    {547, 136, 3, 4 },
    {561, 140, 3, 4 },
    {575, 144, 3, 4 },
    {590, 148, 3, 4 },
    {604, 152, 3, 4 },
    {619, 156, 3, 4 },
    {634, 160, 3, 4 },
    {649, 164, 3, 4 },
    {663, 168, 3, 4 },
    {678, 172, 3, 4 },
    {693, 176, 3, 4 },
    {709, 180, 3, 4 },
    {724, 184, 3, 4 },
    {740, 188, 3, 4 },
    // SP::BPICCANT - 64
    {754, 192, 2, 3 },
    {771, 195, 2, 3 },
    {788, 198, 2, 3 },
    {806, 201, 2, 3 },
    {823, 204, 2, 3 },
    {840, 207, 2, 3 },
    {858, 210, 2, 3 },
    {876, 213, 2, 3 },
    {893, 216, 2, 3 },
    {911, 219, 2, 3 },
    {930, 222, 2, 3 },
    {948, 225, 2, 3 },
    {966, 228, 2, 3 },
    {985, 231, 2, 3 },
    {1004, 234, 2, 3 },
    {1022, 237, 2, 3 },
    // SP::BPICCNT - 80
    {1040, 240, 2, 3 },
    {1055, 243, 2, 3 },
    {1070, 246, 2, 3 },
    {1086, 249, 2, 3 },
    {1101, 252, 2, 3 },
    {1116, 255, 2, 3 },
    {1132, 258, 2, 3 },
    {1148, 261, 2, 3 },
    {1163, 264, 2, 3 },
    {1179, 267, 2, 3 },
    {1196, 270, 2, 3 },
    {1212, 273, 2, 3 },
    {1228, 276, 2, 3 },
    {1245, 279, 2, 3 },
    {1262, 282, 2, 3 },
    {1278, 285, 2, 3 },
    // SP::BPXCCANT - 96
    {1294, 288, 2, 2 },
    {1311, 290, 2, 2 },
    {1328, 292, 2, 2 },
    {1346, 294, 2, 2 },
    {1363, 296, 2, 2 },
    {1380, 298, 2, 2 },
    {1398, 300, 2, 2 },
    {1416, 302, 2, 2 },
    {1433, 304, 2, 2 },
    {1451, 306, 2, 2 },
    {1470, 308, 2, 2 },
    {1488, 310, 2, 2 },
    {1506, 312, 2, 2 },
    {1525, 314, 2, 2 },
    {1544, 316, 2, 2 },
    {1562, 318, 2, 2 },
    // SP::BPXCCNT - 112
    {1580, 320, 2, 2 },
    {1595, 322, 2, 2 },
    {1610, 324, 2, 2 },
    {1626, 326, 2, 2 },
    {1641, 328, 2, 2 },
    {1656, 330, 2, 2 },
    {1672, 332, 2, 2 },
    {1688, 334, 2, 2 },
    {1703, 336, 2, 2 },
    {1719, 338, 2, 2 },
    {1736, 340, 2, 2 },
    {1752, 342, 2, 2 },
    {1768, 344, 2, 2 },
    {1785, 346, 2, 2 },
    {1802, 348, 2, 2 },
    {1818, 350, 2, 2 },
    // SP::FMOVD_ICC - 128
    {1834, 352, 4, 5 },
    {1854, 357, 4, 5 },
    {1874, 362, 4, 5 },
    {1895, 367, 4, 5 },
    {1915, 372, 4, 5 },
    {1935, 377, 4, 5 },
    {1956, 382, 4, 5 },
    {1977, 387, 4, 5 },
    {1997, 392, 4, 5 },
    {2018, 397, 4, 5 },
    {2040, 402, 4, 5 },
    {2061, 407, 4, 5 },
    {2082, 412, 4, 5 },
    {2104, 417, 4, 5 },
    {2126, 422, 4, 5 },
    {2147, 427, 4, 5 },
    // SP::FMOVD_XCC - 144
    {2168, 432, 4, 4 },
    {2188, 436, 4, 4 },
    {2208, 440, 4, 4 },
    {2229, 444, 4, 4 },
    {2249, 448, 4, 4 },
    {2269, 452, 4, 4 },
    {2290, 456, 4, 4 },
    {2311, 460, 4, 4 },
    {2331, 464, 4, 4 },
    {2352, 468, 4, 4 },
    {2374, 472, 4, 4 },
    {2395, 476, 4, 4 },
    {2416, 480, 4, 4 },
    {2438, 484, 4, 4 },
    {2460, 488, 4, 4 },
    {2481, 492, 4, 4 },
    // SP::FMOVQ_ICC - 160
    {2502, 496, 4, 5 },
    {2522, 501, 4, 5 },
    {2542, 506, 4, 5 },
    {2563, 511, 4, 5 },
    {2583, 516, 4, 5 },
    {2603, 521, 4, 5 },
    {2624, 526, 4, 5 },
    {2645, 531, 4, 5 },
    {2665, 536, 4, 5 },
    {2686, 541, 4, 5 },
    {2708, 546, 4, 5 },
    {2729, 551, 4, 5 },
    {2750, 556, 4, 5 },
    {2772, 561, 4, 5 },
    {2794, 566, 4, 5 },
    {2815, 571, 4, 5 },
    // SP::FMOVQ_XCC - 176
    {2836, 576, 4, 4 },
    {2856, 580, 4, 4 },
    {2876, 584, 4, 4 },
    {2897, 588, 4, 4 },
    {2917, 592, 4, 4 },
    {2937, 596, 4, 4 },
    {2958, 600, 4, 4 },
    {2979, 604, 4, 4 },
    {2999, 608, 4, 4 },
    {3020, 612, 4, 4 },
    {3042, 616, 4, 4 },
    {3063, 620, 4, 4 },
    {3084, 624, 4, 4 },
    {3106, 628, 4, 4 },
    {3128, 632, 4, 4 },
    {3149, 636, 4, 4 },
    // SP::FMOVS_ICC - 192
    {3170, 640, 4, 5 },
    {3190, 645, 4, 5 },
    {3210, 650, 4, 5 },
    {3231, 655, 4, 5 },
    {3251, 660, 4, 5 },
    {3271, 665, 4, 5 },
    {3292, 670, 4, 5 },
    {3313, 675, 4, 5 },
    {3333, 680, 4, 5 },
    {3354, 685, 4, 5 },
    {3376, 690, 4, 5 },
    {3397, 695, 4, 5 },
    {3418, 700, 4, 5 },
    {3440, 705, 4, 5 },
    {3462, 710, 4, 5 },
    {3483, 715, 4, 5 },
    // SP::FMOVS_XCC - 208
    {3504, 720, 4, 4 },
    {3524, 724, 4, 4 },
    {3544, 728, 4, 4 },
    {3565, 732, 4, 4 },
    {3585, 736, 4, 4 },
    {3605, 740, 4, 4 },
    {3626, 744, 4, 4 },
    {3647, 748, 4, 4 },
    {3667, 752, 4, 4 },
    {3688, 756, 4, 4 },
    {3710, 760, 4, 4 },
    {3731, 764, 4, 4 },
    {3752, 768, 4, 4 },
    {3774, 772, 4, 4 },
    {3796, 776, 4, 4 },
    {3817, 780, 4, 4 },
    // SP::MOVICCri - 224
    {3838, 784, 4, 5 },
    {3856, 789, 4, 5 },
    {3874, 794, 4, 5 },
    {3893, 799, 4, 5 },
    {3911, 804, 4, 5 },
    {3929, 809, 4, 5 },
    {3948, 814, 4, 5 },
    {3967, 819, 4, 5 },
    {3985, 824, 4, 5 },
    {4004, 829, 4, 5 },
    {4024, 834, 4, 5 },
    {4043, 839, 4, 5 },
    {4062, 844, 4, 5 },
    {4082, 849, 4, 5 },
    {4102, 854, 4, 5 },
    {4121, 859, 4, 5 },
    // SP::MOVICCrr - 240
    {3838, 864, 4, 5 },
    {3856, 869, 4, 5 },
    {3874, 874, 4, 5 },
    {3893, 879, 4, 5 },
    {3911, 884, 4, 5 },
    {3929, 889, 4, 5 },
    {3948, 894, 4, 5 },
    {3967, 899, 4, 5 },
    {3985, 904, 4, 5 },
    {4004, 909, 4, 5 },
    {4024, 914, 4, 5 },
    {4043, 919, 4, 5 },
    {4062, 924, 4, 5 },
    {4082, 929, 4, 5 },
    {4102, 934, 4, 5 },
    {4121, 939, 4, 5 },
    // SP::MOVXCCri - 256
    {4140, 944, 4, 4 },
    {4158, 948, 4, 4 },
    {4176, 952, 4, 4 },
    {4195, 956, 4, 4 },
    {4213, 960, 4, 4 },
    {4231, 964, 4, 4 },
    {4250, 968, 4, 4 },
    {4269, 972, 4, 4 },
    {4287, 976, 4, 4 },
    {4306, 980, 4, 4 },
    {4326, 984, 4, 4 },
    {4345, 988, 4, 4 },
    {4364, 992, 4, 4 },
    {4384, 996, 4, 4 },
    {4404, 1000, 4, 4 },
    {4423, 1004, 4, 4 },
    // SP::MOVXCCrr - 272
    {4140, 1008, 4, 4 },
    {4158, 1012, 4, 4 },
    {4176, 1016, 4, 4 },
    {4195, 1020, 4, 4 },
    {4213, 1024, 4, 4 },
    {4231, 1028, 4, 4 },
    {4250, 1032, 4, 4 },
    {4269, 1036, 4, 4 },
    {4287, 1040, 4, 4 },
    {4306, 1044, 4, 4 },
    {4326, 1048, 4, 4 },
    {4345, 1052, 4, 4 },
    {4364, 1056, 4, 4 },
    {4384, 1060, 4, 4 },
    {4404, 1064, 4, 4 },
    {4423, 1068, 4, 4 },
    // SP::ORCCrr - 288
    {4442, 1072, 3, 3 },
    // SP::ORri - 289
    {4449, 1075, 3, 2 },
    // SP::ORrr - 290
    {4449, 1077, 3, 3 },
    // SP::RESTORErr - 291
    {4460, 1080, 3, 3 },
    // SP::RET - 292
    {4468, 1083, 1, 1 },
    // SP::RETL - 293
    {4472, 1084, 1, 1 },
    // SP::SAVErr - 294
    {4477, 1085, 3, 3 },
    // SP::TICCri - 295
    {4482, 1088, 3, 4 },
    {4494, 1092, 3, 4 },
    {4511, 1096, 3, 4 },
    {4523, 1100, 3, 4 },
    {4540, 1104, 3, 4 },
    {4553, 1108, 3, 4 },
    {4571, 1112, 3, 4 },
    {4583, 1116, 3, 4 },
    {4600, 1120, 3, 4 },
    {4612, 1124, 3, 4 },
    {4629, 1128, 3, 4 },
    {4642, 1132, 3, 4 },
    {4660, 1136, 3, 4 },
    {4673, 1140, 3, 4 },
    {4691, 1144, 3, 4 },
    {4703, 1148, 3, 4 },
    {4720, 1152, 3, 4 },
    {4733, 1156, 3, 4 },
    {4751, 1160, 3, 4 },
    {4765, 1164, 3, 4 },
    {4784, 1168, 3, 4 },
    {4797, 1172, 3, 4 },
    {4815, 1176, 3, 4 },
    {4828, 1180, 3, 4 },
    {4846, 1184, 3, 4 },
    {4860, 1188, 3, 4 },
    {4879, 1192, 3, 4 },
    {4893, 1196, 3, 4 },
    {4912, 1200, 3, 4 },
    {4925, 1204, 3, 4 },
    {4943, 1208, 3, 4 },
    {4956, 1212, 3, 4 },
    // SP::TICCrr - 327
    {4482, 1216, 3, 4 },
    {4494, 1220, 3, 4 },
    {4511, 1224, 3, 4 },
    {4523, 1228, 3, 4 },
    {4540, 1232, 3, 4 },
    {4553, 1236, 3, 4 },
    {4571, 1240, 3, 4 },
    {4583, 1244, 3, 4 },
    {4600, 1248, 3, 4 },
    {4612, 1252, 3, 4 },
    {4629, 1256, 3, 4 },
    {4642, 1260, 3, 4 },
    {4660, 1264, 3, 4 },
    {4673, 1268, 3, 4 },
    {4691, 1272, 3, 4 },
    {4703, 1276, 3, 4 },
    {4720, 1280, 3, 4 },
    {4733, 1284, 3, 4 },
    {4751, 1288, 3, 4 },
    {4765, 1292, 3, 4 },
    {4784, 1296, 3, 4 },
    {4797, 1300, 3, 4 },
    {4815, 1304, 3, 4 },
    {4828, 1308, 3, 4 },
    {4846, 1312, 3, 4 },
    {4860, 1316, 3, 4 },
    {4879, 1320, 3, 4 },
    {4893, 1324, 3, 4 },
    {4912, 1328, 3, 4 },
    {4925, 1332, 3, 4 },
    {4943, 1336, 3, 4 },
    {4956, 1340, 3, 4 },
    // SP::TRAPri - 359
    {4974, 1344, 3, 3 },
    {4980, 1347, 3, 3 },
    {4991, 1350, 3, 3 },
    {4997, 1353, 3, 3 },
    {5008, 1356, 3, 3 },
    {5015, 1359, 3, 3 },
    {5027, 1362, 3, 3 },
    {5033, 1365, 3, 3 },
    {5044, 1368, 3, 3 },
    {5050, 1371, 3, 3 },
    {5061, 1374, 3, 3 },
    {5068, 1377, 3, 3 },
    {5080, 1380, 3, 3 },
    {5087, 1383, 3, 3 },
    {5099, 1386, 3, 3 },
    {5105, 1389, 3, 3 },
    {5116, 1392, 3, 3 },
    {5123, 1395, 3, 3 },
    {5135, 1398, 3, 3 },
    {5143, 1401, 3, 3 },
    {5156, 1404, 3, 3 },
    {5163, 1407, 3, 3 },
    {5175, 1410, 3, 3 },
    {5182, 1413, 3, 3 },
    {5194, 1416, 3, 3 },
    {5202, 1419, 3, 3 },
    {5215, 1422, 3, 3 },
    {5223, 1425, 3, 3 },
    {5236, 1428, 3, 3 },
    {5243, 1431, 3, 3 },
    {5255, 1434, 3, 3 },
    {5262, 1437, 3, 3 },
    // SP::TRAPrr - 391
    {4974, 1440, 3, 3 },
    {4980, 1443, 3, 3 },
    {4991, 1446, 3, 3 },
    {4997, 1449, 3, 3 },
    {5008, 1452, 3, 3 },
    {5015, 1455, 3, 3 },
    {5027, 1458, 3, 3 },
    {5033, 1461, 3, 3 },
    {5044, 1464, 3, 3 },
    {5050, 1467, 3, 3 },
    {5061, 1470, 3, 3 },
    {5068, 1473, 3, 3 },
    {5080, 1476, 3, 3 },
    {5087, 1479, 3, 3 },
    {5099, 1482, 3, 3 },
    {5105, 1485, 3, 3 },
    {5116, 1488, 3, 3 },
    {5123, 1491, 3, 3 },
    {5135, 1494, 3, 3 },
    {5143, 1497, 3, 3 },
    {5156, 1500, 3, 3 },
    {5163, 1503, 3, 3 },
    {5175, 1506, 3, 3 },
    {5182, 1509, 3, 3 },
    {5194, 1512, 3, 3 },
    {5202, 1515, 3, 3 },
    {5215, 1518, 3, 3 },
    {5223, 1521, 3, 3 },
    {5236, 1524, 3, 3 },
    {5243, 1527, 3, 3 },
    {5255, 1530, 3, 3 },
    {5262, 1533, 3, 3 },
    // SP::TXCCri - 423
    {5274, 1536, 3, 4 },
    {5286, 1540, 3, 4 },
    {5303, 1544, 3, 4 },
    {5315, 1548, 3, 4 },
    {5332, 1552, 3, 4 },
    {5345, 1556, 3, 4 },
    {5363, 1560, 3, 4 },
    {5375, 1564, 3, 4 },
    {5392, 1568, 3, 4 },
    {5404, 1572, 3, 4 },
    {5421, 1576, 3, 4 },
    {5434, 1580, 3, 4 },
    {5452, 1584, 3, 4 },
    {5465, 1588, 3, 4 },
    {5483, 1592, 3, 4 },
    {5495, 1596, 3, 4 },
    {5512, 1600, 3, 4 },
    {5525, 1604, 3, 4 },
    {5543, 1608, 3, 4 },
    {5557, 1612, 3, 4 },
    {5576, 1616, 3, 4 },
    {5589, 1620, 3, 4 },
    {5607, 1624, 3, 4 },
    {5620, 1628, 3, 4 },
    {5638, 1632, 3, 4 },
    {5652, 1636, 3, 4 },
    {5671, 1640, 3, 4 },
    {5685, 1644, 3, 4 },
    {5704, 1648, 3, 4 },
    {5717, 1652, 3, 4 },
    {5735, 1656, 3, 4 },
    {5748, 1660, 3, 4 },
    // SP::TXCCrr - 455
    {5274, 1664, 3, 4 },
    {5286, 1668, 3, 4 },
    {5303, 1672, 3, 4 },
    {5315, 1676, 3, 4 },
    {5332, 1680, 3, 4 },
    {5345, 1684, 3, 4 },
    {5363, 1688, 3, 4 },
    {5375, 1692, 3, 4 },
    {5392, 1696, 3, 4 },
    {5404, 1700, 3, 4 },
    {5421, 1704, 3, 4 },
    {5434, 1708, 3, 4 },
    {5452, 1712, 3, 4 },
    {5465, 1716, 3, 4 },
    {5483, 1720, 3, 4 },
    {5495, 1724, 3, 4 },
    {5512, 1728, 3, 4 },
    {5525, 1732, 3, 4 },
    {5543, 1736, 3, 4 },
    {5557, 1740, 3, 4 },
    {5576, 1744, 3, 4 },
    {5589, 1748, 3, 4 },
    {5607, 1752, 3, 4 },
    {5620, 1756, 3, 4 },
    {5638, 1760, 3, 4 },
    {5652, 1764, 3, 4 },
    {5671, 1768, 3, 4 },
    {5685, 1772, 3, 4 },
    {5704, 1776, 3, 4 },
    {5717, 1780, 3, 4 },
    {5735, 1784, 3, 4 },
    {5748, 1788, 3, 4 },
    // SP::V9FCMPD - 487
    {5766, 1792, 3, 3 },
    // SP::V9FCMPED - 488
    {5779, 1795, 3, 3 },
    // SP::V9FCMPEQ - 489
    {5793, 1798, 3, 3 },
    // SP::V9FCMPES - 490
    {5807, 1801, 3, 3 },
    // SP::V9FCMPQ - 491
    {5821, 1804, 3, 3 },
    // SP::V9FCMPS - 492
    {5834, 1807, 3, 3 },
    // SP::V9FMOVD_FCC - 493
    {5847, 1810, 5, 6 },
    {5865, 1816, 5, 6 },
    {5883, 1822, 5, 6 },
    {5901, 1828, 5, 6 },
    {5919, 1834, 5, 6 },
    {5938, 1840, 5, 6 },
    {5956, 1846, 5, 6 },
    {5975, 1852, 5, 6 },
    {5994, 1858, 5, 6 },
    {6013, 1864, 5, 6 },
    {6031, 1870, 5, 6 },
    {6050, 1876, 5, 6 },
    {6069, 1882, 5, 6 },
    {6089, 1888, 5, 6 },
    {6108, 1894, 5, 6 },
    {6128, 1900, 5, 6 },
    // SP::V9FMOVQ_FCC - 509
    {6146, 1906, 5, 6 },
    {6164, 1912, 5, 6 },
    {6182, 1918, 5, 6 },
    {6200, 1924, 5, 6 },
    {6218, 1930, 5, 6 },
    {6237, 1936, 5, 6 },
    {6255, 1942, 5, 6 },
    {6274, 1948, 5, 6 },
    {6293, 1954, 5, 6 },
    {6312, 1960, 5, 6 },
    {6330, 1966, 5, 6 },
    {6349, 1972, 5, 6 },
    {6368, 1978, 5, 6 },
    {6388, 1984, 5, 6 },
    {6407, 1990, 5, 6 },
    {6427, 1996, 5, 6 },
    // SP::V9FMOVS_FCC - 525
    {6445, 2002, 5, 6 },
    {6463, 2008, 5, 6 },
    {6481, 2014, 5, 6 },
    {6499, 2020, 5, 6 },
    {6517, 2026, 5, 6 },
    {6536, 2032, 5, 6 },
    {6554, 2038, 5, 6 },
    {6573, 2044, 5, 6 },
    {6592, 2050, 5, 6 },
    {6611, 2056, 5, 6 },
    {6629, 2062, 5, 6 },
    {6648, 2068, 5, 6 },
    {6667, 2074, 5, 6 },
    {6687, 2080, 5, 6 },
    {6706, 2086, 5, 6 },
    {6726, 2092, 5, 6 },
    // SP::V9MOVFCCri - 541
    {6744, 2098, 5, 6 },
    {6760, 2104, 5, 6 },
    {6776, 2110, 5, 6 },
    {6792, 2116, 5, 6 },
    {6808, 2122, 5, 6 },
    {6825, 2128, 5, 6 },
    {6841, 2134, 5, 6 },
    {6858, 2140, 5, 6 },
    {6875, 2146, 5, 6 },
    {6892, 2152, 5, 6 },
    {6908, 2158, 5, 6 },
    {6925, 2164, 5, 6 },
    {6942, 2170, 5, 6 },
    {6960, 2176, 5, 6 },
    {6977, 2182, 5, 6 },
    {6995, 2188, 5, 6 },
    // SP::V9MOVFCCrr - 557
    {6744, 2194, 5, 6 },
    {6760, 2200, 5, 6 },
    {6776, 2206, 5, 6 },
    {6792, 2212, 5, 6 },
    {6808, 2218, 5, 6 },
    {6825, 2224, 5, 6 },
    {6841, 2230, 5, 6 },
    {6858, 2236, 5, 6 },
    {6875, 2242, 5, 6 },
    {6892, 2248, 5, 6 },
    {6908, 2254, 5, 6 },
    {6925, 2260, 5, 6 },
    {6942, 2266, 5, 6 },
    {6960, 2272, 5, 6 },
    {6977, 2278, 5, 6 },
    {6995, 2284, 5, 6 },
  };

  static const AliasPatternCond Conds[] = {
    // (BCOND brtarget:$imm, 8) - 0
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    // (BCOND brtarget:$imm, 0) - 2
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    // (BCOND brtarget:$imm, 9) - 4
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    // (BCOND brtarget:$imm, 1) - 6
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    // (BCOND brtarget:$imm, 10) - 8
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    // (BCOND brtarget:$imm, 2) - 10
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    // (BCOND brtarget:$imm, 11) - 12
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    // (BCOND brtarget:$imm, 3) - 14
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    // (BCOND brtarget:$imm, 12) - 16
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    // (BCOND brtarget:$imm, 4) - 18
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    // (BCOND brtarget:$imm, 13) - 20
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    // (BCOND brtarget:$imm, 5) - 22
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    // (BCOND brtarget:$imm, 14) - 24
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    // (BCOND brtarget:$imm, 6) - 26
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    // (BCOND brtarget:$imm, 15) - 28
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    // (BCOND brtarget:$imm, 7) - 30
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    // (BCONDA brtarget:$imm, 8) - 32
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    // (BCONDA brtarget:$imm, 0) - 34
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    // (BCONDA brtarget:$imm, 9) - 36
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    // (BCONDA brtarget:$imm, 1) - 38
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    // (BCONDA brtarget:$imm, 10) - 40
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    // (BCONDA brtarget:$imm, 2) - 42
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    // (BCONDA brtarget:$imm, 11) - 44
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    // (BCONDA brtarget:$imm, 3) - 46
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    // (BCONDA brtarget:$imm, 12) - 48
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    // (BCONDA brtarget:$imm, 4) - 50
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    // (BCONDA brtarget:$imm, 13) - 52
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    // (BCONDA brtarget:$imm, 5) - 54
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    // (BCONDA brtarget:$imm, 14) - 56
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    // (BCONDA brtarget:$imm, 6) - 58
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    // (BCONDA brtarget:$imm, 15) - 60
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    // (BCONDA brtarget:$imm, 7) - 62
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    // (BPFCCANT brtarget:$imm, 8, FCCRegs:$cc) - 64
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCANT brtarget:$imm, 0, FCCRegs:$cc) - 68
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCANT brtarget:$imm, 7, FCCRegs:$cc) - 72
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCANT brtarget:$imm, 6, FCCRegs:$cc) - 76
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCANT brtarget:$imm, 5, FCCRegs:$cc) - 80
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCANT brtarget:$imm, 4, FCCRegs:$cc) - 84
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCANT brtarget:$imm, 3, FCCRegs:$cc) - 88
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCANT brtarget:$imm, 2, FCCRegs:$cc) - 92
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCANT brtarget:$imm, 1, FCCRegs:$cc) - 96
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCANT brtarget:$imm, 9, FCCRegs:$cc) - 100
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCANT brtarget:$imm, 10, FCCRegs:$cc) - 104
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCANT brtarget:$imm, 11, FCCRegs:$cc) - 108
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCANT brtarget:$imm, 12, FCCRegs:$cc) - 112
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCANT brtarget:$imm, 13, FCCRegs:$cc) - 116
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCANT brtarget:$imm, 14, FCCRegs:$cc) - 120
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCANT brtarget:$imm, 15, FCCRegs:$cc) - 124
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCNT brtarget:$imm, 8, FCCRegs:$cc) - 128
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCNT brtarget:$imm, 0, FCCRegs:$cc) - 132
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCNT brtarget:$imm, 7, FCCRegs:$cc) - 136
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCNT brtarget:$imm, 6, FCCRegs:$cc) - 140
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCNT brtarget:$imm, 5, FCCRegs:$cc) - 144
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCNT brtarget:$imm, 4, FCCRegs:$cc) - 148
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCNT brtarget:$imm, 3, FCCRegs:$cc) - 152
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCNT brtarget:$imm, 2, FCCRegs:$cc) - 156
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCNT brtarget:$imm, 1, FCCRegs:$cc) - 160
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCNT brtarget:$imm, 9, FCCRegs:$cc) - 164
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCNT brtarget:$imm, 10, FCCRegs:$cc) - 168
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCNT brtarget:$imm, 11, FCCRegs:$cc) - 172
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCNT brtarget:$imm, 12, FCCRegs:$cc) - 176
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCNT brtarget:$imm, 13, FCCRegs:$cc) - 180
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCNT brtarget:$imm, 14, FCCRegs:$cc) - 184
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPFCCNT brtarget:$imm, 15, FCCRegs:$cc) - 188
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCANT brtarget:$imm, 8) - 192
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCANT brtarget:$imm, 0) - 195
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCANT brtarget:$imm, 9) - 198
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCANT brtarget:$imm, 1) - 201
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCANT brtarget:$imm, 10) - 204
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCANT brtarget:$imm, 2) - 207
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCANT brtarget:$imm, 11) - 210
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCANT brtarget:$imm, 3) - 213
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCANT brtarget:$imm, 12) - 216
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCANT brtarget:$imm, 4) - 219
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCANT brtarget:$imm, 13) - 222
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCANT brtarget:$imm, 5) - 225
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCANT brtarget:$imm, 14) - 228
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCANT brtarget:$imm, 6) - 231
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCANT brtarget:$imm, 15) - 234
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCANT brtarget:$imm, 7) - 237
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCNT brtarget:$imm, 8) - 240
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCNT brtarget:$imm, 0) - 243
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCNT brtarget:$imm, 9) - 246
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCNT brtarget:$imm, 1) - 249
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCNT brtarget:$imm, 10) - 252
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCNT brtarget:$imm, 2) - 255
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCNT brtarget:$imm, 11) - 258
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCNT brtarget:$imm, 3) - 261
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCNT brtarget:$imm, 12) - 264
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCNT brtarget:$imm, 4) - 267
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCNT brtarget:$imm, 13) - 270
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCNT brtarget:$imm, 5) - 273
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCNT brtarget:$imm, 14) - 276
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCNT brtarget:$imm, 6) - 279
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCNT brtarget:$imm, 15) - 282
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPICCNT brtarget:$imm, 7) - 285
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (BPXCCANT brtarget:$imm, 8) - 288
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    // (BPXCCANT brtarget:$imm, 0) - 290
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    // (BPXCCANT brtarget:$imm, 9) - 292
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    // (BPXCCANT brtarget:$imm, 1) - 294
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    // (BPXCCANT brtarget:$imm, 10) - 296
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    // (BPXCCANT brtarget:$imm, 2) - 298
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    // (BPXCCANT brtarget:$imm, 11) - 300
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    // (BPXCCANT brtarget:$imm, 3) - 302
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    // (BPXCCANT brtarget:$imm, 12) - 304
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    // (BPXCCANT brtarget:$imm, 4) - 306
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    // (BPXCCANT brtarget:$imm, 13) - 308
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    // (BPXCCANT brtarget:$imm, 5) - 310
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    // (BPXCCANT brtarget:$imm, 14) - 312
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    // (BPXCCANT brtarget:$imm, 6) - 314
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    // (BPXCCANT brtarget:$imm, 15) - 316
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    // (BPXCCANT brtarget:$imm, 7) - 318
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    // (BPXCCNT brtarget:$imm, 8) - 320
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    // (BPXCCNT brtarget:$imm, 0) - 322
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    // (BPXCCNT brtarget:$imm, 9) - 324
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    // (BPXCCNT brtarget:$imm, 1) - 326
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    // (BPXCCNT brtarget:$imm, 10) - 328
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    // (BPXCCNT brtarget:$imm, 2) - 330
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    // (BPXCCNT brtarget:$imm, 11) - 332
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    // (BPXCCNT brtarget:$imm, 3) - 334
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    // (BPXCCNT brtarget:$imm, 12) - 336
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    // (BPXCCNT brtarget:$imm, 4) - 338
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    // (BPXCCNT brtarget:$imm, 13) - 340
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    // (BPXCCNT brtarget:$imm, 5) - 342
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    // (BPXCCNT brtarget:$imm, 14) - 344
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    // (BPXCCNT brtarget:$imm, 6) - 346
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    // (BPXCCNT brtarget:$imm, 15) - 348
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    // (BPXCCNT brtarget:$imm, 7) - 350
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    // (FMOVD_ICC DFPRegs:$rd, DFPRegs:$rs2, 8) - 352
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVD_ICC DFPRegs:$rd, DFPRegs:$rs2, 0) - 357
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVD_ICC DFPRegs:$rd, DFPRegs:$rs2, 9) - 362
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVD_ICC DFPRegs:$rd, DFPRegs:$rs2, 1) - 367
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVD_ICC DFPRegs:$rd, DFPRegs:$rs2, 10) - 372
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVD_ICC DFPRegs:$rd, DFPRegs:$rs2, 2) - 377
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVD_ICC DFPRegs:$rd, DFPRegs:$rs2, 11) - 382
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVD_ICC DFPRegs:$rd, DFPRegs:$rs2, 3) - 387
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVD_ICC DFPRegs:$rd, DFPRegs:$rs2, 12) - 392
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVD_ICC DFPRegs:$rd, DFPRegs:$rs2, 4) - 397
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVD_ICC DFPRegs:$rd, DFPRegs:$rs2, 13) - 402
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVD_ICC DFPRegs:$rd, DFPRegs:$rs2, 5) - 407
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVD_ICC DFPRegs:$rd, DFPRegs:$rs2, 14) - 412
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVD_ICC DFPRegs:$rd, DFPRegs:$rs2, 6) - 417
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVD_ICC DFPRegs:$rd, DFPRegs:$rs2, 15) - 422
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVD_ICC DFPRegs:$rd, DFPRegs:$rs2, 7) - 427
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVD_XCC DFPRegs:$rd, DFPRegs:$rs2, 8) - 432
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    // (FMOVD_XCC DFPRegs:$rd, DFPRegs:$rs2, 0) - 436
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    // (FMOVD_XCC DFPRegs:$rd, DFPRegs:$rs2, 9) - 440
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    // (FMOVD_XCC DFPRegs:$rd, DFPRegs:$rs2, 1) - 444
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    // (FMOVD_XCC DFPRegs:$rd, DFPRegs:$rs2, 10) - 448
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    // (FMOVD_XCC DFPRegs:$rd, DFPRegs:$rs2, 2) - 452
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    // (FMOVD_XCC DFPRegs:$rd, DFPRegs:$rs2, 11) - 456
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    // (FMOVD_XCC DFPRegs:$rd, DFPRegs:$rs2, 3) - 460
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    // (FMOVD_XCC DFPRegs:$rd, DFPRegs:$rs2, 12) - 464
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    // (FMOVD_XCC DFPRegs:$rd, DFPRegs:$rs2, 4) - 468
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    // (FMOVD_XCC DFPRegs:$rd, DFPRegs:$rs2, 13) - 472
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    // (FMOVD_XCC DFPRegs:$rd, DFPRegs:$rs2, 5) - 476
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    // (FMOVD_XCC DFPRegs:$rd, DFPRegs:$rs2, 14) - 480
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    // (FMOVD_XCC DFPRegs:$rd, DFPRegs:$rs2, 6) - 484
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    // (FMOVD_XCC DFPRegs:$rd, DFPRegs:$rs2, 15) - 488
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    // (FMOVD_XCC DFPRegs:$rd, DFPRegs:$rs2, 7) - 492
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    // (FMOVQ_ICC QFPRegs:$rd, QFPRegs:$rs2, 8) - 496
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVQ_ICC QFPRegs:$rd, QFPRegs:$rs2, 0) - 501
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVQ_ICC QFPRegs:$rd, QFPRegs:$rs2, 9) - 506
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVQ_ICC QFPRegs:$rd, QFPRegs:$rs2, 1) - 511
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVQ_ICC QFPRegs:$rd, QFPRegs:$rs2, 10) - 516
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVQ_ICC QFPRegs:$rd, QFPRegs:$rs2, 2) - 521
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVQ_ICC QFPRegs:$rd, QFPRegs:$rs2, 11) - 526
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVQ_ICC QFPRegs:$rd, QFPRegs:$rs2, 3) - 531
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVQ_ICC QFPRegs:$rd, QFPRegs:$rs2, 12) - 536
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVQ_ICC QFPRegs:$rd, QFPRegs:$rs2, 4) - 541
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVQ_ICC QFPRegs:$rd, QFPRegs:$rs2, 13) - 546
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVQ_ICC QFPRegs:$rd, QFPRegs:$rs2, 5) - 551
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVQ_ICC QFPRegs:$rd, QFPRegs:$rs2, 14) - 556
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVQ_ICC QFPRegs:$rd, QFPRegs:$rs2, 6) - 561
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVQ_ICC QFPRegs:$rd, QFPRegs:$rs2, 15) - 566
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVQ_ICC QFPRegs:$rd, QFPRegs:$rs2, 7) - 571
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVQ_XCC QFPRegs:$rd, QFPRegs:$rs2, 8) - 576
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    // (FMOVQ_XCC QFPRegs:$rd, QFPRegs:$rs2, 0) - 580
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    // (FMOVQ_XCC QFPRegs:$rd, QFPRegs:$rs2, 9) - 584
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    // (FMOVQ_XCC QFPRegs:$rd, QFPRegs:$rs2, 1) - 588
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    // (FMOVQ_XCC QFPRegs:$rd, QFPRegs:$rs2, 10) - 592
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    // (FMOVQ_XCC QFPRegs:$rd, QFPRegs:$rs2, 2) - 596
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    // (FMOVQ_XCC QFPRegs:$rd, QFPRegs:$rs2, 11) - 600
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    // (FMOVQ_XCC QFPRegs:$rd, QFPRegs:$rs2, 3) - 604
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    // (FMOVQ_XCC QFPRegs:$rd, QFPRegs:$rs2, 12) - 608
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    // (FMOVQ_XCC QFPRegs:$rd, QFPRegs:$rs2, 4) - 612
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    // (FMOVQ_XCC QFPRegs:$rd, QFPRegs:$rs2, 13) - 616
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    // (FMOVQ_XCC QFPRegs:$rd, QFPRegs:$rs2, 5) - 620
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    // (FMOVQ_XCC QFPRegs:$rd, QFPRegs:$rs2, 14) - 624
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    // (FMOVQ_XCC QFPRegs:$rd, QFPRegs:$rs2, 6) - 628
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    // (FMOVQ_XCC QFPRegs:$rd, QFPRegs:$rs2, 15) - 632
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    // (FMOVQ_XCC QFPRegs:$rd, QFPRegs:$rs2, 7) - 636
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    // (FMOVS_ICC FPRegs:$rd, FPRegs:$rs2, 8) - 640
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVS_ICC FPRegs:$rd, FPRegs:$rs2, 0) - 645
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVS_ICC FPRegs:$rd, FPRegs:$rs2, 9) - 650
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVS_ICC FPRegs:$rd, FPRegs:$rs2, 1) - 655
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVS_ICC FPRegs:$rd, FPRegs:$rs2, 10) - 660
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVS_ICC FPRegs:$rd, FPRegs:$rs2, 2) - 665
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVS_ICC FPRegs:$rd, FPRegs:$rs2, 11) - 670
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVS_ICC FPRegs:$rd, FPRegs:$rs2, 3) - 675
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVS_ICC FPRegs:$rd, FPRegs:$rs2, 12) - 680
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVS_ICC FPRegs:$rd, FPRegs:$rs2, 4) - 685
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVS_ICC FPRegs:$rd, FPRegs:$rs2, 13) - 690
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVS_ICC FPRegs:$rd, FPRegs:$rs2, 5) - 695
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVS_ICC FPRegs:$rd, FPRegs:$rs2, 14) - 700
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVS_ICC FPRegs:$rd, FPRegs:$rs2, 6) - 705
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVS_ICC FPRegs:$rd, FPRegs:$rs2, 15) - 710
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVS_ICC FPRegs:$rd, FPRegs:$rs2, 7) - 715
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (FMOVS_XCC FPRegs:$rd, FPRegs:$rs2, 8) - 720
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    // (FMOVS_XCC FPRegs:$rd, FPRegs:$rs2, 0) - 724
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    // (FMOVS_XCC FPRegs:$rd, FPRegs:$rs2, 9) - 728
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    // (FMOVS_XCC FPRegs:$rd, FPRegs:$rs2, 1) - 732
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    // (FMOVS_XCC FPRegs:$rd, FPRegs:$rs2, 10) - 736
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    // (FMOVS_XCC FPRegs:$rd, FPRegs:$rs2, 2) - 740
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    // (FMOVS_XCC FPRegs:$rd, FPRegs:$rs2, 11) - 744
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    // (FMOVS_XCC FPRegs:$rd, FPRegs:$rs2, 3) - 748
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    // (FMOVS_XCC FPRegs:$rd, FPRegs:$rs2, 12) - 752
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    // (FMOVS_XCC FPRegs:$rd, FPRegs:$rs2, 4) - 756
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    // (FMOVS_XCC FPRegs:$rd, FPRegs:$rs2, 13) - 760
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    // (FMOVS_XCC FPRegs:$rd, FPRegs:$rs2, 5) - 764
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    // (FMOVS_XCC FPRegs:$rd, FPRegs:$rs2, 14) - 768
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    // (FMOVS_XCC FPRegs:$rd, FPRegs:$rs2, 6) - 772
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    // (FMOVS_XCC FPRegs:$rd, FPRegs:$rs2, 15) - 776
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    // (FMOVS_XCC FPRegs:$rd, FPRegs:$rs2, 7) - 780
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    // (MOVICCri IntRegs:$rd, i32imm:$simm11, 8) - 784
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCri IntRegs:$rd, i32imm:$simm11, 0) - 789
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCri IntRegs:$rd, i32imm:$simm11, 9) - 794
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCri IntRegs:$rd, i32imm:$simm11, 1) - 799
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCri IntRegs:$rd, i32imm:$simm11, 10) - 804
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCri IntRegs:$rd, i32imm:$simm11, 2) - 809
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCri IntRegs:$rd, i32imm:$simm11, 11) - 814
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCri IntRegs:$rd, i32imm:$simm11, 3) - 819
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCri IntRegs:$rd, i32imm:$simm11, 12) - 824
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCri IntRegs:$rd, i32imm:$simm11, 4) - 829
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCri IntRegs:$rd, i32imm:$simm11, 13) - 834
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCri IntRegs:$rd, i32imm:$simm11, 5) - 839
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCri IntRegs:$rd, i32imm:$simm11, 14) - 844
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCri IntRegs:$rd, i32imm:$simm11, 6) - 849
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCri IntRegs:$rd, i32imm:$simm11, 15) - 854
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCri IntRegs:$rd, i32imm:$simm11, 7) - 859
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCrr IntRegs:$rd, IntRegs:$rs2, 8) - 864
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCrr IntRegs:$rd, IntRegs:$rs2, 0) - 869
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCrr IntRegs:$rd, IntRegs:$rs2, 9) - 874
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCrr IntRegs:$rd, IntRegs:$rs2, 1) - 879
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCrr IntRegs:$rd, IntRegs:$rs2, 10) - 884
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCrr IntRegs:$rd, IntRegs:$rs2, 2) - 889
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCrr IntRegs:$rd, IntRegs:$rs2, 11) - 894
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCrr IntRegs:$rd, IntRegs:$rs2, 3) - 899
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCrr IntRegs:$rd, IntRegs:$rs2, 12) - 904
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCrr IntRegs:$rd, IntRegs:$rs2, 4) - 909
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCrr IntRegs:$rd, IntRegs:$rs2, 13) - 914
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCrr IntRegs:$rd, IntRegs:$rs2, 5) - 919
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCrr IntRegs:$rd, IntRegs:$rs2, 14) - 924
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCrr IntRegs:$rd, IntRegs:$rs2, 6) - 929
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCrr IntRegs:$rd, IntRegs:$rs2, 15) - 934
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVICCrr IntRegs:$rd, IntRegs:$rs2, 7) - 939
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (MOVXCCri IntRegs:$rd, i32imm:$simm11, 8) - 944
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    // (MOVXCCri IntRegs:$rd, i32imm:$simm11, 0) - 948
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    // (MOVXCCri IntRegs:$rd, i32imm:$simm11, 9) - 952
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    // (MOVXCCri IntRegs:$rd, i32imm:$simm11, 1) - 956
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    // (MOVXCCri IntRegs:$rd, i32imm:$simm11, 10) - 960
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    // (MOVXCCri IntRegs:$rd, i32imm:$simm11, 2) - 964
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    // (MOVXCCri IntRegs:$rd, i32imm:$simm11, 11) - 968
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    // (MOVXCCri IntRegs:$rd, i32imm:$simm11, 3) - 972
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    // (MOVXCCri IntRegs:$rd, i32imm:$simm11, 12) - 976
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    // (MOVXCCri IntRegs:$rd, i32imm:$simm11, 4) - 980
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    // (MOVXCCri IntRegs:$rd, i32imm:$simm11, 13) - 984
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    // (MOVXCCri IntRegs:$rd, i32imm:$simm11, 5) - 988
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    // (MOVXCCri IntRegs:$rd, i32imm:$simm11, 14) - 992
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    // (MOVXCCri IntRegs:$rd, i32imm:$simm11, 6) - 996
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    // (MOVXCCri IntRegs:$rd, i32imm:$simm11, 15) - 1000
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    // (MOVXCCri IntRegs:$rd, i32imm:$simm11, 7) - 1004
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    // (MOVXCCrr IntRegs:$rd, IntRegs:$rs2, 8) - 1008
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    // (MOVXCCrr IntRegs:$rd, IntRegs:$rs2, 0) - 1012
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    // (MOVXCCrr IntRegs:$rd, IntRegs:$rs2, 9) - 1016
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    // (MOVXCCrr IntRegs:$rd, IntRegs:$rs2, 1) - 1020
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    // (MOVXCCrr IntRegs:$rd, IntRegs:$rs2, 10) - 1024
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    // (MOVXCCrr IntRegs:$rd, IntRegs:$rs2, 2) - 1028
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    // (MOVXCCrr IntRegs:$rd, IntRegs:$rs2, 11) - 1032
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    // (MOVXCCrr IntRegs:$rd, IntRegs:$rs2, 3) - 1036
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    // (MOVXCCrr IntRegs:$rd, IntRegs:$rs2, 12) - 1040
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    // (MOVXCCrr IntRegs:$rd, IntRegs:$rs2, 4) - 1044
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    // (MOVXCCrr IntRegs:$rd, IntRegs:$rs2, 13) - 1048
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    // (MOVXCCrr IntRegs:$rd, IntRegs:$rs2, 5) - 1052
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    // (MOVXCCrr IntRegs:$rd, IntRegs:$rs2, 14) - 1056
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    // (MOVXCCrr IntRegs:$rd, IntRegs:$rs2, 6) - 1060
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    // (MOVXCCrr IntRegs:$rd, IntRegs:$rs2, 15) - 1064
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    // (MOVXCCrr IntRegs:$rd, IntRegs:$rs2, 7) - 1068
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    // (ORCCrr G0, IntRegs:$rs2, G0) - 1072
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Reg, SP_G0},
    // (ORri IntRegs:$rd, G0, i32imm:$simm13) - 1075
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Reg, SP_G0},
    // (ORrr IntRegs:$rd, G0, IntRegs:$rs2) - 1077
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    // (RESTORErr G0, G0, G0) - 1080
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Reg, SP_G0},
    // (RET 8) - 1083
    {AliasPatternCond_K_Imm, (uint32_t)8},
    // (RETL 8) - 1084
    {AliasPatternCond_K_Imm, (uint32_t)8},
    // (SAVErr G0, G0, G0) - 1085
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Reg, SP_G0},
    // (TICCri G0, i32imm:$imm, 8) - 1088
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri IntRegs:$rs1, i32imm:$imm, 8) - 1092
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri G0, i32imm:$imm, 0) - 1096
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri IntRegs:$rs1, i32imm:$imm, 0) - 1100
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri G0, i32imm:$imm, 9) - 1104
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri IntRegs:$rs1, i32imm:$imm, 9) - 1108
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri G0, i32imm:$imm, 1) - 1112
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri IntRegs:$rs1, i32imm:$imm, 1) - 1116
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri G0, i32imm:$imm, 10) - 1120
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri IntRegs:$rs1, i32imm:$imm, 10) - 1124
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri G0, i32imm:$imm, 2) - 1128
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri IntRegs:$rs1, i32imm:$imm, 2) - 1132
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri G0, i32imm:$imm, 11) - 1136
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri IntRegs:$rs1, i32imm:$imm, 11) - 1140
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri G0, i32imm:$imm, 3) - 1144
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri IntRegs:$rs1, i32imm:$imm, 3) - 1148
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri G0, i32imm:$imm, 12) - 1152
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri IntRegs:$rs1, i32imm:$imm, 12) - 1156
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri G0, i32imm:$imm, 4) - 1160
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri IntRegs:$rs1, i32imm:$imm, 4) - 1164
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri G0, i32imm:$imm, 13) - 1168
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri IntRegs:$rs1, i32imm:$imm, 13) - 1172
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri G0, i32imm:$imm, 5) - 1176
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri IntRegs:$rs1, i32imm:$imm, 5) - 1180
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri G0, i32imm:$imm, 14) - 1184
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri IntRegs:$rs1, i32imm:$imm, 14) - 1188
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri G0, i32imm:$imm, 6) - 1192
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri IntRegs:$rs1, i32imm:$imm, 6) - 1196
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri G0, i32imm:$imm, 15) - 1200
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri IntRegs:$rs1, i32imm:$imm, 15) - 1204
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri G0, i32imm:$imm, 7) - 1208
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCri IntRegs:$rs1, i32imm:$imm, 7) - 1212
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr G0, IntRegs:$rs2, 8) - 1216
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr IntRegs:$rs1, IntRegs:$rs2, 8) - 1220
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr G0, IntRegs:$rs2, 0) - 1224
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr IntRegs:$rs1, IntRegs:$rs2, 0) - 1228
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr G0, IntRegs:$rs2, 9) - 1232
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr IntRegs:$rs1, IntRegs:$rs2, 9) - 1236
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr G0, IntRegs:$rs2, 1) - 1240
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr IntRegs:$rs1, IntRegs:$rs2, 1) - 1244
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr G0, IntRegs:$rs2, 10) - 1248
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr IntRegs:$rs1, IntRegs:$rs2, 10) - 1252
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr G0, IntRegs:$rs2, 2) - 1256
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr IntRegs:$rs1, IntRegs:$rs2, 2) - 1260
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr G0, IntRegs:$rs2, 11) - 1264
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr IntRegs:$rs1, IntRegs:$rs2, 11) - 1268
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr G0, IntRegs:$rs2, 3) - 1272
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr IntRegs:$rs1, IntRegs:$rs2, 3) - 1276
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr G0, IntRegs:$rs2, 12) - 1280
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr IntRegs:$rs1, IntRegs:$rs2, 12) - 1284
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr G0, IntRegs:$rs2, 4) - 1288
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr IntRegs:$rs1, IntRegs:$rs2, 4) - 1292
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr G0, IntRegs:$rs2, 13) - 1296
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr IntRegs:$rs1, IntRegs:$rs2, 13) - 1300
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr G0, IntRegs:$rs2, 5) - 1304
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr IntRegs:$rs1, IntRegs:$rs2, 5) - 1308
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr G0, IntRegs:$rs2, 14) - 1312
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr IntRegs:$rs1, IntRegs:$rs2, 14) - 1316
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr G0, IntRegs:$rs2, 6) - 1320
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr IntRegs:$rs1, IntRegs:$rs2, 6) - 1324
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr G0, IntRegs:$rs2, 15) - 1328
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr IntRegs:$rs1, IntRegs:$rs2, 15) - 1332
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr G0, IntRegs:$rs2, 7) - 1336
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TICCrr IntRegs:$rs1, IntRegs:$rs2, 7) - 1340
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TRAPri G0, i32imm:$imm, 8) - 1344
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    // (TRAPri IntRegs:$rs1, i32imm:$imm, 8) - 1347
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    // (TRAPri G0, i32imm:$imm, 0) - 1350
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    // (TRAPri IntRegs:$rs1, i32imm:$imm, 0) - 1353
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    // (TRAPri G0, i32imm:$imm, 9) - 1356
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    // (TRAPri IntRegs:$rs1, i32imm:$imm, 9) - 1359
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    // (TRAPri G0, i32imm:$imm, 1) - 1362
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    // (TRAPri IntRegs:$rs1, i32imm:$imm, 1) - 1365
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    // (TRAPri G0, i32imm:$imm, 10) - 1368
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    // (TRAPri IntRegs:$rs1, i32imm:$imm, 10) - 1371
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    // (TRAPri G0, i32imm:$imm, 2) - 1374
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    // (TRAPri IntRegs:$rs1, i32imm:$imm, 2) - 1377
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    // (TRAPri G0, i32imm:$imm, 11) - 1380
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    // (TRAPri IntRegs:$rs1, i32imm:$imm, 11) - 1383
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    // (TRAPri G0, i32imm:$imm, 3) - 1386
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    // (TRAPri IntRegs:$rs1, i32imm:$imm, 3) - 1389
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    // (TRAPri G0, i32imm:$imm, 12) - 1392
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    // (TRAPri IntRegs:$rs1, i32imm:$imm, 12) - 1395
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    // (TRAPri G0, i32imm:$imm, 4) - 1398
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    // (TRAPri IntRegs:$rs1, i32imm:$imm, 4) - 1401
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    // (TRAPri G0, i32imm:$imm, 13) - 1404
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    // (TRAPri IntRegs:$rs1, i32imm:$imm, 13) - 1407
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    // (TRAPri G0, i32imm:$imm, 5) - 1410
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    // (TRAPri IntRegs:$rs1, i32imm:$imm, 5) - 1413
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    // (TRAPri G0, i32imm:$imm, 14) - 1416
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    // (TRAPri IntRegs:$rs1, i32imm:$imm, 14) - 1419
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    // (TRAPri G0, i32imm:$imm, 6) - 1422
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    // (TRAPri IntRegs:$rs1, i32imm:$imm, 6) - 1425
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    // (TRAPri G0, i32imm:$imm, 15) - 1428
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    // (TRAPri IntRegs:$rs1, i32imm:$imm, 15) - 1431
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    // (TRAPri G0, i32imm:$imm, 7) - 1434
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    // (TRAPri IntRegs:$rs1, i32imm:$imm, 7) - 1437
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    // (TRAPrr G0, IntRegs:$rs1, 8) - 1440
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    // (TRAPrr IntRegs:$rs1, IntRegs:$rs2, 8) - 1443
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    // (TRAPrr G0, IntRegs:$rs1, 0) - 1446
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    // (TRAPrr IntRegs:$rs1, IntRegs:$rs2, 0) - 1449
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    // (TRAPrr G0, IntRegs:$rs1, 9) - 1452
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    // (TRAPrr IntRegs:$rs1, IntRegs:$rs2, 9) - 1455
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    // (TRAPrr G0, IntRegs:$rs1, 1) - 1458
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    // (TRAPrr IntRegs:$rs1, IntRegs:$rs2, 1) - 1461
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    // (TRAPrr G0, IntRegs:$rs1, 10) - 1464
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    // (TRAPrr IntRegs:$rs1, IntRegs:$rs2, 10) - 1467
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    // (TRAPrr G0, IntRegs:$rs1, 2) - 1470
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    // (TRAPrr IntRegs:$rs1, IntRegs:$rs2, 2) - 1473
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    // (TRAPrr G0, IntRegs:$rs1, 11) - 1476
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    // (TRAPrr IntRegs:$rs1, IntRegs:$rs2, 11) - 1479
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    // (TRAPrr G0, IntRegs:$rs1, 3) - 1482
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    // (TRAPrr IntRegs:$rs1, IntRegs:$rs2, 3) - 1485
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    // (TRAPrr G0, IntRegs:$rs1, 12) - 1488
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    // (TRAPrr IntRegs:$rs1, IntRegs:$rs2, 12) - 1491
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    // (TRAPrr G0, IntRegs:$rs1, 4) - 1494
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    // (TRAPrr IntRegs:$rs1, IntRegs:$rs2, 4) - 1497
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    // (TRAPrr G0, IntRegs:$rs1, 13) - 1500
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    // (TRAPrr IntRegs:$rs1, IntRegs:$rs2, 13) - 1503
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    // (TRAPrr G0, IntRegs:$rs1, 5) - 1506
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    // (TRAPrr IntRegs:$rs1, IntRegs:$rs2, 5) - 1509
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    // (TRAPrr G0, IntRegs:$rs1, 14) - 1512
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    // (TRAPrr IntRegs:$rs1, IntRegs:$rs2, 14) - 1515
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    // (TRAPrr G0, IntRegs:$rs1, 6) - 1518
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    // (TRAPrr IntRegs:$rs1, IntRegs:$rs2, 6) - 1521
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    // (TRAPrr G0, IntRegs:$rs1, 15) - 1524
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    // (TRAPrr IntRegs:$rs1, IntRegs:$rs2, 15) - 1527
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    // (TRAPrr G0, IntRegs:$rs1, 7) - 1530
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    // (TRAPrr IntRegs:$rs1, IntRegs:$rs2, 7) - 1533
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    // (TXCCri G0, i32imm:$imm, 8) - 1536
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri IntRegs:$rs1, i32imm:$imm, 8) - 1540
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri G0, i32imm:$imm, 0) - 1544
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri IntRegs:$rs1, i32imm:$imm, 0) - 1548
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri G0, i32imm:$imm, 9) - 1552
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri IntRegs:$rs1, i32imm:$imm, 9) - 1556
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri G0, i32imm:$imm, 1) - 1560
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri IntRegs:$rs1, i32imm:$imm, 1) - 1564
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri G0, i32imm:$imm, 10) - 1568
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri IntRegs:$rs1, i32imm:$imm, 10) - 1572
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri G0, i32imm:$imm, 2) - 1576
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri IntRegs:$rs1, i32imm:$imm, 2) - 1580
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri G0, i32imm:$imm, 11) - 1584
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri IntRegs:$rs1, i32imm:$imm, 11) - 1588
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri G0, i32imm:$imm, 3) - 1592
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri IntRegs:$rs1, i32imm:$imm, 3) - 1596
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri G0, i32imm:$imm, 12) - 1600
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri IntRegs:$rs1, i32imm:$imm, 12) - 1604
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri G0, i32imm:$imm, 4) - 1608
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri IntRegs:$rs1, i32imm:$imm, 4) - 1612
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri G0, i32imm:$imm, 13) - 1616
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri IntRegs:$rs1, i32imm:$imm, 13) - 1620
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri G0, i32imm:$imm, 5) - 1624
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri IntRegs:$rs1, i32imm:$imm, 5) - 1628
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri G0, i32imm:$imm, 14) - 1632
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri IntRegs:$rs1, i32imm:$imm, 14) - 1636
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri G0, i32imm:$imm, 6) - 1640
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri IntRegs:$rs1, i32imm:$imm, 6) - 1644
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri G0, i32imm:$imm, 15) - 1648
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri IntRegs:$rs1, i32imm:$imm, 15) - 1652
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri G0, i32imm:$imm, 7) - 1656
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCri IntRegs:$rs1, i32imm:$imm, 7) - 1660
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr G0, IntRegs:$rs2, 8) - 1664
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr IntRegs:$rs1, IntRegs:$rs2, 8) - 1668
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr G0, IntRegs:$rs2, 0) - 1672
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr IntRegs:$rs1, IntRegs:$rs2, 0) - 1676
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr G0, IntRegs:$rs2, 9) - 1680
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr IntRegs:$rs1, IntRegs:$rs2, 9) - 1684
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr G0, IntRegs:$rs2, 1) - 1688
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr IntRegs:$rs1, IntRegs:$rs2, 1) - 1692
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr G0, IntRegs:$rs2, 10) - 1696
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr IntRegs:$rs1, IntRegs:$rs2, 10) - 1700
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr G0, IntRegs:$rs2, 2) - 1704
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr IntRegs:$rs1, IntRegs:$rs2, 2) - 1708
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr G0, IntRegs:$rs2, 11) - 1712
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr IntRegs:$rs1, IntRegs:$rs2, 11) - 1716
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr G0, IntRegs:$rs2, 3) - 1720
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr IntRegs:$rs1, IntRegs:$rs2, 3) - 1724
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr G0, IntRegs:$rs2, 12) - 1728
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr IntRegs:$rs1, IntRegs:$rs2, 12) - 1732
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr G0, IntRegs:$rs2, 4) - 1736
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr IntRegs:$rs1, IntRegs:$rs2, 4) - 1740
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr G0, IntRegs:$rs2, 13) - 1744
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr IntRegs:$rs1, IntRegs:$rs2, 13) - 1748
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr G0, IntRegs:$rs2, 5) - 1752
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr IntRegs:$rs1, IntRegs:$rs2, 5) - 1756
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr G0, IntRegs:$rs2, 14) - 1760
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr IntRegs:$rs1, IntRegs:$rs2, 14) - 1764
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr G0, IntRegs:$rs2, 6) - 1768
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr IntRegs:$rs1, IntRegs:$rs2, 6) - 1772
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr G0, IntRegs:$rs2, 15) - 1776
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr IntRegs:$rs1, IntRegs:$rs2, 15) - 1780
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr G0, IntRegs:$rs2, 7) - 1784
    {AliasPatternCond_K_Reg, SP_G0},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (TXCCrr IntRegs:$rs1, IntRegs:$rs2, 7) - 1788
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FCMPD FCC0, DFPRegs:$rs1, DFPRegs:$rs2) - 1792
    {AliasPatternCond_K_Reg, SP_FCC0},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    // (V9FCMPED FCC0, DFPRegs:$rs1, DFPRegs:$rs2) - 1795
    {AliasPatternCond_K_Reg, SP_FCC0},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    // (V9FCMPEQ FCC0, QFPRegs:$rs1, QFPRegs:$rs2) - 1798
    {AliasPatternCond_K_Reg, SP_FCC0},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    // (V9FCMPES FCC0, FPRegs:$rs1, FPRegs:$rs2) - 1801
    {AliasPatternCond_K_Reg, SP_FCC0},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    // (V9FCMPQ FCC0, QFPRegs:$rs1, QFPRegs:$rs2) - 1804
    {AliasPatternCond_K_Reg, SP_FCC0},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    // (V9FCMPS FCC0, FPRegs:$rs1, FPRegs:$rs2) - 1807
    {AliasPatternCond_K_Reg, SP_FCC0},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    // (V9FMOVD_FCC DFPRegs:$rd, FCCRegs:$cc, DFPRegs:$rs2, 8) - 1810
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVD_FCC DFPRegs:$rd, FCCRegs:$cc, DFPRegs:$rs2, 0) - 1816
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVD_FCC DFPRegs:$rd, FCCRegs:$cc, DFPRegs:$rs2, 7) - 1822
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVD_FCC DFPRegs:$rd, FCCRegs:$cc, DFPRegs:$rs2, 6) - 1828
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVD_FCC DFPRegs:$rd, FCCRegs:$cc, DFPRegs:$rs2, 5) - 1834
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVD_FCC DFPRegs:$rd, FCCRegs:$cc, DFPRegs:$rs2, 4) - 1840
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVD_FCC DFPRegs:$rd, FCCRegs:$cc, DFPRegs:$rs2, 3) - 1846
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVD_FCC DFPRegs:$rd, FCCRegs:$cc, DFPRegs:$rs2, 2) - 1852
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVD_FCC DFPRegs:$rd, FCCRegs:$cc, DFPRegs:$rs2, 1) - 1858
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVD_FCC DFPRegs:$rd, FCCRegs:$cc, DFPRegs:$rs2, 9) - 1864
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVD_FCC DFPRegs:$rd, FCCRegs:$cc, DFPRegs:$rs2, 10) - 1870
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVD_FCC DFPRegs:$rd, FCCRegs:$cc, DFPRegs:$rs2, 11) - 1876
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVD_FCC DFPRegs:$rd, FCCRegs:$cc, DFPRegs:$rs2, 12) - 1882
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVD_FCC DFPRegs:$rd, FCCRegs:$cc, DFPRegs:$rs2, 13) - 1888
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVD_FCC DFPRegs:$rd, FCCRegs:$cc, DFPRegs:$rs2, 14) - 1894
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVD_FCC DFPRegs:$rd, FCCRegs:$cc, DFPRegs:$rs2, 15) - 1900
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_DFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVQ_FCC QFPRegs:$rd, FCCRegs:$cc, QFPRegs:$rs2, 8) - 1906
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVQ_FCC QFPRegs:$rd, FCCRegs:$cc, QFPRegs:$rs2, 0) - 1912
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVQ_FCC QFPRegs:$rd, FCCRegs:$cc, QFPRegs:$rs2, 7) - 1918
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVQ_FCC QFPRegs:$rd, FCCRegs:$cc, QFPRegs:$rs2, 6) - 1924
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVQ_FCC QFPRegs:$rd, FCCRegs:$cc, QFPRegs:$rs2, 5) - 1930
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVQ_FCC QFPRegs:$rd, FCCRegs:$cc, QFPRegs:$rs2, 4) - 1936
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVQ_FCC QFPRegs:$rd, FCCRegs:$cc, QFPRegs:$rs2, 3) - 1942
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVQ_FCC QFPRegs:$rd, FCCRegs:$cc, QFPRegs:$rs2, 2) - 1948
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVQ_FCC QFPRegs:$rd, FCCRegs:$cc, QFPRegs:$rs2, 1) - 1954
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVQ_FCC QFPRegs:$rd, FCCRegs:$cc, QFPRegs:$rs2, 9) - 1960
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVQ_FCC QFPRegs:$rd, FCCRegs:$cc, QFPRegs:$rs2, 10) - 1966
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVQ_FCC QFPRegs:$rd, FCCRegs:$cc, QFPRegs:$rs2, 11) - 1972
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVQ_FCC QFPRegs:$rd, FCCRegs:$cc, QFPRegs:$rs2, 12) - 1978
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVQ_FCC QFPRegs:$rd, FCCRegs:$cc, QFPRegs:$rs2, 13) - 1984
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVQ_FCC QFPRegs:$rd, FCCRegs:$cc, QFPRegs:$rs2, 14) - 1990
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVQ_FCC QFPRegs:$rd, FCCRegs:$cc, QFPRegs:$rs2, 15) - 1996
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_QFPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVS_FCC FPRegs:$rd, FCCRegs:$cc, FPRegs:$rs2, 8) - 2002
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVS_FCC FPRegs:$rd, FCCRegs:$cc, FPRegs:$rs2, 0) - 2008
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVS_FCC FPRegs:$rd, FCCRegs:$cc, FPRegs:$rs2, 7) - 2014
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVS_FCC FPRegs:$rd, FCCRegs:$cc, FPRegs:$rs2, 6) - 2020
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVS_FCC FPRegs:$rd, FCCRegs:$cc, FPRegs:$rs2, 5) - 2026
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVS_FCC FPRegs:$rd, FCCRegs:$cc, FPRegs:$rs2, 4) - 2032
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVS_FCC FPRegs:$rd, FCCRegs:$cc, FPRegs:$rs2, 3) - 2038
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVS_FCC FPRegs:$rd, FCCRegs:$cc, FPRegs:$rs2, 2) - 2044
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVS_FCC FPRegs:$rd, FCCRegs:$cc, FPRegs:$rs2, 1) - 2050
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVS_FCC FPRegs:$rd, FCCRegs:$cc, FPRegs:$rs2, 9) - 2056
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVS_FCC FPRegs:$rd, FCCRegs:$cc, FPRegs:$rs2, 10) - 2062
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVS_FCC FPRegs:$rd, FCCRegs:$cc, FPRegs:$rs2, 11) - 2068
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVS_FCC FPRegs:$rd, FCCRegs:$cc, FPRegs:$rs2, 12) - 2074
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVS_FCC FPRegs:$rd, FCCRegs:$cc, FPRegs:$rs2, 13) - 2080
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVS_FCC FPRegs:$rd, FCCRegs:$cc, FPRegs:$rs2, 14) - 2086
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9FMOVS_FCC FPRegs:$rd, FCCRegs:$cc, FPRegs:$rs2, 15) - 2092
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FPRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCri IntRegs:$rd, FCCRegs:$cc, i32imm:$simm11, 8) - 2098
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCri IntRegs:$rd, FCCRegs:$cc, i32imm:$simm11, 0) - 2104
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCri IntRegs:$rd, FCCRegs:$cc, i32imm:$simm11, 7) - 2110
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCri IntRegs:$rd, FCCRegs:$cc, i32imm:$simm11, 6) - 2116
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCri IntRegs:$rd, FCCRegs:$cc, i32imm:$simm11, 5) - 2122
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCri IntRegs:$rd, FCCRegs:$cc, i32imm:$simm11, 4) - 2128
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCri IntRegs:$rd, FCCRegs:$cc, i32imm:$simm11, 3) - 2134
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCri IntRegs:$rd, FCCRegs:$cc, i32imm:$simm11, 2) - 2140
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCri IntRegs:$rd, FCCRegs:$cc, i32imm:$simm11, 1) - 2146
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCri IntRegs:$rd, FCCRegs:$cc, i32imm:$simm11, 9) - 2152
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCri IntRegs:$rd, FCCRegs:$cc, i32imm:$simm11, 10) - 2158
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCri IntRegs:$rd, FCCRegs:$cc, i32imm:$simm11, 11) - 2164
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCri IntRegs:$rd, FCCRegs:$cc, i32imm:$simm11, 12) - 2170
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCri IntRegs:$rd, FCCRegs:$cc, i32imm:$simm11, 13) - 2176
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCri IntRegs:$rd, FCCRegs:$cc, i32imm:$simm11, 14) - 2182
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCri IntRegs:$rd, FCCRegs:$cc, i32imm:$simm11, 15) - 2188
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCrr IntRegs:$rd, FCCRegs:$cc, IntRegs:$rs2, 8) - 2194
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)8},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCrr IntRegs:$rd, FCCRegs:$cc, IntRegs:$rs2, 0) - 2200
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)0},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCrr IntRegs:$rd, FCCRegs:$cc, IntRegs:$rs2, 7) - 2206
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)7},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCrr IntRegs:$rd, FCCRegs:$cc, IntRegs:$rs2, 6) - 2212
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)6},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCrr IntRegs:$rd, FCCRegs:$cc, IntRegs:$rs2, 5) - 2218
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)5},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCrr IntRegs:$rd, FCCRegs:$cc, IntRegs:$rs2, 4) - 2224
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)4},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCrr IntRegs:$rd, FCCRegs:$cc, IntRegs:$rs2, 3) - 2230
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)3},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCrr IntRegs:$rd, FCCRegs:$cc, IntRegs:$rs2, 2) - 2236
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)2},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCrr IntRegs:$rd, FCCRegs:$cc, IntRegs:$rs2, 1) - 2242
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)1},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCrr IntRegs:$rd, FCCRegs:$cc, IntRegs:$rs2, 9) - 2248
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)9},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCrr IntRegs:$rd, FCCRegs:$cc, IntRegs:$rs2, 10) - 2254
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)10},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCrr IntRegs:$rd, FCCRegs:$cc, IntRegs:$rs2, 11) - 2260
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)11},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCrr IntRegs:$rd, FCCRegs:$cc, IntRegs:$rs2, 12) - 2266
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)12},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCrr IntRegs:$rd, FCCRegs:$cc, IntRegs:$rs2, 13) - 2272
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)13},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCrr IntRegs:$rd, FCCRegs:$cc, IntRegs:$rs2, 14) - 2278
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)14},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
    // (V9MOVFCCrr IntRegs:$rd, FCCRegs:$cc, IntRegs:$rs2, 15) - 2284
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_FCCRegsRegClassID},
    {AliasPatternCond_K_RegClass, SP_IntRegsRegClassID},
    {AliasPatternCond_K_Ignore, 0},
    {AliasPatternCond_K_Imm, (uint32_t)15},
    {AliasPatternCond_K_Feature, Sparc_FeatureV9},
  };

  static const char *AsmStrings[] = {
    /* 0 */ "ba $\x01\0"
    /* 6 */ "bn $\x01\0"
    /* 12 */ "bne $\x01\0"
    /* 19 */ "be $\x01\0"
    /* 25 */ "bg $\x01\0"
    /* 31 */ "ble $\x01\0"
    /* 38 */ "bge $\x01\0"
    /* 45 */ "bl $\x01\0"
    /* 51 */ "bgu $\x01\0"
    /* 58 */ "bleu $\x01\0"
    /* 66 */ "bcc $\x01\0"
    /* 73 */ "bcs $\x01\0"
    /* 80 */ "bpos $\x01\0"
    /* 88 */ "bneg $\x01\0"
    /* 96 */ "bvc $\x01\0"
    /* 103 */ "bvs $\x01\0"
    /* 110 */ "ba,a $\x01\0"
    /* 118 */ "bn,a $\x01\0"
    /* 126 */ "bne,a $\x01\0"
    /* 135 */ "be,a $\x01\0"
    /* 143 */ "bg,a $\x01\0"
    /* 151 */ "ble,a $\x01\0"
    /* 160 */ "bge,a $\x01\0"
    /* 169 */ "bl,a $\x01\0"
    /* 177 */ "bgu,a $\x01\0"
    /* 186 */ "bleu,a $\x01\0"
    /* 196 */ "bcc,a $\x01\0"
    /* 205 */ "bcs,a $\x01\0"
    /* 214 */ "bpos,a $\x01\0"
    /* 224 */ "bneg,a $\x01\0"
    /* 234 */ "bvc,a $\x01\0"
    /* 243 */ "bvs,a $\x01\0"
    /* 252 */ "fba,a,pn $\x03, $\x01\0"
    /* 268 */ "fbn,a,pn $\x03, $\x01\0"
    /* 284 */ "fbu,a,pn $\x03, $\x01\0"
    /* 300 */ "fbg,a,pn $\x03, $\x01\0"
    /* 316 */ "fbug,a,pn $\x03, $\x01\0"
    /* 333 */ "fbl,a,pn $\x03, $\x01\0"
    /* 349 */ "fbul,a,pn $\x03, $\x01\0"
    /* 366 */ "fblg,a,pn $\x03, $\x01\0"
    /* 383 */ "fbne,a,pn $\x03, $\x01\0"
    /* 400 */ "fbe,a,pn $\x03, $\x01\0"
    /* 416 */ "fbue,a,pn $\x03, $\x01\0"
    /* 433 */ "fbge,a,pn $\x03, $\x01\0"
    /* 450 */ "fbuge,a,pn $\x03, $\x01\0"
    /* 468 */ "fble,a,pn $\x03, $\x01\0"
    /* 485 */ "fbule,a,pn $\x03, $\x01\0"
    /* 503 */ "fbo,a,pn $\x03, $\x01\0"
    /* 519 */ "fba,pn $\x03, $\x01\0"
    /* 533 */ "fbn,pn $\x03, $\x01\0"
    /* 547 */ "fbu,pn $\x03, $\x01\0"
    /* 561 */ "fbg,pn $\x03, $\x01\0"
    /* 575 */ "fbug,pn $\x03, $\x01\0"
    /* 590 */ "fbl,pn $\x03, $\x01\0"
    /* 604 */ "fbul,pn $\x03, $\x01\0"
    /* 619 */ "fblg,pn $\x03, $\x01\0"
    /* 634 */ "fbne,pn $\x03, $\x01\0"
    /* 649 */ "fbe,pn $\x03, $\x01\0"
    /* 663 */ "fbue,pn $\x03, $\x01\0"
    /* 678 */ "fbge,pn $\x03, $\x01\0"
    /* 693 */ "fbuge,pn $\x03, $\x01\0"
    /* 709 */ "fble,pn $\x03, $\x01\0"
    /* 724 */ "fbule,pn $\x03, $\x01\0"
    /* 740 */ "fbo,pn $\x03, $\x01\0"
    /* 754 */ "ba,a,pn %icc, $\x01\0"
    /* 771 */ "bn,a,pn %icc, $\x01\0"
    /* 788 */ "bne,a,pn %icc, $\x01\0"
    /* 806 */ "be,a,pn %icc, $\x01\0"
    /* 823 */ "bg,a,pn %icc, $\x01\0"
    /* 840 */ "ble,a,pn %icc, $\x01\0"
    /* 858 */ "bge,a,pn %icc, $\x01\0"
    /* 876 */ "bl,a,pn %icc, $\x01\0"
    /* 893 */ "bgu,a,pn %icc, $\x01\0"
    /* 911 */ "bleu,a,pn %icc, $\x01\0"
    /* 930 */ "bcc,a,pn %icc, $\x01\0"
    /* 948 */ "bcs,a,pn %icc, $\x01\0"
    /* 966 */ "bpos,a,pn %icc, $\x01\0"
    /* 985 */ "bneg,a,pn %icc, $\x01\0"
    /* 1004 */ "bvc,a,pn %icc, $\x01\0"
    /* 1022 */ "bvs,a,pn %icc, $\x01\0"
    /* 1040 */ "ba,pn %icc, $\x01\0"
    /* 1055 */ "bn,pn %icc, $\x01\0"
    /* 1070 */ "bne,pn %icc, $\x01\0"
    /* 1086 */ "be,pn %icc, $\x01\0"
    /* 1101 */ "bg,pn %icc, $\x01\0"
    /* 1116 */ "ble,pn %icc, $\x01\0"
    /* 1132 */ "bge,pn %icc, $\x01\0"
    /* 1148 */ "bl,pn %icc, $\x01\0"
    /* 1163 */ "bgu,pn %icc, $\x01\0"
    /* 1179 */ "bleu,pn %icc, $\x01\0"
    /* 1196 */ "bcc,pn %icc, $\x01\0"
    /* 1212 */ "bcs,pn %icc, $\x01\0"
    /* 1228 */ "bpos,pn %icc, $\x01\0"
    /* 1245 */ "bneg,pn %icc, $\x01\0"
    /* 1262 */ "bvc,pn %icc, $\x01\0"
    /* 1278 */ "bvs,pn %icc, $\x01\0"
    /* 1294 */ "ba,a,pn %xcc, $\x01\0"
    /* 1311 */ "bn,a,pn %xcc, $\x01\0"
    /* 1328 */ "bne,a,pn %xcc, $\x01\0"
    /* 1346 */ "be,a,pn %xcc, $\x01\0"
    /* 1363 */ "bg,a,pn %xcc, $\x01\0"
    /* 1380 */ "ble,a,pn %xcc, $\x01\0"
    /* 1398 */ "bge,a,pn %xcc, $\x01\0"
    /* 1416 */ "bl,a,pn %xcc, $\x01\0"
    /* 1433 */ "bgu,a,pn %xcc, $\x01\0"
    /* 1451 */ "bleu,a,pn %xcc, $\x01\0"
    /* 1470 */ "bcc,a,pn %xcc, $\x01\0"
    /* 1488 */ "bcs,a,pn %xcc, $\x01\0"
    /* 1506 */ "bpos,a,pn %xcc, $\x01\0"
    /* 1525 */ "bneg,a,pn %xcc, $\x01\0"
    /* 1544 */ "bvc,a,pn %xcc, $\x01\0"
    /* 1562 */ "bvs,a,pn %xcc, $\x01\0"
    /* 1580 */ "ba,pn %xcc, $\x01\0"
    /* 1595 */ "bn,pn %xcc, $\x01\0"
    /* 1610 */ "bne,pn %xcc, $\x01\0"
    /* 1626 */ "be,pn %xcc, $\x01\0"
    /* 1641 */ "bg,pn %xcc, $\x01\0"
    /* 1656 */ "ble,pn %xcc, $\x01\0"
    /* 1672 */ "bge,pn %xcc, $\x01\0"
    /* 1688 */ "bl,pn %xcc, $\x01\0"
    /* 1703 */ "bgu,pn %xcc, $\x01\0"
    /* 1719 */ "bleu,pn %xcc, $\x01\0"
    /* 1736 */ "bcc,pn %xcc, $\x01\0"
    /* 1752 */ "bcs,pn %xcc, $\x01\0"
    /* 1768 */ "bpos,pn %xcc, $\x01\0"
    /* 1785 */ "bneg,pn %xcc, $\x01\0"
    /* 1802 */ "bvc,pn %xcc, $\x01\0"
    /* 1818 */ "bvs,pn %xcc, $\x01\0"
    /* 1834 */ "fmovda %icc, $\x02, $\x01\0"
    /* 1854 */ "fmovdn %icc, $\x02, $\x01\0"
    /* 1874 */ "fmovdne %icc, $\x02, $\x01\0"
    /* 1895 */ "fmovde %icc, $\x02, $\x01\0"
    /* 1915 */ "fmovdg %icc, $\x02, $\x01\0"
    /* 1935 */ "fmovdle %icc, $\x02, $\x01\0"
    /* 1956 */ "fmovdge %icc, $\x02, $\x01\0"
    /* 1977 */ "fmovdl %icc, $\x02, $\x01\0"
    /* 1997 */ "fmovdgu %icc, $\x02, $\x01\0"
    /* 2018 */ "fmovdleu %icc, $\x02, $\x01\0"
    /* 2040 */ "fmovdcc %icc, $\x02, $\x01\0"
    /* 2061 */ "fmovdcs %icc, $\x02, $\x01\0"
    /* 2082 */ "fmovdpos %icc, $\x02, $\x01\0"
    /* 2104 */ "fmovdneg %icc, $\x02, $\x01\0"
    /* 2126 */ "fmovdvc %icc, $\x02, $\x01\0"
    /* 2147 */ "fmovdvs %icc, $\x02, $\x01\0"
    /* 2168 */ "fmovda %xcc, $\x02, $\x01\0"
    /* 2188 */ "fmovdn %xcc, $\x02, $\x01\0"
    /* 2208 */ "fmovdne %xcc, $\x02, $\x01\0"
    /* 2229 */ "fmovde %xcc, $\x02, $\x01\0"
    /* 2249 */ "fmovdg %xcc, $\x02, $\x01\0"
    /* 2269 */ "fmovdle %xcc, $\x02, $\x01\0"
    /* 2290 */ "fmovdge %xcc, $\x02, $\x01\0"
    /* 2311 */ "fmovdl %xcc, $\x02, $\x01\0"
    /* 2331 */ "fmovdgu %xcc, $\x02, $\x01\0"
    /* 2352 */ "fmovdleu %xcc, $\x02, $\x01\0"
    /* 2374 */ "fmovdcc %xcc, $\x02, $\x01\0"
    /* 2395 */ "fmovdcs %xcc, $\x02, $\x01\0"
    /* 2416 */ "fmovdpos %xcc, $\x02, $\x01\0"
    /* 2438 */ "fmovdneg %xcc, $\x02, $\x01\0"
    /* 2460 */ "fmovdvc %xcc, $\x02, $\x01\0"
    /* 2481 */ "fmovdvs %xcc, $\x02, $\x01\0"
    /* 2502 */ "fmovqa %icc, $\x02, $\x01\0"
    /* 2522 */ "fmovqn %icc, $\x02, $\x01\0"
    /* 2542 */ "fmovqne %icc, $\x02, $\x01\0"
    /* 2563 */ "fmovqe %icc, $\x02, $\x01\0"
    /* 2583 */ "fmovqg %icc, $\x02, $\x01\0"
    /* 2603 */ "fmovqle %icc, $\x02, $\x01\0"
    /* 2624 */ "fmovqge %icc, $\x02, $\x01\0"
    /* 2645 */ "fmovql %icc, $\x02, $\x01\0"
    /* 2665 */ "fmovqgu %icc, $\x02, $\x01\0"
    /* 2686 */ "fmovqleu %icc, $\x02, $\x01\0"
    /* 2708 */ "fmovqcc %icc, $\x02, $\x01\0"
    /* 2729 */ "fmovqcs %icc, $\x02, $\x01\0"
    /* 2750 */ "fmovqpos %icc, $\x02, $\x01\0"
    /* 2772 */ "fmovqneg %icc, $\x02, $\x01\0"
    /* 2794 */ "fmovqvc %icc, $\x02, $\x01\0"
    /* 2815 */ "fmovqvs %icc, $\x02, $\x01\0"
    /* 2836 */ "fmovqa %xcc, $\x02, $\x01\0"
    /* 2856 */ "fmovqn %xcc, $\x02, $\x01\0"
    /* 2876 */ "fmovqne %xcc, $\x02, $\x01\0"
    /* 2897 */ "fmovqe %xcc, $\x02, $\x01\0"
    /* 2917 */ "fmovqg %xcc, $\x02, $\x01\0"
    /* 2937 */ "fmovqle %xcc, $\x02, $\x01\0"
    /* 2958 */ "fmovqge %xcc, $\x02, $\x01\0"
    /* 2979 */ "fmovql %xcc, $\x02, $\x01\0"
    /* 2999 */ "fmovqgu %xcc, $\x02, $\x01\0"
    /* 3020 */ "fmovqleu %xcc, $\x02, $\x01\0"
    /* 3042 */ "fmovqcc %xcc, $\x02, $\x01\0"
    /* 3063 */ "fmovqcs %xcc, $\x02, $\x01\0"
    /* 3084 */ "fmovqpos %xcc, $\x02, $\x01\0"
    /* 3106 */ "fmovqneg %xcc, $\x02, $\x01\0"
    /* 3128 */ "fmovqvc %xcc, $\x02, $\x01\0"
    /* 3149 */ "fmovqvs %xcc, $\x02, $\x01\0"
    /* 3170 */ "fmovsa %icc, $\x02, $\x01\0"
    /* 3190 */ "fmovsn %icc, $\x02, $\x01\0"
    /* 3210 */ "fmovsne %icc, $\x02, $\x01\0"
    /* 3231 */ "fmovse %icc, $\x02, $\x01\0"
    /* 3251 */ "fmovsg %icc, $\x02, $\x01\0"
    /* 3271 */ "fmovsle %icc, $\x02, $\x01\0"
    /* 3292 */ "fmovsge %icc, $\x02, $\x01\0"
    /* 3313 */ "fmovsl %icc, $\x02, $\x01\0"
    /* 3333 */ "fmovsgu %icc, $\x02, $\x01\0"
    /* 3354 */ "fmovsleu %icc, $\x02, $\x01\0"
    /* 3376 */ "fmovscc %icc, $\x02, $\x01\0"
    /* 3397 */ "fmovscs %icc, $\x02, $\x01\0"
    /* 3418 */ "fmovspos %icc, $\x02, $\x01\0"
    /* 3440 */ "fmovsneg %icc, $\x02, $\x01\0"
    /* 3462 */ "fmovsvc %icc, $\x02, $\x01\0"
    /* 3483 */ "fmovsvs %icc, $\x02, $\x01\0"
    /* 3504 */ "fmovsa %xcc, $\x02, $\x01\0"
    /* 3524 */ "fmovsn %xcc, $\x02, $\x01\0"
    /* 3544 */ "fmovsne %xcc, $\x02, $\x01\0"
    /* 3565 */ "fmovse %xcc, $\x02, $\x01\0"
    /* 3585 */ "fmovsg %xcc, $\x02, $\x01\0"
    /* 3605 */ "fmovsle %xcc, $\x02, $\x01\0"
    /* 3626 */ "fmovsge %xcc, $\x02, $\x01\0"
    /* 3647 */ "fmovsl %xcc, $\x02, $\x01\0"
    /* 3667 */ "fmovsgu %xcc, $\x02, $\x01\0"
    /* 3688 */ "fmovsleu %xcc, $\x02, $\x01\0"
    /* 3710 */ "fmovscc %xcc, $\x02, $\x01\0"
    /* 3731 */ "fmovscs %xcc, $\x02, $\x01\0"
    /* 3752 */ "fmovspos %xcc, $\x02, $\x01\0"
    /* 3774 */ "fmovsneg %xcc, $\x02, $\x01\0"
    /* 3796 */ "fmovsvc %xcc, $\x02, $\x01\0"
    /* 3817 */ "fmovsvs %xcc, $\x02, $\x01\0"
    /* 3838 */ "mova %icc, $\x02, $\x01\0"
    /* 3856 */ "movn %icc, $\x02, $\x01\0"
    /* 3874 */ "movne %icc, $\x02, $\x01\0"
    /* 3893 */ "move %icc, $\x02, $\x01\0"
    /* 3911 */ "movg %icc, $\x02, $\x01\0"
    /* 3929 */ "movle %icc, $\x02, $\x01\0"
    /* 3948 */ "movge %icc, $\x02, $\x01\0"
    /* 3967 */ "movl %icc, $\x02, $\x01\0"
    /* 3985 */ "movgu %icc, $\x02, $\x01\0"
    /* 4004 */ "movleu %icc, $\x02, $\x01\0"
    /* 4024 */ "movcc %icc, $\x02, $\x01\0"
    /* 4043 */ "movcs %icc, $\x02, $\x01\0"
    /* 4062 */ "movpos %icc, $\x02, $\x01\0"
    /* 4082 */ "movneg %icc, $\x02, $\x01\0"
    /* 4102 */ "movvc %icc, $\x02, $\x01\0"
    /* 4121 */ "movvs %icc, $\x02, $\x01\0"
    /* 4140 */ "mova %xcc, $\x02, $\x01\0"
    /* 4158 */ "movn %xcc, $\x02, $\x01\0"
    /* 4176 */ "movne %xcc, $\x02, $\x01\0"
    /* 4195 */ "move %xcc, $\x02, $\x01\0"
    /* 4213 */ "movg %xcc, $\x02, $\x01\0"
    /* 4231 */ "movle %xcc, $\x02, $\x01\0"
    /* 4250 */ "movge %xcc, $\x02, $\x01\0"
    /* 4269 */ "movl %xcc, $\x02, $\x01\0"
    /* 4287 */ "movgu %xcc, $\x02, $\x01\0"
    /* 4306 */ "movleu %xcc, $\x02, $\x01\0"
    /* 4326 */ "movcc %xcc, $\x02, $\x01\0"
    /* 4345 */ "movcs %xcc, $\x02, $\x01\0"
    /* 4364 */ "movpos %xcc, $\x02, $\x01\0"
    /* 4384 */ "movneg %xcc, $\x02, $\x01\0"
    /* 4404 */ "movvc %xcc, $\x02, $\x01\0"
    /* 4423 */ "movvs %xcc, $\x02, $\x01\0"
    /* 4442 */ "tst $\x02\0"
    /* 4449 */ "mov $\x03, $\x01\0"
    /* 4460 */ "restore\0"
    /* 4468 */ "ret\0"
    /* 4472 */ "retl\0"
    /* 4477 */ "save\0"
    /* 4482 */ "ta %icc, $\x02\0"
    /* 4494 */ "ta %icc, $\x01 + $\x02\0"
    /* 4511 */ "tn %icc, $\x02\0"
    /* 4523 */ "tn %icc, $\x01 + $\x02\0"
    /* 4540 */ "tne %icc, $\x02\0"
    /* 4553 */ "tne %icc, $\x01 + $\x02\0"
    /* 4571 */ "te %icc, $\x02\0"
    /* 4583 */ "te %icc, $\x01 + $\x02\0"
    /* 4600 */ "tg %icc, $\x02\0"
    /* 4612 */ "tg %icc, $\x01 + $\x02\0"
    /* 4629 */ "tle %icc, $\x02\0"
    /* 4642 */ "tle %icc, $\x01 + $\x02\0"
    /* 4660 */ "tge %icc, $\x02\0"
    /* 4673 */ "tge %icc, $\x01 + $\x02\0"
    /* 4691 */ "tl %icc, $\x02\0"
    /* 4703 */ "tl %icc, $\x01 + $\x02\0"
    /* 4720 */ "tgu %icc, $\x02\0"
    /* 4733 */ "tgu %icc, $\x01 + $\x02\0"
    /* 4751 */ "tleu %icc, $\x02\0"
    /* 4765 */ "tleu %icc, $\x01 + $\x02\0"
    /* 4784 */ "tcc %icc, $\x02\0"
    /* 4797 */ "tcc %icc, $\x01 + $\x02\0"
    /* 4815 */ "tcs %icc, $\x02\0"
    /* 4828 */ "tcs %icc, $\x01 + $\x02\0"
    /* 4846 */ "tpos %icc, $\x02\0"
    /* 4860 */ "tpos %icc, $\x01 + $\x02\0"
    /* 4879 */ "tneg %icc, $\x02\0"
    /* 4893 */ "tneg %icc, $\x01 + $\x02\0"
    /* 4912 */ "tvc %icc, $\x02\0"
    /* 4925 */ "tvc %icc, $\x01 + $\x02\0"
    /* 4943 */ "tvs %icc, $\x02\0"
    /* 4956 */ "tvs %icc, $\x01 + $\x02\0"
    /* 4974 */ "ta $\x02\0"
    /* 4980 */ "ta $\x01 + $\x02\0"
    /* 4991 */ "tn $\x02\0"
    /* 4997 */ "tn $\x01 + $\x02\0"
    /* 5008 */ "tne $\x02\0"
    /* 5015 */ "tne $\x01 + $\x02\0"
    /* 5027 */ "te $\x02\0"
    /* 5033 */ "te $\x01 + $\x02\0"
    /* 5044 */ "tg $\x02\0"
    /* 5050 */ "tg $\x01 + $\x02\0"
    /* 5061 */ "tle $\x02\0"
    /* 5068 */ "tle $\x01 + $\x02\0"
    /* 5080 */ "tge $\x02\0"
    /* 5087 */ "tge $\x01 + $\x02\0"
    /* 5099 */ "tl $\x02\0"
    /* 5105 */ "tl $\x01 + $\x02\0"
    /* 5116 */ "tgu $\x02\0"
    /* 5123 */ "tgu $\x01 + $\x02\0"
    /* 5135 */ "tleu $\x02\0"
    /* 5143 */ "tleu $\x01 + $\x02\0"
    /* 5156 */ "tcc $\x02\0"
    /* 5163 */ "tcc $\x01 + $\x02\0"
    /* 5175 */ "tcs $\x02\0"
    /* 5182 */ "tcs $\x01 + $\x02\0"
    /* 5194 */ "tpos $\x02\0"
    /* 5202 */ "tpos $\x01 + $\x02\0"
    /* 5215 */ "tneg $\x02\0"
    /* 5223 */ "tneg $\x01 + $\x02\0"
    /* 5236 */ "tvc $\x02\0"
    /* 5243 */ "tvc $\x01 + $\x02\0"
    /* 5255 */ "tvs $\x02\0"
    /* 5262 */ "tvs $\x01 + $\x02\0"
    /* 5274 */ "ta %xcc, $\x02\0"
    /* 5286 */ "ta %xcc, $\x01 + $\x02\0"
    /* 5303 */ "tn %xcc, $\x02\0"
    /* 5315 */ "tn %xcc, $\x01 + $\x02\0"
    /* 5332 */ "tne %xcc, $\x02\0"
    /* 5345 */ "tne %xcc, $\x01 + $\x02\0"
    /* 5363 */ "te %xcc, $\x02\0"
    /* 5375 */ "te %xcc, $\x01 + $\x02\0"
    /* 5392 */ "tg %xcc, $\x02\0"
    /* 5404 */ "tg %xcc, $\x01 + $\x02\0"
    /* 5421 */ "tle %xcc, $\x02\0"
    /* 5434 */ "tle %xcc, $\x01 + $\x02\0"
    /* 5452 */ "tge %xcc, $\x02\0"
    /* 5465 */ "tge %xcc, $\x01 + $\x02\0"
    /* 5483 */ "tl %xcc, $\x02\0"
    /* 5495 */ "tl %xcc, $\x01 + $\x02\0"
    /* 5512 */ "tgu %xcc, $\x02\0"
    /* 5525 */ "tgu %xcc, $\x01 + $\x02\0"
    /* 5543 */ "tleu %xcc, $\x02\0"
    /* 5557 */ "tleu %xcc, $\x01 + $\x02\0"
    /* 5576 */ "tcc %xcc, $\x02\0"
    /* 5589 */ "tcc %xcc, $\x01 + $\x02\0"
    /* 5607 */ "tcs %xcc, $\x02\0"
    /* 5620 */ "tcs %xcc, $\x01 + $\x02\0"
    /* 5638 */ "tpos %xcc, $\x02\0"
    /* 5652 */ "tpos %xcc, $\x01 + $\x02\0"
    /* 5671 */ "tneg %xcc, $\x02\0"
    /* 5685 */ "tneg %xcc, $\x01 + $\x02\0"
    /* 5704 */ "tvc %xcc, $\x02\0"
    /* 5717 */ "tvc %xcc, $\x01 + $\x02\0"
    /* 5735 */ "tvs %xcc, $\x02\0"
    /* 5748 */ "tvs %xcc, $\x01 + $\x02\0"
    /* 5766 */ "fcmpd $\x02, $\x03\0"
    /* 5779 */ "fcmped $\x02, $\x03\0"
    /* 5793 */ "fcmpeq $\x02, $\x03\0"
    /* 5807 */ "fcmpes $\x02, $\x03\0"
    /* 5821 */ "fcmpq $\x02, $\x03\0"
    /* 5834 */ "fcmps $\x02, $\x03\0"
    /* 5847 */ "fmovda $\x02, $\x03, $\x01\0"
    /* 5865 */ "fmovdn $\x02, $\x03, $\x01\0"
    /* 5883 */ "fmovdu $\x02, $\x03, $\x01\0"
    /* 5901 */ "fmovdg $\x02, $\x03, $\x01\0"
    /* 5919 */ "fmovdug $\x02, $\x03, $\x01\0"
    /* 5938 */ "fmovdl $\x02, $\x03, $\x01\0"
    /* 5956 */ "fmovdul $\x02, $\x03, $\x01\0"
    /* 5975 */ "fmovdlg $\x02, $\x03, $\x01\0"
    /* 5994 */ "fmovdne $\x02, $\x03, $\x01\0"
    /* 6013 */ "fmovde $\x02, $\x03, $\x01\0"
    /* 6031 */ "fmovdue $\x02, $\x03, $\x01\0"
    /* 6050 */ "fmovdge $\x02, $\x03, $\x01\0"
    /* 6069 */ "fmovduge $\x02, $\x03, $\x01\0"
    /* 6089 */ "fmovdle $\x02, $\x03, $\x01\0"
    /* 6108 */ "fmovdule $\x02, $\x03, $\x01\0"
    /* 6128 */ "fmovdo $\x02, $\x03, $\x01\0"
    /* 6146 */ "fmovqa $\x02, $\x03, $\x01\0"
    /* 6164 */ "fmovqn $\x02, $\x03, $\x01\0"
    /* 6182 */ "fmovqu $\x02, $\x03, $\x01\0"
    /* 6200 */ "fmovqg $\x02, $\x03, $\x01\0"
    /* 6218 */ "fmovqug $\x02, $\x03, $\x01\0"
    /* 6237 */ "fmovql $\x02, $\x03, $\x01\0"
    /* 6255 */ "fmovqul $\x02, $\x03, $\x01\0"
    /* 6274 */ "fmovqlg $\x02, $\x03, $\x01\0"
    /* 6293 */ "fmovqne $\x02, $\x03, $\x01\0"
    /* 6312 */ "fmovqe $\x02, $\x03, $\x01\0"
    /* 6330 */ "fmovque $\x02, $\x03, $\x01\0"
    /* 6349 */ "fmovqge $\x02, $\x03, $\x01\0"
    /* 6368 */ "fmovquge $\x02, $\x03, $\x01\0"
    /* 6388 */ "fmovqle $\x02, $\x03, $\x01\0"
    /* 6407 */ "fmovqule $\x02, $\x03, $\x01\0"
    /* 6427 */ "fmovqo $\x02, $\x03, $\x01\0"
    /* 6445 */ "fmovsa $\x02, $\x03, $\x01\0"
    /* 6463 */ "fmovsn $\x02, $\x03, $\x01\0"
    /* 6481 */ "fmovsu $\x02, $\x03, $\x01\0"
    /* 6499 */ "fmovsg $\x02, $\x03, $\x01\0"
    /* 6517 */ "fmovsug $\x02, $\x03, $\x01\0"
    /* 6536 */ "fmovsl $\x02, $\x03, $\x01\0"
    /* 6554 */ "fmovsul $\x02, $\x03, $\x01\0"
    /* 6573 */ "fmovslg $\x02, $\x03, $\x01\0"
    /* 6592 */ "fmovsne $\x02, $\x03, $\x01\0"
    /* 6611 */ "fmovse $\x02, $\x03, $\x01\0"
    /* 6629 */ "fmovsue $\x02, $\x03, $\x01\0"
    /* 6648 */ "fmovsge $\x02, $\x03, $\x01\0"
    /* 6667 */ "fmovsuge $\x02, $\x03, $\x01\0"
    /* 6687 */ "fmovsle $\x02, $\x03, $\x01\0"
    /* 6706 */ "fmovsule $\x02, $\x03, $\x01\0"
    /* 6726 */ "fmovso $\x02, $\x03, $\x01\0"
    /* 6744 */ "mova $\x02, $\x03, $\x01\0"
    /* 6760 */ "movn $\x02, $\x03, $\x01\0"
    /* 6776 */ "movu $\x02, $\x03, $\x01\0"
    /* 6792 */ "movg $\x02, $\x03, $\x01\0"
    /* 6808 */ "movug $\x02, $\x03, $\x01\0"
    /* 6825 */ "movl $\x02, $\x03, $\x01\0"
    /* 6841 */ "movul $\x02, $\x03, $\x01\0"
    /* 6858 */ "movlg $\x02, $\x03, $\x01\0"
    /* 6875 */ "movne $\x02, $\x03, $\x01\0"
    /* 6892 */ "move $\x02, $\x03, $\x01\0"
    /* 6908 */ "movue $\x02, $\x03, $\x01\0"
    /* 6925 */ "movge $\x02, $\x03, $\x01\0"
    /* 6942 */ "movuge $\x02, $\x03, $\x01\0"
    /* 6960 */ "movle $\x02, $\x03, $\x01\0"
    /* 6977 */ "movule $\x02, $\x03, $\x01\0"
    /* 6995 */ "movo $\x02, $\x03, $\x01\0"
  };

  const char *AsmString = MCInstPrinter_matchAliasPatterns(MI, OpToPatterns, Patterns, Conds, AsmStrings, 42);
  if (!AsmString) return false;

  char* tmpString = cs_strdup(AsmString);

  unsigned I = 0;
  while (AsmString[I] != ' ' && AsmString[I] != '\t' &&
         AsmString[I] != '$' && AsmString[I] != '\0')
    ++I;

  tmpString[I] = 0;
  SStream_concat0(OS, tmpString);

  SStream_concat0(OS, "\t");
  if (AsmString[I] != '\0') {
    if (AsmString[I] == ' ' || AsmString[I] == '\t') {
      SStream_concat0(OS, "\t");
      ++I;
    }
    do {
      if (AsmString[I] == '$') {
        ++I;
        if (AsmString[I] == (char)0xff) {
          ++I;
          int OpIdx = AsmString[I++] - 1;
          int PrintMethodIdx = AsmString[I++] - 1;
          printCustomAliasOperand(MI, OpIdx, PrintMethodIdx, OS);
        } else
          printOperand(MI, ((unsigned)AsmString[I++]) - 1, OS);
      } else {
        SStream_concat1(OS, *(tmpString + (I++)));
      }
    } while (AsmString[I] != '\0');
  }

  return tmpString;
}

void printCustomAliasOperand(
         const MCInst *MI, unsigned OpIdx,
         unsigned PrintMethodIdx,
         SStream *OS) {
  llvm_unreachable("Unknown PrintMethod kind");
}

#endif // PRINT_ALIAS_INSTR
#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC

static const MCOperandInfo OperandInfo2[] = { { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo3[] = { { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo4[] = { { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo5[] = { { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, MCOI_TIED_TO/*0*/ }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo6[] = { { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo7[] = { { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo8[] = { { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo9[] = { { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, MCOI_TIED_TO/*0*/ }, };
static const MCOperandInfo OperandInfo10[] = { { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo11[] = { { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo12[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo13[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo14[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo15[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo16[] = { { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo17[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo18[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo19[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo20[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo21[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo22[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo23[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo24[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo25[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo26[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_2, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo27[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_2, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo28[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_2, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo29[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo30[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo31[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo32[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo33[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo34[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo35[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo36[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo37[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo38[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_2, 0 }, };
static const MCOperandInfo OperandInfo39[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_2, 0 }, };
static const MCOperandInfo OperandInfo40[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo41[] = { { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo42[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_2, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo43[] = { { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo44[] = { { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo45[] = { { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo46[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo47[] = { { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo48[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo49[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo50[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo51[] = { { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo52[] = { { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo53[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo54[] = { { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo55[] = { { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo56[] = { { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo57[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, MCOI_TIED_TO/*0*/ }, };
static const MCOperandInfo OperandInfo58[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, MCOI_TIED_TO/*0*/ }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo59[] = { { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, MCOI_TIED_TO/*0*/ }, };
static const MCOperandInfo OperandInfo60[] = { { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo61[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo62[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo63[] = { { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo64[] = { { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo65[] = { { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo66[] = { { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo67[] = { { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo68[] = { { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo69[] = { { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo70[] = { { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo71[] = { { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo72[] = { { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo73[] = { { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo74[] = { { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo75[] = { { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, MCOI_TIED_TO/*0*/ }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo76[] = { { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, MCOI_TIED_TO/*0*/ }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo77[] = { { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo78[] = { { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, MCOI_TIED_TO/*0*/ }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo79[] = { { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, MCOI_TIED_TO/*0*/ }, };
static const MCOperandInfo OperandInfo80[] = { { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, MCOI_TIED_TO/*0*/ }, };
static const MCOperandInfo OperandInfo81[] = { { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo82[] = { { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo83[] = { { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo84[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo85[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo86[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo87[] = { { SP_CoprocRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo88[] = { { SP_CoprocRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo89[] = { { SP_IntPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo90[] = { { SP_CoprocPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo91[] = { { SP_CoprocPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo92[] = { { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo93[] = { { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo94[] = { { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo95[] = { { SP_IntPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo96[] = { { SP_IntPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo97[] = { { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo98[] = { { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo99[] = { { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo100[] = { { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo101[] = { { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo102[] = { { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo103[] = { { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo104[] = { { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo105[] = { { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo106[] = { { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo107[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, MCOI_TIED_TO/*0*/ }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo108[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, MCOI_TIED_TO/*0*/ }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo109[] = { { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo110[] = { { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo111[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo112[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo113[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo114[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_ASRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo115[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo116[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_PRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo117[] = { { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo118[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_ASRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo119[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_ASRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo120[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo121[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo122[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo123[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_CoprocRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo124[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_CoprocRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo125[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_IntPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo126[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_CoprocPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo127[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_CoprocPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo128[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo129[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo130[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo131[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_IntPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo132[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_IntPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo133[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo134[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo135[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo136[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo137[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo138[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo139[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo140[] = { { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo141[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, MCOI_TIED_TO/*0*/ }, };
static const MCOperandInfo OperandInfo142[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, MCOI_TIED_TO/*0*/ }, };
static const MCOperandInfo OperandInfo143[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, MCOI_TIED_TO/*0*/ }, };
static const MCOperandInfo OperandInfo144[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo145[] = { { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo146[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo147[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo148[] = { { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo149[] = { { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo150[] = { { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, MCOI_TIED_TO/*0*/ }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo151[] = { { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, MCOI_TIED_TO/*0*/ }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo152[] = { { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, MCOI_TIED_TO/*0*/ }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo153[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, MCOI_TIED_TO/*0*/ }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo154[] = { { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, MCOI_TIED_TO/*0*/ }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo155[] = { { SP_ASRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo156[] = { { SP_ASRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo157[] = { { SP_PRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo158[] = { { SP_PRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, };

extern const MCInstrDesc SparcInsts[] = {
  { 1,	OperandInfo2 },  // Inst #0 = PHI
  { 0,	NULL },  // Inst #1 = INLINEASM
  { 0,	NULL },  // Inst #2 = INLINEASM_BR
  { 1,	OperandInfo3 },  // Inst #3 = CFI_INSTRUCTION
  { 1,	OperandInfo3 },  // Inst #4 = EH_LABEL
  { 1,	OperandInfo3 },  // Inst #5 = GC_LABEL
  { 1,	OperandInfo3 },  // Inst #6 = ANNOTATION_LABEL
  { 0,	NULL },  // Inst #7 = KILL
  { 3,	OperandInfo4 },  // Inst #8 = EXTRACT_SUBREG
  { 4,	OperandInfo5 },  // Inst #9 = INSERT_SUBREG
  { 1,	OperandInfo2 },  // Inst #10 = IMPLICIT_DEF
  { 4,	OperandInfo6 },  // Inst #11 = SUBREG_TO_REG
  { 3,	OperandInfo4 },  // Inst #12 = COPY_TO_REGCLASS
  { 0,	NULL },  // Inst #13 = DBG_VALUE
  { 0,	NULL },  // Inst #14 = DBG_VALUE_LIST
  { 0,	NULL },  // Inst #15 = DBG_INSTR_REF
  { 0,	NULL },  // Inst #16 = DBG_PHI
  { 1,	OperandInfo2 },  // Inst #17 = DBG_LABEL
  { 2,	OperandInfo7 },  // Inst #18 = REG_SEQUENCE
  { 2,	OperandInfo7 },  // Inst #19 = COPY
  { 0,	NULL },  // Inst #20 = BUNDLE
  { 1,	OperandInfo3 },  // Inst #21 = LIFETIME_START
  { 1,	OperandInfo3 },  // Inst #22 = LIFETIME_END
  { 4,	OperandInfo8 },  // Inst #23 = PSEUDO_PROBE
  { 2,	OperandInfo9 },  // Inst #24 = ARITH_FENCE
  { 2,	OperandInfo10 },  // Inst #25 = STACKMAP
  { 0,	NULL },  // Inst #26 = FENTRY_CALL
  { 6,	OperandInfo11 },  // Inst #27 = PATCHPOINT
  { 1,	OperandInfo12 },  // Inst #28 = LOAD_STACK_GUARD
  { 1,	OperandInfo3 },  // Inst #29 = PREALLOCATED_SETUP
  { 3,	OperandInfo13 },  // Inst #30 = PREALLOCATED_ARG
  { 0,	NULL },  // Inst #31 = STATEPOINT
  { 2,	OperandInfo14 },  // Inst #32 = LOCAL_ESCAPE
  { 1,	OperandInfo2 },  // Inst #33 = FAULTING_OP
  { 0,	NULL },  // Inst #34 = PATCHABLE_OP
  { 0,	NULL },  // Inst #35 = PATCHABLE_FUNCTION_ENTER
  { 0,	NULL },  // Inst #36 = PATCHABLE_RET
  { 0,	NULL },  // Inst #37 = PATCHABLE_FUNCTION_EXIT
  { 0,	NULL },  // Inst #38 = PATCHABLE_TAIL_CALL
  { 2,	OperandInfo15 },  // Inst #39 = PATCHABLE_EVENT_CALL
  { 3,	OperandInfo16 },  // Inst #40 = PATCHABLE_TYPED_EVENT_CALL
  { 0,	NULL },  // Inst #41 = ICALL_BRANCH_FUNNEL
  { 3,	OperandInfo17 },  // Inst #42 = G_ASSERT_SEXT
  { 3,	OperandInfo17 },  // Inst #43 = G_ASSERT_ZEXT
  { 3,	OperandInfo18 },  // Inst #44 = G_ADD
  { 3,	OperandInfo18 },  // Inst #45 = G_SUB
  { 3,	OperandInfo18 },  // Inst #46 = G_MUL
  { 3,	OperandInfo18 },  // Inst #47 = G_SDIV
  { 3,	OperandInfo18 },  // Inst #48 = G_UDIV
  { 3,	OperandInfo18 },  // Inst #49 = G_SREM
  { 3,	OperandInfo18 },  // Inst #50 = G_UREM
  { 4,	OperandInfo19 },  // Inst #51 = G_SDIVREM
  { 4,	OperandInfo19 },  // Inst #52 = G_UDIVREM
  { 3,	OperandInfo18 },  // Inst #53 = G_AND
  { 3,	OperandInfo18 },  // Inst #54 = G_OR
  { 3,	OperandInfo18 },  // Inst #55 = G_XOR
  { 1,	OperandInfo20 },  // Inst #56 = G_IMPLICIT_DEF
  { 1,	OperandInfo20 },  // Inst #57 = G_PHI
  { 2,	OperandInfo21 },  // Inst #58 = G_FRAME_INDEX
  { 2,	OperandInfo21 },  // Inst #59 = G_GLOBAL_VALUE
  { 3,	OperandInfo22 },  // Inst #60 = G_EXTRACT
  { 2,	OperandInfo23 },  // Inst #61 = G_UNMERGE_VALUES
  { 4,	OperandInfo24 },  // Inst #62 = G_INSERT
  { 2,	OperandInfo23 },  // Inst #63 = G_MERGE_VALUES
  { 2,	OperandInfo23 },  // Inst #64 = G_BUILD_VECTOR
  { 2,	OperandInfo23 },  // Inst #65 = G_BUILD_VECTOR_TRUNC
  { 2,	OperandInfo23 },  // Inst #66 = G_CONCAT_VECTORS
  { 2,	OperandInfo23 },  // Inst #67 = G_PTRTOINT
  { 2,	OperandInfo23 },  // Inst #68 = G_INTTOPTR
  { 2,	OperandInfo23 },  // Inst #69 = G_BITCAST
  { 2,	OperandInfo25 },  // Inst #70 = G_FREEZE
  { 2,	OperandInfo25 },  // Inst #71 = G_INTRINSIC_TRUNC
  { 2,	OperandInfo25 },  // Inst #72 = G_INTRINSIC_ROUND
  { 2,	OperandInfo23 },  // Inst #73 = G_INTRINSIC_LRINT
  { 2,	OperandInfo25 },  // Inst #74 = G_INTRINSIC_ROUNDEVEN
  { 1,	OperandInfo20 },  // Inst #75 = G_READCYCLECOUNTER
  { 2,	OperandInfo23 },  // Inst #76 = G_LOAD
  { 2,	OperandInfo23 },  // Inst #77 = G_SEXTLOAD
  { 2,	OperandInfo23 },  // Inst #78 = G_ZEXTLOAD
  { 5,	OperandInfo26 },  // Inst #79 = G_INDEXED_LOAD
  { 5,	OperandInfo26 },  // Inst #80 = G_INDEXED_SEXTLOAD
  { 5,	OperandInfo26 },  // Inst #81 = G_INDEXED_ZEXTLOAD
  { 2,	OperandInfo23 },  // Inst #82 = G_STORE
  { 5,	OperandInfo27 },  // Inst #83 = G_INDEXED_STORE
  { 5,	OperandInfo28 },  // Inst #84 = G_ATOMIC_CMPXCHG_WITH_SUCCESS
  { 4,	OperandInfo29 },  // Inst #85 = G_ATOMIC_CMPXCHG
  { 3,	OperandInfo30 },  // Inst #86 = G_ATOMICRMW_XCHG
  { 3,	OperandInfo30 },  // Inst #87 = G_ATOMICRMW_ADD
  { 3,	OperandInfo30 },  // Inst #88 = G_ATOMICRMW_SUB
  { 3,	OperandInfo30 },  // Inst #89 = G_ATOMICRMW_AND
  { 3,	OperandInfo30 },  // Inst #90 = G_ATOMICRMW_NAND
  { 3,	OperandInfo30 },  // Inst #91 = G_ATOMICRMW_OR
  { 3,	OperandInfo30 },  // Inst #92 = G_ATOMICRMW_XOR
  { 3,	OperandInfo30 },  // Inst #93 = G_ATOMICRMW_MAX
  { 3,	OperandInfo30 },  // Inst #94 = G_ATOMICRMW_MIN
  { 3,	OperandInfo30 },  // Inst #95 = G_ATOMICRMW_UMAX
  { 3,	OperandInfo30 },  // Inst #96 = G_ATOMICRMW_UMIN
  { 3,	OperandInfo30 },  // Inst #97 = G_ATOMICRMW_FADD
  { 3,	OperandInfo30 },  // Inst #98 = G_ATOMICRMW_FSUB
  { 2,	OperandInfo10 },  // Inst #99 = G_FENCE
  { 2,	OperandInfo21 },  // Inst #100 = G_BRCOND
  { 1,	OperandInfo20 },  // Inst #101 = G_BRINDIRECT
  { 1,	OperandInfo2 },  // Inst #102 = G_INTRINSIC
  { 1,	OperandInfo2 },  // Inst #103 = G_INTRINSIC_W_SIDE_EFFECTS
  { 2,	OperandInfo23 },  // Inst #104 = G_ANYEXT
  { 2,	OperandInfo23 },  // Inst #105 = G_TRUNC
  { 2,	OperandInfo21 },  // Inst #106 = G_CONSTANT
  { 2,	OperandInfo21 },  // Inst #107 = G_FCONSTANT
  { 1,	OperandInfo20 },  // Inst #108 = G_VASTART
  { 3,	OperandInfo31 },  // Inst #109 = G_VAARG
  { 2,	OperandInfo23 },  // Inst #110 = G_SEXT
  { 3,	OperandInfo17 },  // Inst #111 = G_SEXT_INREG
  { 2,	OperandInfo23 },  // Inst #112 = G_ZEXT
  { 3,	OperandInfo32 },  // Inst #113 = G_SHL
  { 3,	OperandInfo32 },  // Inst #114 = G_LSHR
  { 3,	OperandInfo32 },  // Inst #115 = G_ASHR
  { 4,	OperandInfo33 },  // Inst #116 = G_FSHL
  { 4,	OperandInfo33 },  // Inst #117 = G_FSHR
  { 3,	OperandInfo32 },  // Inst #118 = G_ROTR
  { 3,	OperandInfo32 },  // Inst #119 = G_ROTL
  { 4,	OperandInfo34 },  // Inst #120 = G_ICMP
  { 4,	OperandInfo34 },  // Inst #121 = G_FCMP
  { 4,	OperandInfo29 },  // Inst #122 = G_SELECT
  { 4,	OperandInfo29 },  // Inst #123 = G_UADDO
  { 5,	OperandInfo35 },  // Inst #124 = G_UADDE
  { 4,	OperandInfo29 },  // Inst #125 = G_USUBO
  { 5,	OperandInfo35 },  // Inst #126 = G_USUBE
  { 4,	OperandInfo29 },  // Inst #127 = G_SADDO
  { 5,	OperandInfo35 },  // Inst #128 = G_SADDE
  { 4,	OperandInfo29 },  // Inst #129 = G_SSUBO
  { 5,	OperandInfo35 },  // Inst #130 = G_SSUBE
  { 4,	OperandInfo29 },  // Inst #131 = G_UMULO
  { 4,	OperandInfo29 },  // Inst #132 = G_SMULO
  { 3,	OperandInfo18 },  // Inst #133 = G_UMULH
  { 3,	OperandInfo18 },  // Inst #134 = G_SMULH
  { 3,	OperandInfo18 },  // Inst #135 = G_UADDSAT
  { 3,	OperandInfo18 },  // Inst #136 = G_SADDSAT
  { 3,	OperandInfo18 },  // Inst #137 = G_USUBSAT
  { 3,	OperandInfo18 },  // Inst #138 = G_SSUBSAT
  { 3,	OperandInfo32 },  // Inst #139 = G_USHLSAT
  { 3,	OperandInfo32 },  // Inst #140 = G_SSHLSAT
  { 4,	OperandInfo36 },  // Inst #141 = G_SMULFIX
  { 4,	OperandInfo36 },  // Inst #142 = G_UMULFIX
  { 4,	OperandInfo36 },  // Inst #143 = G_SMULFIXSAT
  { 4,	OperandInfo36 },  // Inst #144 = G_UMULFIXSAT
  { 4,	OperandInfo36 },  // Inst #145 = G_SDIVFIX
  { 4,	OperandInfo36 },  // Inst #146 = G_UDIVFIX
  { 4,	OperandInfo36 },  // Inst #147 = G_SDIVFIXSAT
  { 4,	OperandInfo36 },  // Inst #148 = G_UDIVFIXSAT
  { 3,	OperandInfo18 },  // Inst #149 = G_FADD
  { 3,	OperandInfo18 },  // Inst #150 = G_FSUB
  { 3,	OperandInfo18 },  // Inst #151 = G_FMUL
  { 4,	OperandInfo19 },  // Inst #152 = G_FMA
  { 4,	OperandInfo19 },  // Inst #153 = G_FMAD
  { 3,	OperandInfo18 },  // Inst #154 = G_FDIV
  { 3,	OperandInfo18 },  // Inst #155 = G_FREM
  { 3,	OperandInfo18 },  // Inst #156 = G_FPOW
  { 3,	OperandInfo32 },  // Inst #157 = G_FPOWI
  { 2,	OperandInfo25 },  // Inst #158 = G_FEXP
  { 2,	OperandInfo25 },  // Inst #159 = G_FEXP2
  { 2,	OperandInfo25 },  // Inst #160 = G_FLOG
  { 2,	OperandInfo25 },  // Inst #161 = G_FLOG2
  { 2,	OperandInfo25 },  // Inst #162 = G_FLOG10
  { 2,	OperandInfo25 },  // Inst #163 = G_FNEG
  { 2,	OperandInfo23 },  // Inst #164 = G_FPEXT
  { 2,	OperandInfo23 },  // Inst #165 = G_FPTRUNC
  { 2,	OperandInfo23 },  // Inst #166 = G_FPTOSI
  { 2,	OperandInfo23 },  // Inst #167 = G_FPTOUI
  { 2,	OperandInfo23 },  // Inst #168 = G_SITOFP
  { 2,	OperandInfo23 },  // Inst #169 = G_UITOFP
  { 2,	OperandInfo25 },  // Inst #170 = G_FABS
  { 3,	OperandInfo32 },  // Inst #171 = G_FCOPYSIGN
  { 2,	OperandInfo25 },  // Inst #172 = G_FCANONICALIZE
  { 3,	OperandInfo18 },  // Inst #173 = G_FMINNUM
  { 3,	OperandInfo18 },  // Inst #174 = G_FMAXNUM
  { 3,	OperandInfo18 },  // Inst #175 = G_FMINNUM_IEEE
  { 3,	OperandInfo18 },  // Inst #176 = G_FMAXNUM_IEEE
  { 3,	OperandInfo18 },  // Inst #177 = G_FMINIMUM
  { 3,	OperandInfo18 },  // Inst #178 = G_FMAXIMUM
  { 3,	OperandInfo32 },  // Inst #179 = G_PTR_ADD
  { 3,	OperandInfo32 },  // Inst #180 = G_PTRMASK
  { 3,	OperandInfo18 },  // Inst #181 = G_SMIN
  { 3,	OperandInfo18 },  // Inst #182 = G_SMAX
  { 3,	OperandInfo18 },  // Inst #183 = G_UMIN
  { 3,	OperandInfo18 },  // Inst #184 = G_UMAX
  { 2,	OperandInfo25 },  // Inst #185 = G_ABS
  { 2,	OperandInfo23 },  // Inst #186 = G_LROUND
  { 2,	OperandInfo23 },  // Inst #187 = G_LLROUND
  { 1,	OperandInfo2 },  // Inst #188 = G_BR
  { 3,	OperandInfo37 },  // Inst #189 = G_BRJT
  { 4,	OperandInfo38 },  // Inst #190 = G_INSERT_VECTOR_ELT
  { 3,	OperandInfo39 },  // Inst #191 = G_EXTRACT_VECTOR_ELT
  { 4,	OperandInfo40 },  // Inst #192 = G_SHUFFLE_VECTOR
  { 2,	OperandInfo23 },  // Inst #193 = G_CTTZ
  { 2,	OperandInfo23 },  // Inst #194 = G_CTTZ_ZERO_UNDEF
  { 2,	OperandInfo23 },  // Inst #195 = G_CTLZ
  { 2,	OperandInfo23 },  // Inst #196 = G_CTLZ_ZERO_UNDEF
  { 2,	OperandInfo23 },  // Inst #197 = G_CTPOP
  { 2,	OperandInfo25 },  // Inst #198 = G_BSWAP
  { 2,	OperandInfo25 },  // Inst #199 = G_BITREVERSE
  { 2,	OperandInfo25 },  // Inst #200 = G_FCEIL
  { 2,	OperandInfo25 },  // Inst #201 = G_FCOS
  { 2,	OperandInfo25 },  // Inst #202 = G_FSIN
  { 2,	OperandInfo25 },  // Inst #203 = G_FSQRT
  { 2,	OperandInfo25 },  // Inst #204 = G_FFLOOR
  { 2,	OperandInfo25 },  // Inst #205 = G_FRINT
  { 2,	OperandInfo25 },  // Inst #206 = G_FNEARBYINT
  { 2,	OperandInfo23 },  // Inst #207 = G_ADDRSPACE_CAST
  { 2,	OperandInfo21 },  // Inst #208 = G_BLOCK_ADDR
  { 2,	OperandInfo21 },  // Inst #209 = G_JUMP_TABLE
  { 3,	OperandInfo22 },  // Inst #210 = G_DYN_STACKALLOC
  { 3,	OperandInfo18 },  // Inst #211 = G_STRICT_FADD
  { 3,	OperandInfo18 },  // Inst #212 = G_STRICT_FSUB
  { 3,	OperandInfo18 },  // Inst #213 = G_STRICT_FMUL
  { 3,	OperandInfo18 },  // Inst #214 = G_STRICT_FDIV
  { 3,	OperandInfo18 },  // Inst #215 = G_STRICT_FREM
  { 4,	OperandInfo19 },  // Inst #216 = G_STRICT_FMA
  { 2,	OperandInfo25 },  // Inst #217 = G_STRICT_FSQRT
  { 2,	OperandInfo21 },  // Inst #218 = G_READ_REGISTER
  { 2,	OperandInfo41 },  // Inst #219 = G_WRITE_REGISTER
  { 4,	OperandInfo42 },  // Inst #220 = G_MEMCPY
  { 3,	OperandInfo39 },  // Inst #221 = G_MEMCPY_INLINE
  { 4,	OperandInfo42 },  // Inst #222 = G_MEMMOVE
  { 4,	OperandInfo42 },  // Inst #223 = G_MEMSET
  { 3,	OperandInfo22 },  // Inst #224 = G_BZERO
  { 3,	OperandInfo39 },  // Inst #225 = G_VECREDUCE_SEQ_FADD
  { 3,	OperandInfo39 },  // Inst #226 = G_VECREDUCE_SEQ_FMUL
  { 2,	OperandInfo23 },  // Inst #227 = G_VECREDUCE_FADD
  { 2,	OperandInfo23 },  // Inst #228 = G_VECREDUCE_FMUL
  { 2,	OperandInfo23 },  // Inst #229 = G_VECREDUCE_FMAX
  { 2,	OperandInfo23 },  // Inst #230 = G_VECREDUCE_FMIN
  { 2,	OperandInfo23 },  // Inst #231 = G_VECREDUCE_ADD
  { 2,	OperandInfo23 },  // Inst #232 = G_VECREDUCE_MUL
  { 2,	OperandInfo23 },  // Inst #233 = G_VECREDUCE_AND
  { 2,	OperandInfo23 },  // Inst #234 = G_VECREDUCE_OR
  { 2,	OperandInfo23 },  // Inst #235 = G_VECREDUCE_XOR
  { 2,	OperandInfo23 },  // Inst #236 = G_VECREDUCE_SMAX
  { 2,	OperandInfo23 },  // Inst #237 = G_VECREDUCE_SMIN
  { 2,	OperandInfo23 },  // Inst #238 = G_VECREDUCE_UMAX
  { 2,	OperandInfo23 },  // Inst #239 = G_VECREDUCE_UMIN
  { 4,	OperandInfo43 },  // Inst #240 = G_SBFX
  { 4,	OperandInfo43 },  // Inst #241 = G_UBFX
  { 2,	OperandInfo10 },  // Inst #242 = ADJCALLSTACKDOWN
  { 2,	OperandInfo10 },  // Inst #243 = ADJCALLSTACKUP
  { 1,	OperandInfo2 },  // Inst #244 = GETPCX
  { 4,	OperandInfo44 },  // Inst #245 = SELECT_CC_DFP_FCC
  { 4,	OperandInfo44 },  // Inst #246 = SELECT_CC_DFP_ICC
  { 4,	OperandInfo45 },  // Inst #247 = SELECT_CC_FP_FCC
  { 4,	OperandInfo45 },  // Inst #248 = SELECT_CC_FP_ICC
  { 4,	OperandInfo46 },  // Inst #249 = SELECT_CC_Int_FCC
  { 4,	OperandInfo46 },  // Inst #250 = SELECT_CC_Int_ICC
  { 4,	OperandInfo47 },  // Inst #251 = SELECT_CC_QFP_FCC
  { 4,	OperandInfo47 },  // Inst #252 = SELECT_CC_QFP_ICC
  { 2,	OperandInfo48 },  // Inst #253 = SET
  { 3,	OperandInfo49 },  // Inst #254 = ADDCCri
  { 3,	OperandInfo50 },  // Inst #255 = ADDCCrr
  { 3,	OperandInfo49 },  // Inst #256 = ADDCri
  { 3,	OperandInfo50 },  // Inst #257 = ADDCrr
  { 3,	OperandInfo49 },  // Inst #258 = ADDEri
  { 3,	OperandInfo50 },  // Inst #259 = ADDErr
  { 3,	OperandInfo51 },  // Inst #260 = ADDXC
  { 3,	OperandInfo51 },  // Inst #261 = ADDXCCC
  { 3,	OperandInfo52 },  // Inst #262 = ADDXri
  { 3,	OperandInfo51 },  // Inst #263 = ADDXrr
  { 3,	OperandInfo49 },  // Inst #264 = ADDri
  { 3,	OperandInfo50 },  // Inst #265 = ADDrr
  { 3,	OperandInfo51 },  // Inst #266 = ALIGNADDR
  { 3,	OperandInfo51 },  // Inst #267 = ALIGNADDRL
  { 3,	OperandInfo49 },  // Inst #268 = ANDCCri
  { 3,	OperandInfo50 },  // Inst #269 = ANDCCrr
  { 3,	OperandInfo49 },  // Inst #270 = ANDNCCri
  { 3,	OperandInfo50 },  // Inst #271 = ANDNCCrr
  { 3,	OperandInfo49 },  // Inst #272 = ANDNri
  { 3,	OperandInfo50 },  // Inst #273 = ANDNrr
  { 3,	OperandInfo51 },  // Inst #274 = ANDXNrr
  { 3,	OperandInfo52 },  // Inst #275 = ANDXri
  { 3,	OperandInfo51 },  // Inst #276 = ANDXrr
  { 3,	OperandInfo49 },  // Inst #277 = ANDri
  { 3,	OperandInfo50 },  // Inst #278 = ANDrr
  { 3,	OperandInfo51 },  // Inst #279 = ARRAY16
  { 3,	OperandInfo51 },  // Inst #280 = ARRAY32
  { 3,	OperandInfo51 },  // Inst #281 = ARRAY8
  { 1,	OperandInfo2 },  // Inst #282 = BA
  { 2,	OperandInfo7 },  // Inst #283 = BCOND
  { 2,	OperandInfo7 },  // Inst #284 = BCONDA
  { 2,	OperandInfo15 },  // Inst #285 = BINDri
  { 2,	OperandInfo53 },  // Inst #286 = BINDrr
  { 3,	OperandInfo51 },  // Inst #287 = BMASK
  { 3,	OperandInfo54 },  // Inst #288 = BPFCC
  { 3,	OperandInfo54 },  // Inst #289 = BPFCCA
  { 3,	OperandInfo54 },  // Inst #290 = BPFCCANT
  { 3,	OperandInfo54 },  // Inst #291 = BPFCCNT
  { 2,	OperandInfo55 },  // Inst #292 = BPGEZapn
  { 2,	OperandInfo55 },  // Inst #293 = BPGEZapt
  { 2,	OperandInfo55 },  // Inst #294 = BPGEZnapn
  { 2,	OperandInfo55 },  // Inst #295 = BPGEZnapt
  { 2,	OperandInfo55 },  // Inst #296 = BPGZapn
  { 2,	OperandInfo55 },  // Inst #297 = BPGZapt
  { 2,	OperandInfo55 },  // Inst #298 = BPGZnapn
  { 2,	OperandInfo55 },  // Inst #299 = BPGZnapt
  { 2,	OperandInfo7 },  // Inst #300 = BPICC
  { 2,	OperandInfo7 },  // Inst #301 = BPICCA
  { 2,	OperandInfo7 },  // Inst #302 = BPICCANT
  { 2,	OperandInfo7 },  // Inst #303 = BPICCNT
  { 2,	OperandInfo55 },  // Inst #304 = BPLEZapn
  { 2,	OperandInfo55 },  // Inst #305 = BPLEZapt
  { 2,	OperandInfo55 },  // Inst #306 = BPLEZnapn
  { 2,	OperandInfo55 },  // Inst #307 = BPLEZnapt
  { 2,	OperandInfo55 },  // Inst #308 = BPLZapn
  { 2,	OperandInfo55 },  // Inst #309 = BPLZapt
  { 2,	OperandInfo55 },  // Inst #310 = BPLZnapn
  { 2,	OperandInfo55 },  // Inst #311 = BPLZnapt
  { 2,	OperandInfo55 },  // Inst #312 = BPNZapn
  { 2,	OperandInfo55 },  // Inst #313 = BPNZapt
  { 2,	OperandInfo55 },  // Inst #314 = BPNZnapn
  { 2,	OperandInfo55 },  // Inst #315 = BPNZnapt
  { 2,	OperandInfo7 },  // Inst #316 = BPXCC
  { 2,	OperandInfo7 },  // Inst #317 = BPXCCA
  { 2,	OperandInfo7 },  // Inst #318 = BPXCCANT
  { 2,	OperandInfo7 },  // Inst #319 = BPXCCNT
  { 2,	OperandInfo55 },  // Inst #320 = BPZapn
  { 2,	OperandInfo55 },  // Inst #321 = BPZapt
  { 2,	OperandInfo55 },  // Inst #322 = BPZnapn
  { 2,	OperandInfo55 },  // Inst #323 = BPZnapt
  { 3,	OperandInfo56 },  // Inst #324 = BSHUFFLE
  { 1,	OperandInfo2 },  // Inst #325 = CALL
  { 2,	OperandInfo15 },  // Inst #326 = CALLri
  { 2,	OperandInfo53 },  // Inst #327 = CALLrr
  { 4,	OperandInfo57 },  // Inst #328 = CASAasi10
  { 5,	OperandInfo58 },  // Inst #329 = CASArr
  { 4,	OperandInfo59 },  // Inst #330 = CASXrr
  { 4,	OperandInfo57 },  // Inst #331 = CASrr
  { 2,	OperandInfo7 },  // Inst #332 = CBCOND
  { 2,	OperandInfo7 },  // Inst #333 = CBCONDA
  { 1,	OperandInfo60 },  // Inst #334 = CMASK16
  { 1,	OperandInfo60 },  // Inst #335 = CMASK32
  { 1,	OperandInfo60 },  // Inst #336 = CMASK8
  { 2,	OperandInfo61 },  // Inst #337 = CMPri
  { 2,	OperandInfo62 },  // Inst #338 = CMPrr
  { 3,	OperandInfo51 },  // Inst #339 = EDGE16
  { 3,	OperandInfo51 },  // Inst #340 = EDGE16L
  { 3,	OperandInfo51 },  // Inst #341 = EDGE16LN
  { 3,	OperandInfo51 },  // Inst #342 = EDGE16N
  { 3,	OperandInfo51 },  // Inst #343 = EDGE32
  { 3,	OperandInfo51 },  // Inst #344 = EDGE32L
  { 3,	OperandInfo51 },  // Inst #345 = EDGE32LN
  { 3,	OperandInfo51 },  // Inst #346 = EDGE32N
  { 3,	OperandInfo51 },  // Inst #347 = EDGE8
  { 3,	OperandInfo51 },  // Inst #348 = EDGE8L
  { 3,	OperandInfo51 },  // Inst #349 = EDGE8LN
  { 3,	OperandInfo51 },  // Inst #350 = EDGE8N
  { 2,	OperandInfo63 },  // Inst #351 = FABSD
  { 2,	OperandInfo64 },  // Inst #352 = FABSQ
  { 2,	OperandInfo65 },  // Inst #353 = FABSS
  { 3,	OperandInfo56 },  // Inst #354 = FADDD
  { 3,	OperandInfo66 },  // Inst #355 = FADDQ
  { 3,	OperandInfo67 },  // Inst #356 = FADDS
  { 3,	OperandInfo56 },  // Inst #357 = FALIGNADATA
  { 3,	OperandInfo56 },  // Inst #358 = FAND
  { 3,	OperandInfo56 },  // Inst #359 = FANDNOT1
  { 3,	OperandInfo67 },  // Inst #360 = FANDNOT1S
  { 3,	OperandInfo56 },  // Inst #361 = FANDNOT2
  { 3,	OperandInfo67 },  // Inst #362 = FANDNOT2S
  { 3,	OperandInfo67 },  // Inst #363 = FANDS
  { 2,	OperandInfo7 },  // Inst #364 = FBCOND
  { 2,	OperandInfo7 },  // Inst #365 = FBCONDA
  { 3,	OperandInfo56 },  // Inst #366 = FCHKSM16
  { 2,	OperandInfo63 },  // Inst #367 = FCMPD
  { 3,	OperandInfo68 },  // Inst #368 = FCMPEQ16
  { 3,	OperandInfo68 },  // Inst #369 = FCMPEQ32
  { 3,	OperandInfo68 },  // Inst #370 = FCMPGT16
  { 3,	OperandInfo68 },  // Inst #371 = FCMPGT32
  { 3,	OperandInfo68 },  // Inst #372 = FCMPLE16
  { 3,	OperandInfo68 },  // Inst #373 = FCMPLE32
  { 3,	OperandInfo68 },  // Inst #374 = FCMPNE16
  { 3,	OperandInfo68 },  // Inst #375 = FCMPNE32
  { 2,	OperandInfo64 },  // Inst #376 = FCMPQ
  { 2,	OperandInfo65 },  // Inst #377 = FCMPS
  { 3,	OperandInfo56 },  // Inst #378 = FDIVD
  { 3,	OperandInfo66 },  // Inst #379 = FDIVQ
  { 3,	OperandInfo67 },  // Inst #380 = FDIVS
  { 3,	OperandInfo69 },  // Inst #381 = FDMULQ
  { 2,	OperandInfo70 },  // Inst #382 = FDTOI
  { 2,	OperandInfo71 },  // Inst #383 = FDTOQ
  { 2,	OperandInfo70 },  // Inst #384 = FDTOS
  { 2,	OperandInfo63 },  // Inst #385 = FDTOX
  { 2,	OperandInfo63 },  // Inst #386 = FEXPAND
  { 3,	OperandInfo56 },  // Inst #387 = FHADDD
  { 3,	OperandInfo56 },  // Inst #388 = FHADDS
  { 3,	OperandInfo56 },  // Inst #389 = FHSUBD
  { 3,	OperandInfo56 },  // Inst #390 = FHSUBS
  { 2,	OperandInfo72 },  // Inst #391 = FITOD
  { 2,	OperandInfo73 },  // Inst #392 = FITOQ
  { 2,	OperandInfo65 },  // Inst #393 = FITOS
  { 3,	OperandInfo74 },  // Inst #394 = FLCMPD
  { 3,	OperandInfo74 },  // Inst #395 = FLCMPS
  { 0,	NULL },  // Inst #396 = FLUSH
  { 0,	NULL },  // Inst #397 = FLUSHW
  { 2,	OperandInfo15 },  // Inst #398 = FLUSHri
  { 2,	OperandInfo53 },  // Inst #399 = FLUSHrr
  { 3,	OperandInfo56 },  // Inst #400 = FMEAN16
  { 2,	OperandInfo63 },  // Inst #401 = FMOVD
  { 4,	OperandInfo75 },  // Inst #402 = FMOVD_FCC
  { 4,	OperandInfo75 },  // Inst #403 = FMOVD_ICC
  { 4,	OperandInfo75 },  // Inst #404 = FMOVD_XCC
  { 2,	OperandInfo64 },  // Inst #405 = FMOVQ
  { 4,	OperandInfo76 },  // Inst #406 = FMOVQ_FCC
  { 4,	OperandInfo76 },  // Inst #407 = FMOVQ_ICC
  { 4,	OperandInfo76 },  // Inst #408 = FMOVQ_XCC
  { 3,	OperandInfo77 },  // Inst #409 = FMOVRGEZD
  { 3,	OperandInfo77 },  // Inst #410 = FMOVRGEZQ
  { 3,	OperandInfo77 },  // Inst #411 = FMOVRGEZS
  { 3,	OperandInfo77 },  // Inst #412 = FMOVRGZD
  { 3,	OperandInfo77 },  // Inst #413 = FMOVRGZQ
  { 3,	OperandInfo77 },  // Inst #414 = FMOVRGZS
  { 3,	OperandInfo77 },  // Inst #415 = FMOVRLEZD
  { 3,	OperandInfo77 },  // Inst #416 = FMOVRLEZQ
  { 3,	OperandInfo77 },  // Inst #417 = FMOVRLEZS
  { 3,	OperandInfo77 },  // Inst #418 = FMOVRLZD
  { 3,	OperandInfo77 },  // Inst #419 = FMOVRLZQ
  { 3,	OperandInfo77 },  // Inst #420 = FMOVRLZS
  { 3,	OperandInfo77 },  // Inst #421 = FMOVRNZD
  { 3,	OperandInfo77 },  // Inst #422 = FMOVRNZQ
  { 3,	OperandInfo77 },  // Inst #423 = FMOVRNZS
  { 3,	OperandInfo77 },  // Inst #424 = FMOVRZD
  { 3,	OperandInfo77 },  // Inst #425 = FMOVRZQ
  { 3,	OperandInfo77 },  // Inst #426 = FMOVRZS
  { 2,	OperandInfo65 },  // Inst #427 = FMOVS
  { 4,	OperandInfo78 },  // Inst #428 = FMOVS_FCC
  { 4,	OperandInfo78 },  // Inst #429 = FMOVS_ICC
  { 4,	OperandInfo78 },  // Inst #430 = FMOVS_XCC
  { 3,	OperandInfo56 },  // Inst #431 = FMUL8SUX16
  { 3,	OperandInfo56 },  // Inst #432 = FMUL8ULX16
  { 3,	OperandInfo56 },  // Inst #433 = FMUL8X16
  { 3,	OperandInfo56 },  // Inst #434 = FMUL8X16AL
  { 3,	OperandInfo56 },  // Inst #435 = FMUL8X16AU
  { 3,	OperandInfo56 },  // Inst #436 = FMULD
  { 3,	OperandInfo56 },  // Inst #437 = FMULD8SUX16
  { 3,	OperandInfo56 },  // Inst #438 = FMULD8ULX16
  { 3,	OperandInfo66 },  // Inst #439 = FMULQ
  { 3,	OperandInfo67 },  // Inst #440 = FMULS
  { 3,	OperandInfo56 },  // Inst #441 = FNADDD
  { 3,	OperandInfo56 },  // Inst #442 = FNADDS
  { 3,	OperandInfo56 },  // Inst #443 = FNAND
  { 3,	OperandInfo67 },  // Inst #444 = FNANDS
  { 2,	OperandInfo63 },  // Inst #445 = FNEGD
  { 2,	OperandInfo64 },  // Inst #446 = FNEGQ
  { 2,	OperandInfo65 },  // Inst #447 = FNEGS
  { 3,	OperandInfo56 },  // Inst #448 = FNHADDD
  { 3,	OperandInfo56 },  // Inst #449 = FNHADDS
  { 3,	OperandInfo56 },  // Inst #450 = FNMULD
  { 3,	OperandInfo56 },  // Inst #451 = FNMULS
  { 3,	OperandInfo56 },  // Inst #452 = FNOR
  { 3,	OperandInfo67 },  // Inst #453 = FNORS
  { 2,	OperandInfo63 },  // Inst #454 = FNOT1
  { 2,	OperandInfo65 },  // Inst #455 = FNOT1S
  { 2,	OperandInfo63 },  // Inst #456 = FNOT2
  { 2,	OperandInfo65 },  // Inst #457 = FNOT2S
  { 3,	OperandInfo56 },  // Inst #458 = FNSMULD
  { 2,	OperandInfo79 },  // Inst #459 = FONE
  { 2,	OperandInfo80 },  // Inst #460 = FONES
  { 3,	OperandInfo56 },  // Inst #461 = FOR
  { 3,	OperandInfo56 },  // Inst #462 = FORNOT1
  { 3,	OperandInfo67 },  // Inst #463 = FORNOT1S
  { 3,	OperandInfo56 },  // Inst #464 = FORNOT2
  { 3,	OperandInfo67 },  // Inst #465 = FORNOT2S
  { 3,	OperandInfo67 },  // Inst #466 = FORS
  { 2,	OperandInfo63 },  // Inst #467 = FPACK16
  { 3,	OperandInfo56 },  // Inst #468 = FPACK32
  { 2,	OperandInfo63 },  // Inst #469 = FPACKFIX
  { 3,	OperandInfo56 },  // Inst #470 = FPADD16
  { 3,	OperandInfo56 },  // Inst #471 = FPADD16S
  { 3,	OperandInfo56 },  // Inst #472 = FPADD32
  { 3,	OperandInfo56 },  // Inst #473 = FPADD32S
  { 3,	OperandInfo56 },  // Inst #474 = FPADD64
  { 3,	OperandInfo56 },  // Inst #475 = FPMERGE
  { 3,	OperandInfo56 },  // Inst #476 = FPSUB16
  { 3,	OperandInfo56 },  // Inst #477 = FPSUB16S
  { 3,	OperandInfo56 },  // Inst #478 = FPSUB32
  { 3,	OperandInfo56 },  // Inst #479 = FPSUB32S
  { 2,	OperandInfo81 },  // Inst #480 = FQTOD
  { 2,	OperandInfo82 },  // Inst #481 = FQTOI
  { 2,	OperandInfo82 },  // Inst #482 = FQTOS
  { 2,	OperandInfo81 },  // Inst #483 = FQTOX
  { 3,	OperandInfo56 },  // Inst #484 = FSLAS16
  { 3,	OperandInfo56 },  // Inst #485 = FSLAS32
  { 3,	OperandInfo56 },  // Inst #486 = FSLL16
  { 3,	OperandInfo56 },  // Inst #487 = FSLL32
  { 3,	OperandInfo83 },  // Inst #488 = FSMULD
  { 2,	OperandInfo63 },  // Inst #489 = FSQRTD
  { 2,	OperandInfo64 },  // Inst #490 = FSQRTQ
  { 2,	OperandInfo65 },  // Inst #491 = FSQRTS
  { 3,	OperandInfo56 },  // Inst #492 = FSRA16
  { 3,	OperandInfo56 },  // Inst #493 = FSRA32
  { 2,	OperandInfo63 },  // Inst #494 = FSRC1
  { 2,	OperandInfo65 },  // Inst #495 = FSRC1S
  { 2,	OperandInfo63 },  // Inst #496 = FSRC2
  { 2,	OperandInfo65 },  // Inst #497 = FSRC2S
  { 3,	OperandInfo56 },  // Inst #498 = FSRL16
  { 3,	OperandInfo56 },  // Inst #499 = FSRL32
  { 2,	OperandInfo72 },  // Inst #500 = FSTOD
  { 2,	OperandInfo65 },  // Inst #501 = FSTOI
  { 2,	OperandInfo73 },  // Inst #502 = FSTOQ
  { 2,	OperandInfo72 },  // Inst #503 = FSTOX
  { 3,	OperandInfo56 },  // Inst #504 = FSUBD
  { 3,	OperandInfo66 },  // Inst #505 = FSUBQ
  { 3,	OperandInfo67 },  // Inst #506 = FSUBS
  { 3,	OperandInfo56 },  // Inst #507 = FXNOR
  { 3,	OperandInfo67 },  // Inst #508 = FXNORS
  { 3,	OperandInfo56 },  // Inst #509 = FXOR
  { 3,	OperandInfo67 },  // Inst #510 = FXORS
  { 2,	OperandInfo63 },  // Inst #511 = FXTOD
  { 2,	OperandInfo71 },  // Inst #512 = FXTOQ
  { 2,	OperandInfo70 },  // Inst #513 = FXTOS
  { 2,	OperandInfo79 },  // Inst #514 = FZERO
  { 2,	OperandInfo80 },  // Inst #515 = FZEROS
  { 3,	OperandInfo84 },  // Inst #516 = JMPLri
  { 3,	OperandInfo85 },  // Inst #517 = JMPLrr
  { 4,	OperandInfo86 },  // Inst #518 = LDArr
  { 2,	OperandInfo15 },  // Inst #519 = LDCSRri
  { 2,	OperandInfo53 },  // Inst #520 = LDCSRrr
  { 3,	OperandInfo87 },  // Inst #521 = LDCri
  { 3,	OperandInfo88 },  // Inst #522 = LDCrr
  { 4,	OperandInfo89 },  // Inst #523 = LDDArr
  { 3,	OperandInfo90 },  // Inst #524 = LDDCri
  { 3,	OperandInfo91 },  // Inst #525 = LDDCrr
  { 4,	OperandInfo92 },  // Inst #526 = LDDFArr
  { 3,	OperandInfo93 },  // Inst #527 = LDDFri
  { 3,	OperandInfo94 },  // Inst #528 = LDDFrr
  { 3,	OperandInfo95 },  // Inst #529 = LDDri
  { 3,	OperandInfo96 },  // Inst #530 = LDDrr
  { 4,	OperandInfo97 },  // Inst #531 = LDFArr
  { 2,	OperandInfo15 },  // Inst #532 = LDFSRri
  { 2,	OperandInfo53 },  // Inst #533 = LDFSRrr
  { 3,	OperandInfo98 },  // Inst #534 = LDFri
  { 3,	OperandInfo99 },  // Inst #535 = LDFrr
  { 4,	OperandInfo100 },  // Inst #536 = LDQFArr
  { 3,	OperandInfo101 },  // Inst #537 = LDQFri
  { 3,	OperandInfo102 },  // Inst #538 = LDQFrr
  { 4,	OperandInfo86 },  // Inst #539 = LDSBArr
  { 3,	OperandInfo84 },  // Inst #540 = LDSBri
  { 3,	OperandInfo85 },  // Inst #541 = LDSBrr
  { 4,	OperandInfo86 },  // Inst #542 = LDSHArr
  { 3,	OperandInfo84 },  // Inst #543 = LDSHri
  { 3,	OperandInfo85 },  // Inst #544 = LDSHrr
  { 4,	OperandInfo86 },  // Inst #545 = LDSTUBArr
  { 3,	OperandInfo84 },  // Inst #546 = LDSTUBri
  { 3,	OperandInfo85 },  // Inst #547 = LDSTUBrr
  { 3,	OperandInfo103 },  // Inst #548 = LDSWri
  { 3,	OperandInfo104 },  // Inst #549 = LDSWrr
  { 4,	OperandInfo86 },  // Inst #550 = LDUBArr
  { 3,	OperandInfo84 },  // Inst #551 = LDUBri
  { 3,	OperandInfo85 },  // Inst #552 = LDUBrr
  { 4,	OperandInfo86 },  // Inst #553 = LDUHArr
  { 3,	OperandInfo84 },  // Inst #554 = LDUHri
  { 3,	OperandInfo85 },  // Inst #555 = LDUHrr
  { 2,	OperandInfo15 },  // Inst #556 = LDXFSRri
  { 2,	OperandInfo53 },  // Inst #557 = LDXFSRrr
  { 3,	OperandInfo103 },  // Inst #558 = LDXri
  { 3,	OperandInfo104 },  // Inst #559 = LDXrr
  { 3,	OperandInfo84 },  // Inst #560 = LDri
  { 3,	OperandInfo85 },  // Inst #561 = LDrr
  { 3,	OperandInfo103 },  // Inst #562 = LEAX_ADDri
  { 3,	OperandInfo84 },  // Inst #563 = LEA_ADDri
  { 2,	OperandInfo105 },  // Inst #564 = LZCNT
  { 1,	OperandInfo2 },  // Inst #565 = MEMBARi
  { 2,	OperandInfo106 },  // Inst #566 = MOVDTOX
  { 4,	OperandInfo107 },  // Inst #567 = MOVFCCri
  { 4,	OperandInfo108 },  // Inst #568 = MOVFCCrr
  { 4,	OperandInfo107 },  // Inst #569 = MOVICCri
  { 4,	OperandInfo108 },  // Inst #570 = MOVICCrr
  { 3,	OperandInfo52 },  // Inst #571 = MOVRGEZri
  { 3,	OperandInfo109 },  // Inst #572 = MOVRGEZrr
  { 3,	OperandInfo52 },  // Inst #573 = MOVRGZri
  { 3,	OperandInfo109 },  // Inst #574 = MOVRGZrr
  { 3,	OperandInfo52 },  // Inst #575 = MOVRLEZri
  { 3,	OperandInfo109 },  // Inst #576 = MOVRLEZrr
  { 3,	OperandInfo52 },  // Inst #577 = MOVRLZri
  { 3,	OperandInfo109 },  // Inst #578 = MOVRLZrr
  { 3,	OperandInfo52 },  // Inst #579 = MOVRNZri
  { 3,	OperandInfo109 },  // Inst #580 = MOVRNZrr
  { 3,	OperandInfo52 },  // Inst #581 = MOVRRZri
  { 3,	OperandInfo109 },  // Inst #582 = MOVRRZrr
  { 2,	OperandInfo106 },  // Inst #583 = MOVSTOSW
  { 2,	OperandInfo106 },  // Inst #584 = MOVSTOUW
  { 2,	OperandInfo110 },  // Inst #585 = MOVWTOS
  { 4,	OperandInfo107 },  // Inst #586 = MOVXCCri
  { 4,	OperandInfo108 },  // Inst #587 = MOVXCCrr
  { 2,	OperandInfo110 },  // Inst #588 = MOVXTOD
  { 3,	OperandInfo49 },  // Inst #589 = MULSCCri
  { 3,	OperandInfo50 },  // Inst #590 = MULSCCrr
  { 3,	OperandInfo111 },  // Inst #591 = MULXri
  { 3,	OperandInfo51 },  // Inst #592 = MULXrr
  { 0,	NULL },  // Inst #593 = NOP
  { 3,	OperandInfo49 },  // Inst #594 = ORCCri
  { 3,	OperandInfo50 },  // Inst #595 = ORCCrr
  { 3,	OperandInfo49 },  // Inst #596 = ORNCCri
  { 3,	OperandInfo50 },  // Inst #597 = ORNCCrr
  { 3,	OperandInfo49 },  // Inst #598 = ORNri
  { 3,	OperandInfo50 },  // Inst #599 = ORNrr
  { 3,	OperandInfo51 },  // Inst #600 = ORXNrr
  { 3,	OperandInfo52 },  // Inst #601 = ORXri
  { 3,	OperandInfo51 },  // Inst #602 = ORXrr
  { 3,	OperandInfo49 },  // Inst #603 = ORri
  { 3,	OperandInfo50 },  // Inst #604 = ORrr
  { 3,	OperandInfo56 },  // Inst #605 = PDIST
  { 3,	OperandInfo56 },  // Inst #606 = PDISTN
  { 2,	OperandInfo62 },  // Inst #607 = POPCrr
  { 3,	OperandInfo112 },  // Inst #608 = PREFETCHi
  { 3,	OperandInfo113 },  // Inst #609 = PREFETCHr
  { 2,	OperandInfo61 },  // Inst #610 = PWRPSRri
  { 2,	OperandInfo62 },  // Inst #611 = PWRPSRrr
  { 2,	OperandInfo114 },  // Inst #612 = RDASR
  { 1,	OperandInfo115 },  // Inst #613 = RDPC
  { 2,	OperandInfo116 },  // Inst #614 = RDPR
  { 1,	OperandInfo115 },  // Inst #615 = RDPSR
  { 1,	OperandInfo115 },  // Inst #616 = RDTBR
  { 1,	OperandInfo115 },  // Inst #617 = RDWIM
  { 3,	OperandInfo49 },  // Inst #618 = RESTOREri
  { 3,	OperandInfo50 },  // Inst #619 = RESTORErr
  { 1,	OperandInfo3 },  // Inst #620 = RET
  { 1,	OperandInfo3 },  // Inst #621 = RETL
  { 2,	OperandInfo15 },  // Inst #622 = RETTri
  { 2,	OperandInfo53 },  // Inst #623 = RETTrr
  { 3,	OperandInfo49 },  // Inst #624 = SAVEri
  { 3,	OperandInfo50 },  // Inst #625 = SAVErr
  { 3,	OperandInfo49 },  // Inst #626 = SDIVCCri
  { 3,	OperandInfo50 },  // Inst #627 = SDIVCCrr
  { 3,	OperandInfo111 },  // Inst #628 = SDIVXri
  { 3,	OperandInfo51 },  // Inst #629 = SDIVXrr
  { 3,	OperandInfo49 },  // Inst #630 = SDIVri
  { 3,	OperandInfo50 },  // Inst #631 = SDIVrr
  { 2,	OperandInfo48 },  // Inst #632 = SETHIXi
  { 2,	OperandInfo48 },  // Inst #633 = SETHIi
  { 0,	NULL },  // Inst #634 = SHUTDOWN
  { 0,	NULL },  // Inst #635 = SIAM
  { 1,	OperandInfo2 },  // Inst #636 = SIR
  { 3,	OperandInfo117 },  // Inst #637 = SLLXri
  { 3,	OperandInfo109 },  // Inst #638 = SLLXrr
  { 3,	OperandInfo49 },  // Inst #639 = SLLri
  { 3,	OperandInfo50 },  // Inst #640 = SLLrr
  { 4,	OperandInfo118 },  // Inst #641 = SMACri
  { 4,	OperandInfo119 },  // Inst #642 = SMACrr
  { 3,	OperandInfo49 },  // Inst #643 = SMULCCri
  { 3,	OperandInfo50 },  // Inst #644 = SMULCCrr
  { 3,	OperandInfo49 },  // Inst #645 = SMULri
  { 3,	OperandInfo50 },  // Inst #646 = SMULrr
  { 3,	OperandInfo117 },  // Inst #647 = SRAXri
  { 3,	OperandInfo109 },  // Inst #648 = SRAXrr
  { 3,	OperandInfo49 },  // Inst #649 = SRAri
  { 3,	OperandInfo50 },  // Inst #650 = SRArr
  { 3,	OperandInfo117 },  // Inst #651 = SRLXri
  { 3,	OperandInfo109 },  // Inst #652 = SRLXrr
  { 3,	OperandInfo49 },  // Inst #653 = SRLri
  { 3,	OperandInfo50 },  // Inst #654 = SRLrr
  { 4,	OperandInfo120 },  // Inst #655 = STArr
  { 0,	NULL },  // Inst #656 = STBAR
  { 4,	OperandInfo120 },  // Inst #657 = STBArr
  { 3,	OperandInfo121 },  // Inst #658 = STBri
  { 3,	OperandInfo122 },  // Inst #659 = STBrr
  { 2,	OperandInfo15 },  // Inst #660 = STCSRri
  { 2,	OperandInfo53 },  // Inst #661 = STCSRrr
  { 3,	OperandInfo123 },  // Inst #662 = STCri
  { 3,	OperandInfo124 },  // Inst #663 = STCrr
  { 4,	OperandInfo125 },  // Inst #664 = STDArr
  { 2,	OperandInfo15 },  // Inst #665 = STDCQri
  { 2,	OperandInfo53 },  // Inst #666 = STDCQrr
  { 3,	OperandInfo126 },  // Inst #667 = STDCri
  { 3,	OperandInfo127 },  // Inst #668 = STDCrr
  { 4,	OperandInfo128 },  // Inst #669 = STDFArr
  { 2,	OperandInfo15 },  // Inst #670 = STDFQri
  { 2,	OperandInfo53 },  // Inst #671 = STDFQrr
  { 3,	OperandInfo129 },  // Inst #672 = STDFri
  { 3,	OperandInfo130 },  // Inst #673 = STDFrr
  { 3,	OperandInfo131 },  // Inst #674 = STDri
  { 3,	OperandInfo132 },  // Inst #675 = STDrr
  { 4,	OperandInfo133 },  // Inst #676 = STFArr
  { 2,	OperandInfo15 },  // Inst #677 = STFSRri
  { 2,	OperandInfo53 },  // Inst #678 = STFSRrr
  { 3,	OperandInfo134 },  // Inst #679 = STFri
  { 3,	OperandInfo135 },  // Inst #680 = STFrr
  { 4,	OperandInfo120 },  // Inst #681 = STHArr
  { 3,	OperandInfo121 },  // Inst #682 = STHri
  { 3,	OperandInfo122 },  // Inst #683 = STHrr
  { 4,	OperandInfo136 },  // Inst #684 = STQFArr
  { 3,	OperandInfo137 },  // Inst #685 = STQFri
  { 3,	OperandInfo138 },  // Inst #686 = STQFrr
  { 2,	OperandInfo15 },  // Inst #687 = STXFSRri
  { 2,	OperandInfo53 },  // Inst #688 = STXFSRrr
  { 3,	OperandInfo139 },  // Inst #689 = STXri
  { 3,	OperandInfo140 },  // Inst #690 = STXrr
  { 3,	OperandInfo121 },  // Inst #691 = STri
  { 3,	OperandInfo122 },  // Inst #692 = STrr
  { 3,	OperandInfo49 },  // Inst #693 = SUBCCri
  { 3,	OperandInfo50 },  // Inst #694 = SUBCCrr
  { 3,	OperandInfo49 },  // Inst #695 = SUBCri
  { 3,	OperandInfo50 },  // Inst #696 = SUBCrr
  { 3,	OperandInfo49 },  // Inst #697 = SUBEri
  { 3,	OperandInfo50 },  // Inst #698 = SUBErr
  { 3,	OperandInfo52 },  // Inst #699 = SUBXri
  { 3,	OperandInfo51 },  // Inst #700 = SUBXrr
  { 3,	OperandInfo49 },  // Inst #701 = SUBri
  { 3,	OperandInfo50 },  // Inst #702 = SUBrr
  { 5,	OperandInfo141 },  // Inst #703 = SWAPArr
  { 4,	OperandInfo142 },  // Inst #704 = SWAPri
  { 4,	OperandInfo143 },  // Inst #705 = SWAPrr
  { 0,	NULL },  // Inst #706 = TA1
  { 0,	NULL },  // Inst #707 = TA3
  { 0,	NULL },  // Inst #708 = TA5
  { 3,	OperandInfo49 },  // Inst #709 = TADDCCTVri
  { 3,	OperandInfo50 },  // Inst #710 = TADDCCTVrr
  { 3,	OperandInfo49 },  // Inst #711 = TADDCCri
  { 3,	OperandInfo50 },  // Inst #712 = TADDCCrr
  { 3,	OperandInfo144 },  // Inst #713 = TICCri
  { 3,	OperandInfo49 },  // Inst #714 = TICCrr
  { 4,	OperandInfo145 },  // Inst #715 = TLS_ADDXrr
  { 4,	OperandInfo146 },  // Inst #716 = TLS_ADDrr
  { 2,	OperandInfo7 },  // Inst #717 = TLS_CALL
  { 4,	OperandInfo147 },  // Inst #718 = TLS_LDXrr
  { 4,	OperandInfo147 },  // Inst #719 = TLS_LDrr
  { 3,	OperandInfo144 },  // Inst #720 = TRAPri
  { 3,	OperandInfo49 },  // Inst #721 = TRAPrr
  { 3,	OperandInfo49 },  // Inst #722 = TSUBCCTVri
  { 3,	OperandInfo50 },  // Inst #723 = TSUBCCTVrr
  { 3,	OperandInfo49 },  // Inst #724 = TSUBCCri
  { 3,	OperandInfo50 },  // Inst #725 = TSUBCCrr
  { 3,	OperandInfo144 },  // Inst #726 = TXCCri
  { 3,	OperandInfo49 },  // Inst #727 = TXCCrr
  { 3,	OperandInfo49 },  // Inst #728 = UDIVCCri
  { 3,	OperandInfo50 },  // Inst #729 = UDIVCCrr
  { 3,	OperandInfo111 },  // Inst #730 = UDIVXri
  { 3,	OperandInfo51 },  // Inst #731 = UDIVXrr
  { 3,	OperandInfo49 },  // Inst #732 = UDIVri
  { 3,	OperandInfo50 },  // Inst #733 = UDIVrr
  { 4,	OperandInfo118 },  // Inst #734 = UMACri
  { 4,	OperandInfo119 },  // Inst #735 = UMACrr
  { 3,	OperandInfo49 },  // Inst #736 = UMULCCri
  { 3,	OperandInfo50 },  // Inst #737 = UMULCCrr
  { 3,	OperandInfo51 },  // Inst #738 = UMULXHI
  { 3,	OperandInfo49 },  // Inst #739 = UMULri
  { 3,	OperandInfo50 },  // Inst #740 = UMULrr
  { 1,	OperandInfo3 },  // Inst #741 = UNIMP
  { 3,	OperandInfo74 },  // Inst #742 = V9FCMPD
  { 3,	OperandInfo74 },  // Inst #743 = V9FCMPED
  { 3,	OperandInfo148 },  // Inst #744 = V9FCMPEQ
  { 3,	OperandInfo149 },  // Inst #745 = V9FCMPES
  { 3,	OperandInfo148 },  // Inst #746 = V9FCMPQ
  { 3,	OperandInfo149 },  // Inst #747 = V9FCMPS
  { 5,	OperandInfo150 },  // Inst #748 = V9FMOVD_FCC
  { 5,	OperandInfo151 },  // Inst #749 = V9FMOVQ_FCC
  { 5,	OperandInfo152 },  // Inst #750 = V9FMOVS_FCC
  { 5,	OperandInfo153 },  // Inst #751 = V9MOVFCCri
  { 5,	OperandInfo154 },  // Inst #752 = V9MOVFCCrr
  { 3,	OperandInfo155 },  // Inst #753 = WRASRri
  { 3,	OperandInfo156 },  // Inst #754 = WRASRrr
  { 3,	OperandInfo157 },  // Inst #755 = WRPRri
  { 3,	OperandInfo158 },  // Inst #756 = WRPRrr
  { 2,	OperandInfo61 },  // Inst #757 = WRPSRri
  { 2,	OperandInfo62 },  // Inst #758 = WRPSRrr
  { 2,	OperandInfo61 },  // Inst #759 = WRTBRri
  { 2,	OperandInfo62 },  // Inst #760 = WRTBRrr
  { 2,	OperandInfo61 },  // Inst #761 = WRWIMri
  { 2,	OperandInfo62 },  // Inst #762 = WRWIMrr
  { 3,	OperandInfo51 },  // Inst #763 = XMULX
  { 3,	OperandInfo51 },  // Inst #764 = XMULXHI
  { 3,	OperandInfo49 },  // Inst #765 = XNORCCri
  { 3,	OperandInfo50 },  // Inst #766 = XNORCCrr
  { 3,	OperandInfo51 },  // Inst #767 = XNORXrr
  { 3,	OperandInfo49 },  // Inst #768 = XNORri
  { 3,	OperandInfo50 },  // Inst #769 = XNORrr
  { 3,	OperandInfo49 },  // Inst #770 = XORCCri
  { 3,	OperandInfo50 },  // Inst #771 = XORCCrr
  { 3,	OperandInfo52 },  // Inst #772 = XORXri
  { 3,	OperandInfo51 },  // Inst #773 = XORXrr
  { 3,	OperandInfo49 },  // Inst #774 = XORri
  { 3,	OperandInfo50 },  // Inst #775 = XORrr
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char SparcInstrNameData[] = {
  /* 0 */ "G_FLOG10\0"
  /* 9 */ "CASAasi10\0"
  /* 19 */ "TA1\0"
  /* 23 */ "FSRC1\0"
  /* 29 */ "FANDNOT1\0"
  /* 38 */ "FNOT1\0"
  /* 44 */ "FORNOT1\0"
  /* 52 */ "FSRA32\0"
  /* 59 */ "FPSUB32\0"
  /* 67 */ "FPADD32\0"
  /* 75 */ "EDGE32\0"
  /* 82 */ "FCMPLE32\0"
  /* 91 */ "FCMPNE32\0"
  /* 100 */ "FPACK32\0"
  /* 108 */ "CMASK32\0"
  /* 116 */ "FSLL32\0"
  /* 123 */ "FSRL32\0"
  /* 130 */ "FCMPEQ32\0"
  /* 139 */ "FSLAS32\0"
  /* 147 */ "FCMPGT32\0"
  /* 156 */ "ARRAY32\0"
  /* 164 */ "FSRC2\0"
  /* 170 */ "G_FLOG2\0"
  /* 178 */ "G_FEXP2\0"
  /* 186 */ "FANDNOT2\0"
  /* 195 */ "FNOT2\0"
  /* 201 */ "FORNOT2\0"
  /* 209 */ "TA3\0"
  /* 213 */ "FPADD64\0"
  /* 221 */ "TA5\0"
  /* 225 */ "FSRA16\0"
  /* 232 */ "FPSUB16\0"
  /* 240 */ "FPADD16\0"
  /* 248 */ "EDGE16\0"
  /* 255 */ "FCMPLE16\0"
  /* 264 */ "FCMPNE16\0"
  /* 273 */ "FPACK16\0"
  /* 281 */ "CMASK16\0"
  /* 289 */ "FSLL16\0"
  /* 296 */ "FSRL16\0"
  /* 303 */ "FCHKSM16\0"
  /* 312 */ "FMEAN16\0"
  /* 320 */ "FCMPEQ16\0"
  /* 329 */ "FSLAS16\0"
  /* 337 */ "FCMPGT16\0"
  /* 346 */ "FMUL8X16\0"
  /* 355 */ "FMULD8ULX16\0"
  /* 367 */ "FMUL8ULX16\0"
  /* 378 */ "FMULD8SUX16\0"
  /* 390 */ "FMUL8SUX16\0"
  /* 401 */ "ARRAY16\0"
  /* 409 */ "EDGE8\0"
  /* 415 */ "CMASK8\0"
  /* 422 */ "ARRAY8\0"
  /* 429 */ "BA\0"
  /* 432 */ "BPFCCA\0"
  /* 439 */ "BPICCA\0"
  /* 446 */ "BPXCCA\0"
  /* 453 */ "CBCONDA\0"
  /* 461 */ "FBCONDA\0"
  /* 469 */ "G_FMA\0"
  /* 475 */ "G_STRICT_FMA\0"
  /* 488 */ "FALIGNADATA\0"
  /* 500 */ "G_FSUB\0"
  /* 507 */ "G_STRICT_FSUB\0"
  /* 521 */ "G_ATOMICRMW_FSUB\0"
  /* 538 */ "G_SUB\0"
  /* 544 */ "G_ATOMICRMW_SUB\0"
  /* 560 */ "ADDXCCC\0"
  /* 568 */ "BPFCC\0"
  /* 574 */ "V9FMOVD_FCC\0"
  /* 586 */ "SELECT_CC_DFP_FCC\0"
  /* 604 */ "SELECT_CC_QFP_FCC\0"
  /* 622 */ "SELECT_CC_FP_FCC\0"
  /* 639 */ "V9FMOVQ_FCC\0"
  /* 651 */ "V9FMOVS_FCC\0"
  /* 663 */ "SELECT_CC_Int_FCC\0"
  /* 681 */ "BPICC\0"
  /* 687 */ "FMOVD_ICC\0"
  /* 697 */ "SELECT_CC_DFP_ICC\0"
  /* 715 */ "SELECT_CC_QFP_ICC\0"
  /* 733 */ "SELECT_CC_FP_ICC\0"
  /* 750 */ "FMOVQ_ICC\0"
  /* 760 */ "FMOVS_ICC\0"
  /* 770 */ "SELECT_CC_Int_ICC\0"
  /* 788 */ "BPXCC\0"
  /* 794 */ "FMOVD_XCC\0"
  /* 804 */ "FMOVQ_XCC\0"
  /* 814 */ "FMOVS_XCC\0"
  /* 824 */ "G_INTRINSIC\0"
  /* 836 */ "G_FPTRUNC\0"
  /* 846 */ "G_INTRINSIC_TRUNC\0"
  /* 864 */ "G_TRUNC\0"
  /* 872 */ "G_BUILD_VECTOR_TRUNC\0"
  /* 893 */ "G_DYN_STACKALLOC\0"
  /* 910 */ "RDPC\0"
  /* 915 */ "ADDXC\0"
  /* 921 */ "G_FMAD\0"
  /* 928 */ "G_INDEXED_SEXTLOAD\0"
  /* 947 */ "G_SEXTLOAD\0"
  /* 958 */ "G_INDEXED_ZEXTLOAD\0"
  /* 977 */ "G_ZEXTLOAD\0"
  /* 988 */ "G_INDEXED_LOAD\0"
  /* 1003 */ "G_LOAD\0"
  /* 1010 */ "FSUBD\0"
  /* 1016 */ "FHSUBD\0"
  /* 1023 */ "G_VECREDUCE_FADD\0"
  /* 1040 */ "G_FADD\0"
  /* 1047 */ "G_VECREDUCE_SEQ_FADD\0"
  /* 1068 */ "G_STRICT_FADD\0"
  /* 1082 */ "G_ATOMICRMW_FADD\0"
  /* 1099 */ "G_VECREDUCE_ADD\0"
  /* 1115 */ "G_ADD\0"
  /* 1121 */ "G_PTR_ADD\0"
  /* 1131 */ "G_ATOMICRMW_ADD\0"
  /* 1147 */ "FADDD\0"
  /* 1153 */ "FHADDD\0"
  /* 1160 */ "FNHADDD\0"
  /* 1168 */ "FNADDD\0"
  /* 1175 */ "V9FCMPED\0"
  /* 1184 */ "FNEGD\0"
  /* 1190 */ "FMULD\0"
  /* 1196 */ "FNMULD\0"
  /* 1203 */ "FSMULD\0"
  /* 1210 */ "FNSMULD\0"
  /* 1218 */ "FAND\0"
  /* 1223 */ "FNAND\0"
  /* 1229 */ "G_ATOMICRMW_NAND\0"
  /* 1246 */ "FEXPAND\0"
  /* 1254 */ "G_VECREDUCE_AND\0"
  /* 1270 */ "G_AND\0"
  /* 1276 */ "G_ATOMICRMW_AND\0"
  /* 1292 */ "LIFETIME_END\0"
  /* 1305 */ "CBCOND\0"
  /* 1312 */ "FBCOND\0"
  /* 1319 */ "G_BRCOND\0"
  /* 1328 */ "G_LLROUND\0"
  /* 1338 */ "G_LROUND\0"
  /* 1347 */ "G_INTRINSIC_ROUND\0"
  /* 1365 */ "FITOD\0"
  /* 1371 */ "FQTOD\0"
  /* 1377 */ "FSTOD\0"
  /* 1383 */ "FXTOD\0"
  /* 1389 */ "MOVXTOD\0"
  /* 1397 */ "V9FCMPD\0"
  /* 1405 */ "FLCMPD\0"
  /* 1412 */ "LOAD_STACK_GUARD\0"
  /* 1429 */ "FABSD\0"
  /* 1435 */ "FSQRTD\0"
  /* 1442 */ "FDIVD\0"
  /* 1448 */ "FMOVD\0"
  /* 1454 */ "FMOVRGEZD\0"
  /* 1464 */ "FMOVRLEZD\0"
  /* 1474 */ "FMOVRGZD\0"
  /* 1483 */ "FMOVRLZD\0"
  /* 1492 */ "FMOVRNZD\0"
  /* 1501 */ "FMOVRZD\0"
  /* 1509 */ "PSEUDO_PROBE\0"
  /* 1522 */ "G_SSUBE\0"
  /* 1530 */ "G_USUBE\0"
  /* 1538 */ "G_FENCE\0"
  /* 1546 */ "ARITH_FENCE\0"
  /* 1558 */ "REG_SEQUENCE\0"
  /* 1571 */ "G_SADDE\0"
  /* 1579 */ "G_UADDE\0"
  /* 1587 */ "G_FMINNUM_IEEE\0"
  /* 1602 */ "G_FMAXNUM_IEEE\0"
  /* 1617 */ "FPMERGE\0"
  /* 1625 */ "G_JUMP_TABLE\0"
  /* 1638 */ "BUNDLE\0"
  /* 1645 */ "BSHUFFLE\0"
  /* 1654 */ "G_MEMCPY_INLINE\0"
  /* 1670 */ "FONE\0"
  /* 1675 */ "LOCAL_ESCAPE\0"
  /* 1688 */ "G_INDEXED_STORE\0"
  /* 1704 */ "G_STORE\0"
  /* 1712 */ "G_BITREVERSE\0"
  /* 1725 */ "DBG_VALUE\0"
  /* 1735 */ "G_GLOBAL_VALUE\0"
  /* 1750 */ "G_MEMMOVE\0"
  /* 1760 */ "G_FREEZE\0"
  /* 1769 */ "G_FCANONICALIZE\0"
  /* 1785 */ "G_CTLZ_ZERO_UNDEF\0"
  /* 1803 */ "G_CTTZ_ZERO_UNDEF\0"
  /* 1821 */ "G_IMPLICIT_DEF\0"
  /* 1836 */ "DBG_INSTR_REF\0"
  /* 1850 */ "G_FNEG\0"
  /* 1857 */ "EXTRACT_SUBREG\0"
  /* 1872 */ "INSERT_SUBREG\0"
  /* 1886 */ "G_SEXT_INREG\0"
  /* 1899 */ "SUBREG_TO_REG\0"
  /* 1913 */ "G_ATOMIC_CMPXCHG\0"
  /* 1930 */ "G_ATOMICRMW_XCHG\0"
  /* 1947 */ "G_FLOG\0"
  /* 1954 */ "G_VAARG\0"
  /* 1962 */ "PREALLOCATED_ARG\0"
  /* 1979 */ "G_SMULH\0"
  /* 1987 */ "G_UMULH\0"
  /* 1995 */ "FLUSH\0"
  /* 2001 */ "DBG_PHI\0"
  /* 2009 */ "UMULXHI\0"
  /* 2017 */ "XMULXHI\0"
  /* 2025 */ "FDTOI\0"
  /* 2031 */ "FQTOI\0"
  /* 2037 */ "FSTOI\0"
  /* 2043 */ "G_FPTOSI\0"
  /* 2052 */ "G_FPTOUI\0"
  /* 2061 */ "G_FPOWI\0"
  /* 2069 */ "BMASK\0"
  /* 2075 */ "G_PTRMASK\0"
  /* 2085 */ "EDGE32L\0"
  /* 2093 */ "EDGE16L\0"
  /* 2101 */ "EDGE8L\0"
  /* 2108 */ "FMUL8X16AL\0"
  /* 2119 */ "GC_LABEL\0"
  /* 2128 */ "DBG_LABEL\0"
  /* 2138 */ "EH_LABEL\0"
  /* 2147 */ "ANNOTATION_LABEL\0"
  /* 2164 */ "ICALL_BRANCH_FUNNEL\0"
  /* 2184 */ "G_FSHL\0"
  /* 2191 */ "G_SHL\0"
  /* 2197 */ "G_FCEIL\0"
  /* 2205 */ "PATCHABLE_TAIL_CALL\0"
  /* 2225 */ "TLS_CALL\0"
  /* 2234 */ "PATCHABLE_TYPED_EVENT_CALL\0"
  /* 2261 */ "PATCHABLE_EVENT_CALL\0"
  /* 2282 */ "FENTRY_CALL\0"
  /* 2294 */ "KILL\0"
  /* 2299 */ "ALIGNADDRL\0"
  /* 2310 */ "RETL\0"
  /* 2315 */ "G_ROTL\0"
  /* 2322 */ "G_VECREDUCE_FMUL\0"
  /* 2339 */ "G_FMUL\0"
  /* 2346 */ "G_VECREDUCE_SEQ_FMUL\0"
  /* 2367 */ "G_STRICT_FMUL\0"
  /* 2381 */ "G_VECREDUCE_MUL\0"
  /* 2397 */ "G_MUL\0"
  /* 2403 */ "SIAM\0"
  /* 2408 */ "G_FREM\0"
  /* 2415 */ "G_STRICT_FREM\0"
  /* 2429 */ "G_SREM\0"
  /* 2436 */ "G_UREM\0"
  /* 2443 */ "G_SDIVREM\0"
  /* 2453 */ "G_UDIVREM\0"
  /* 2463 */ "RDWIM\0"
  /* 2469 */ "INLINEASM\0"
  /* 2479 */ "G_FMINIMUM\0"
  /* 2490 */ "G_FMAXIMUM\0"
  /* 2501 */ "G_FMINNUM\0"
  /* 2511 */ "G_FMAXNUM\0"
  /* 2521 */ "EDGE32N\0"
  /* 2529 */ "EDGE16N\0"
  /* 2537 */ "EDGE8N\0"
  /* 2544 */ "G_INTRINSIC_ROUNDEVEN\0"
  /* 2566 */ "G_FCOPYSIGN\0"
  /* 2578 */ "G_VECREDUCE_FMIN\0"
  /* 2595 */ "G_VECREDUCE_SMIN\0"
  /* 2612 */ "G_SMIN\0"
  /* 2619 */ "G_VECREDUCE_UMIN\0"
  /* 2636 */ "G_UMIN\0"
  /* 2643 */ "G_ATOMICRMW_UMIN\0"
  /* 2660 */ "G_ATOMICRMW_MIN\0"
  /* 2676 */ "G_FSIN\0"
  /* 2683 */ "EDGE32LN\0"
  /* 2692 */ "EDGE16LN\0"
  /* 2701 */ "EDGE8LN\0"
  /* 2709 */ "CFI_INSTRUCTION\0"
  /* 2725 */ "PDISTN\0"
  /* 2732 */ "ADJCALLSTACKDOWN\0"
  /* 2749 */ "SHUTDOWN\0"
  /* 2758 */ "G_SSUBO\0"
  /* 2766 */ "G_USUBO\0"
  /* 2774 */ "G_SADDO\0"
  /* 2782 */ "G_UADDO\0"
  /* 2790 */ "G_SMULO\0"
  /* 2798 */ "G_UMULO\0"
  /* 2806 */ "G_BZERO\0"
  /* 2814 */ "FZERO\0"
  /* 2820 */ "STACKMAP\0"
  /* 2829 */ "G_BSWAP\0"
  /* 2837 */ "G_SITOFP\0"
  /* 2846 */ "G_UITOFP\0"
  /* 2855 */ "G_FCMP\0"
  /* 2862 */ "G_ICMP\0"
  /* 2869 */ "UNIMP\0"
  /* 2875 */ "NOP\0"
  /* 2879 */ "G_CTPOP\0"
  /* 2887 */ "PATCHABLE_OP\0"
  /* 2900 */ "FAULTING_OP\0"
  /* 2912 */ "ADJCALLSTACKUP\0"
  /* 2927 */ "PREALLOCATED_SETUP\0"
  /* 2946 */ "G_FEXP\0"
  /* 2953 */ "FSUBQ\0"
  /* 2959 */ "FADDQ\0"
  /* 2965 */ "V9FCMPEQ\0"
  /* 2974 */ "FNEGQ\0"
  /* 2980 */ "FDMULQ\0"
  /* 2987 */ "FMULQ\0"
  /* 2993 */ "FDTOQ\0"
  /* 2999 */ "FITOQ\0"
  /* 3005 */ "FSTOQ\0"
  /* 3011 */ "FXTOQ\0"
  /* 3017 */ "V9FCMPQ\0"
  /* 3025 */ "FABSQ\0"
  /* 3031 */ "FSQRTQ\0"
  /* 3038 */ "FDIVQ\0"
  /* 3044 */ "FMOVQ\0"
  /* 3050 */ "FMOVRGEZQ\0"
  /* 3060 */ "FMOVRLEZQ\0"
  /* 3070 */ "FMOVRGZQ\0"
  /* 3079 */ "FMOVRLZQ\0"
  /* 3088 */ "FMOVRNZQ\0"
  /* 3097 */ "FMOVRZQ\0"
  /* 3105 */ "STBAR\0"
  /* 3111 */ "RDTBR\0"
  /* 3117 */ "G_BR\0"
  /* 3122 */ "INLINEASM_BR\0"
  /* 3135 */ "ALIGNADDR\0"
  /* 3145 */ "G_BLOCK_ADDR\0"
  /* 3158 */ "PATCHABLE_FUNCTION_ENTER\0"
  /* 3183 */ "G_READCYCLECOUNTER\0"
  /* 3202 */ "G_READ_REGISTER\0"
  /* 3218 */ "G_WRITE_REGISTER\0"
  /* 3235 */ "G_ASHR\0"
  /* 3242 */ "G_FSHR\0"
  /* 3249 */ "G_LSHR\0"
  /* 3256 */ "SIR\0"
  /* 3260 */ "FOR\0"
  /* 3264 */ "FNOR\0"
  /* 3269 */ "FXNOR\0"
  /* 3275 */ "G_FFLOOR\0"
  /* 3284 */ "G_BUILD_VECTOR\0"
  /* 3299 */ "G_SHUFFLE_VECTOR\0"
  /* 3316 */ "FXOR\0"
  /* 3321 */ "G_VECREDUCE_XOR\0"
  /* 3337 */ "G_XOR\0"
  /* 3343 */ "G_ATOMICRMW_XOR\0"
  /* 3359 */ "G_VECREDUCE_OR\0"
  /* 3374 */ "G_OR\0"
  /* 3379 */ "G_ATOMICRMW_OR\0"
  /* 3394 */ "RDPR\0"
  /* 3399 */ "RDASR\0"
  /* 3405 */ "RDPSR\0"
  /* 3411 */ "G_ROTR\0"
  /* 3418 */ "G_INTTOPTR\0"
  /* 3429 */ "FSRC1S\0"
  /* 3436 */ "FANDNOT1S\0"
  /* 3446 */ "FNOT1S\0"
  /* 3453 */ "FORNOT1S\0"
  /* 3462 */ "FPSUB32S\0"
  /* 3471 */ "FPADD32S\0"
  /* 3480 */ "FSRC2S\0"
  /* 3487 */ "FANDNOT2S\0"
  /* 3497 */ "FNOT2S\0"
  /* 3504 */ "FORNOT2S\0"
  /* 3513 */ "FPSUB16S\0"
  /* 3522 */ "FPADD16S\0"
  /* 3531 */ "G_FABS\0"
  /* 3538 */ "G_ABS\0"
  /* 3544 */ "FSUBS\0"
  /* 3550 */ "FHSUBS\0"
  /* 3557 */ "FADDS\0"
  /* 3563 */ "FHADDS\0"
  /* 3570 */ "FNHADDS\0"
  /* 3578 */ "FNADDS\0"
  /* 3585 */ "FANDS\0"
  /* 3591 */ "FNANDS\0"
  /* 3598 */ "FONES\0"
  /* 3604 */ "V9FCMPES\0"
  /* 3613 */ "G_UNMERGE_VALUES\0"
  /* 3630 */ "G_MERGE_VALUES\0"
  /* 3645 */ "FNEGS\0"
  /* 3651 */ "FMULS\0"
  /* 3657 */ "FNMULS\0"
  /* 3664 */ "G_FCOS\0"
  /* 3671 */ "FZEROS\0"
  /* 3678 */ "FDTOS\0"
  /* 3684 */ "FITOS\0"
  /* 3690 */ "FQTOS\0"
  /* 3696 */ "MOVWTOS\0"
  /* 3704 */ "FXTOS\0"
  /* 3710 */ "V9FCMPS\0"
  /* 3718 */ "FLCMPS\0"
  /* 3725 */ "FORS\0"
  /* 3730 */ "FNORS\0"
  /* 3736 */ "FXNORS\0"
  /* 3743 */ "G_CONCAT_VECTORS\0"
  /* 3760 */ "FXORS\0"
  /* 3766 */ "COPY_TO_REGCLASS\0"
  /* 3783 */ "FABSS\0"
  /* 3789 */ "G_ATOMIC_CMPXCHG_WITH_SUCCESS\0"
  /* 3819 */ "G_INTRINSIC_W_SIDE_EFFECTS\0"
  /* 3846 */ "FSQRTS\0"
  /* 3853 */ "FDIVS\0"
  /* 3859 */ "FMOVS\0"
  /* 3865 */ "FMOVRGEZS\0"
  /* 3875 */ "FMOVRLEZS\0"
  /* 3885 */ "FMOVRGZS\0"
  /* 3894 */ "FMOVRLZS\0"
  /* 3903 */ "FMOVRNZS\0"
  /* 3912 */ "FMOVRZS\0"
  /* 3920 */ "G_SSUBSAT\0"
  /* 3930 */ "G_USUBSAT\0"
  /* 3940 */ "G_SADDSAT\0"
  /* 3950 */ "G_UADDSAT\0"
  /* 3960 */ "G_SSHLSAT\0"
  /* 3970 */ "G_USHLSAT\0"
  /* 3980 */ "G_SMULFIXSAT\0"
  /* 3993 */ "G_UMULFIXSAT\0"
  /* 4006 */ "G_SDIVFIXSAT\0"
  /* 4019 */ "G_UDIVFIXSAT\0"
  /* 4032 */ "G_EXTRACT\0"
  /* 4042 */ "G_SELECT\0"
  /* 4051 */ "G_BRINDIRECT\0"
  /* 4064 */ "PATCHABLE_RET\0"
  /* 4078 */ "G_MEMSET\0"
  /* 4087 */ "PATCHABLE_FUNCTION_EXIT\0"
  /* 4111 */ "G_BRJT\0"
  /* 4118 */ "G_EXTRACT_VECTOR_ELT\0"
  /* 4139 */ "G_INSERT_VECTOR_ELT\0"
  /* 4159 */ "BPFCCANT\0"
  /* 4168 */ "BPICCANT\0"
  /* 4177 */ "BPXCCANT\0"
  /* 4186 */ "G_FCONSTANT\0"
  /* 4198 */ "G_CONSTANT\0"
  /* 4209 */ "BPFCCNT\0"
  /* 4217 */ "BPICCNT\0"
  /* 4225 */ "BPXCCNT\0"
  /* 4233 */ "LZCNT\0"
  /* 4239 */ "STATEPOINT\0"
  /* 4250 */ "PATCHPOINT\0"
  /* 4261 */ "G_PTRTOINT\0"
  /* 4272 */ "G_FRINT\0"
  /* 4280 */ "G_INTRINSIC_LRINT\0"
  /* 4298 */ "G_FNEARBYINT\0"
  /* 4311 */ "G_VASTART\0"
  /* 4321 */ "LIFETIME_START\0"
  /* 4336 */ "G_INSERT\0"
  /* 4345 */ "G_FSQRT\0"
  /* 4353 */ "G_STRICT_FSQRT\0"
  /* 4368 */ "G_BITCAST\0"
  /* 4378 */ "G_ADDRSPACE_CAST\0"
  /* 4395 */ "PDIST\0"
  /* 4401 */ "DBG_VALUE_LIST\0"
  /* 4416 */ "G_FPEXT\0"
  /* 4424 */ "G_SEXT\0"
  /* 4431 */ "G_ASSERT_SEXT\0"
  /* 4445 */ "G_ANYEXT\0"
  /* 4454 */ "G_ZEXT\0"
  /* 4461 */ "G_ASSERT_ZEXT\0"
  /* 4475 */ "FMUL8X16AU\0"
  /* 4486 */ "G_FDIV\0"
  /* 4493 */ "G_STRICT_FDIV\0"
  /* 4507 */ "G_SDIV\0"
  /* 4514 */ "G_UDIV\0"
  /* 4521 */ "FLUSHW\0"
  /* 4528 */ "G_FPOW\0"
  /* 4535 */ "MOVSTOSW\0"
  /* 4544 */ "MOVSTOUW\0"
  /* 4553 */ "G_VECREDUCE_FMAX\0"
  /* 4570 */ "G_VECREDUCE_SMAX\0"
  /* 4587 */ "G_SMAX\0"
  /* 4594 */ "G_VECREDUCE_UMAX\0"
  /* 4611 */ "G_UMAX\0"
  /* 4618 */ "G_ATOMICRMW_UMAX\0"
  /* 4635 */ "G_ATOMICRMW_MAX\0"
  /* 4651 */ "GETPCX\0"
  /* 4658 */ "G_FRAME_INDEX\0"
  /* 4672 */ "G_SBFX\0"
  /* 4679 */ "G_UBFX\0"
  /* 4686 */ "FPACKFIX\0"
  /* 4695 */ "G_SMULFIX\0"
  /* 4705 */ "G_UMULFIX\0"
  /* 4715 */ "G_SDIVFIX\0"
  /* 4725 */ "G_UDIVFIX\0"
  /* 4735 */ "XMULX\0"
  /* 4741 */ "FDTOX\0"
  /* 4747 */ "MOVDTOX\0"
  /* 4755 */ "FQTOX\0"
  /* 4761 */ "FSTOX\0"
  /* 4767 */ "G_MEMCPY\0"
  /* 4776 */ "COPY\0"
  /* 4781 */ "G_CTLZ\0"
  /* 4788 */ "G_CTTZ\0"
  /* 4795 */ "PREFETCHi\0"
  /* 4805 */ "SETHIi\0"
  /* 4812 */ "MEMBARi\0"
  /* 4820 */ "SETHIXi\0"
  /* 4828 */ "SRAri\0"
  /* 4834 */ "LDSBri\0"
  /* 4841 */ "STBri\0"
  /* 4847 */ "LDUBri\0"
  /* 4854 */ "SUBri\0"
  /* 4860 */ "LDSTUBri\0"
  /* 4869 */ "SMACri\0"
  /* 4876 */ "UMACri\0"
  /* 4883 */ "SUBCri\0"
  /* 4890 */ "TSUBCCri\0"
  /* 4899 */ "TADDCCri\0"
  /* 4908 */ "ANDCCri\0"
  /* 4916 */ "V9MOVFCCri\0"
  /* 4927 */ "TICCri\0"
  /* 4934 */ "MOVICCri\0"
  /* 4943 */ "SMULCCri\0"
  /* 4952 */ "UMULCCri\0"
  /* 4961 */ "ANDNCCri\0"
  /* 4970 */ "ORNCCri\0"
  /* 4978 */ "XNORCCri\0"
  /* 4987 */ "XORCCri\0"
  /* 4995 */ "MULSCCri\0"
  /* 5004 */ "SDIVCCri\0"
  /* 5013 */ "UDIVCCri\0"
  /* 5022 */ "TXCCri\0"
  /* 5029 */ "MOVXCCri\0"
  /* 5038 */ "ADDCri\0"
  /* 5045 */ "LDDCri\0"
  /* 5052 */ "LDCri\0"
  /* 5058 */ "STDCri\0"
  /* 5065 */ "STCri\0"
  /* 5071 */ "LEA_ADDri\0"
  /* 5081 */ "LEAX_ADDri\0"
  /* 5092 */ "LDDri\0"
  /* 5098 */ "LDri\0"
  /* 5103 */ "ANDri\0"
  /* 5109 */ "BINDri\0"
  /* 5116 */ "STDri\0"
  /* 5122 */ "SUBEri\0"
  /* 5129 */ "ADDEri\0"
  /* 5136 */ "RESTOREri\0"
  /* 5146 */ "SAVEri\0"
  /* 5153 */ "LDDFri\0"
  /* 5160 */ "LDFri\0"
  /* 5166 */ "STDFri\0"
  /* 5173 */ "LDQFri\0"
  /* 5180 */ "STQFri\0"
  /* 5187 */ "STFri\0"
  /* 5193 */ "LDSHri\0"
  /* 5200 */ "FLUSHri\0"
  /* 5208 */ "STHri\0"
  /* 5214 */ "LDUHri\0"
  /* 5221 */ "CALLri\0"
  /* 5228 */ "SLLri\0"
  /* 5234 */ "JMPLri\0"
  /* 5241 */ "SRLri\0"
  /* 5247 */ "SMULri\0"
  /* 5254 */ "UMULri\0"
  /* 5261 */ "WRWIMri\0"
  /* 5269 */ "ANDNri\0"
  /* 5276 */ "ORNri\0"
  /* 5282 */ "TRAPri\0"
  /* 5289 */ "SWAPri\0"
  /* 5296 */ "CMPri\0"
  /* 5302 */ "STDCQri\0"
  /* 5310 */ "STDFQri\0"
  /* 5318 */ "WRTBRri\0"
  /* 5326 */ "XNORri\0"
  /* 5333 */ "XORri\0"
  /* 5339 */ "WRPRri\0"
  /* 5346 */ "WRASRri\0"
  /* 5354 */ "LDCSRri\0"
  /* 5362 */ "STCSRri\0"
  /* 5370 */ "LDFSRri\0"
  /* 5378 */ "STFSRri\0"
  /* 5386 */ "LDXFSRri\0"
  /* 5395 */ "STXFSRri\0"
  /* 5404 */ "PWRPSRri\0"
  /* 5413 */ "STri\0"
  /* 5418 */ "RETTri\0"
  /* 5425 */ "SDIVri\0"
  /* 5432 */ "UDIVri\0"
  /* 5439 */ "TSUBCCTVri\0"
  /* 5450 */ "TADDCCTVri\0"
  /* 5461 */ "LDSWri\0"
  /* 5468 */ "SRAXri\0"
  /* 5475 */ "SUBXri\0"
  /* 5482 */ "ADDXri\0"
  /* 5489 */ "LDXri\0"
  /* 5495 */ "ANDXri\0"
  /* 5502 */ "SLLXri\0"
  /* 5509 */ "SRLXri\0"
  /* 5516 */ "MULXri\0"
  /* 5523 */ "XORXri\0"
  /* 5530 */ "STXri\0"
  /* 5536 */ "SDIVXri\0"
  /* 5544 */ "UDIVXri\0"
  /* 5552 */ "MOVRGEZri\0"
  /* 5562 */ "MOVRLEZri\0"
  /* 5572 */ "MOVRGZri\0"
  /* 5581 */ "MOVRLZri\0"
  /* 5590 */ "MOVRNZri\0"
  /* 5599 */ "MOVRRZri\0"
  /* 5608 */ "BPGEZapn\0"
  /* 5617 */ "BPLEZapn\0"
  /* 5626 */ "BPGZapn\0"
  /* 5634 */ "BPLZapn\0"
  /* 5642 */ "BPNZapn\0"
  /* 5650 */ "BPZapn\0"
  /* 5657 */ "BPGEZnapn\0"
  /* 5667 */ "BPLEZnapn\0"
  /* 5677 */ "BPGZnapn\0"
  /* 5686 */ "BPLZnapn\0"
  /* 5695 */ "BPNZnapn\0"
  /* 5704 */ "BPZnapn\0"
  /* 5712 */ "PREFETCHr\0"
  /* 5722 */ "LDSBArr\0"
  /* 5730 */ "STBArr\0"
  /* 5737 */ "LDUBArr\0"
  /* 5745 */ "LDSTUBArr\0"
  /* 5755 */ "LDDArr\0"
  /* 5762 */ "LDArr\0"
  /* 5768 */ "STDArr\0"
  /* 5775 */ "LDDFArr\0"
  /* 5783 */ "LDFArr\0"
  /* 5790 */ "STDFArr\0"
  /* 5798 */ "LDQFArr\0"
  /* 5806 */ "STQFArr\0"
  /* 5814 */ "STFArr\0"
  /* 5821 */ "LDSHArr\0"
  /* 5829 */ "STHArr\0"
  /* 5836 */ "LDUHArr\0"
  /* 5844 */ "SWAPArr\0"
  /* 5852 */ "SRArr\0"
  /* 5858 */ "CASArr\0"
  /* 5865 */ "STArr\0"
  /* 5871 */ "LDSBrr\0"
  /* 5878 */ "STBrr\0"
  /* 5884 */ "LDUBrr\0"
  /* 5891 */ "SUBrr\0"
  /* 5897 */ "LDSTUBrr\0"
  /* 5906 */ "SMACrr\0"
  /* 5913 */ "UMACrr\0"
  /* 5920 */ "SUBCrr\0"
  /* 5927 */ "TSUBCCrr\0"
  /* 5936 */ "TADDCCrr\0"
  /* 5945 */ "ANDCCrr\0"
  /* 5953 */ "V9MOVFCCrr\0"
  /* 5964 */ "TICCrr\0"
  /* 5971 */ "MOVICCrr\0"
  /* 5980 */ "SMULCCrr\0"
  /* 5989 */ "UMULCCrr\0"
  /* 5998 */ "ANDNCCrr\0"
  /* 6007 */ "ORNCCrr\0"
  /* 6015 */ "XNORCCrr\0"
  /* 6024 */ "XORCCrr\0"
  /* 6032 */ "MULSCCrr\0"
  /* 6041 */ "SDIVCCrr\0"
  /* 6050 */ "UDIVCCrr\0"
  /* 6059 */ "TXCCrr\0"
  /* 6066 */ "MOVXCCrr\0"
  /* 6075 */ "ADDCrr\0"
  /* 6082 */ "LDDCrr\0"
  /* 6089 */ "LDCrr\0"
  /* 6095 */ "STDCrr\0"
  /* 6102 */ "POPCrr\0"
  /* 6109 */ "STCrr\0"
  /* 6115 */ "TLS_ADDrr\0"
  /* 6125 */ "LDDrr\0"
  /* 6131 */ "TLS_LDrr\0"
  /* 6140 */ "ANDrr\0"
  /* 6146 */ "BINDrr\0"
  /* 6153 */ "STDrr\0"
  /* 6159 */ "SUBErr\0"
  /* 6166 */ "ADDErr\0"
  /* 6173 */ "RESTORErr\0"
  /* 6183 */ "SAVErr\0"
  /* 6190 */ "LDDFrr\0"
  /* 6197 */ "LDFrr\0"
  /* 6203 */ "STDFrr\0"
  /* 6210 */ "LDQFrr\0"
  /* 6217 */ "STQFrr\0"
  /* 6224 */ "STFrr\0"
  /* 6230 */ "LDSHrr\0"
  /* 6237 */ "FLUSHrr\0"
  /* 6245 */ "STHrr\0"
  /* 6251 */ "LDUHrr\0"
  /* 6258 */ "CALLrr\0"
  /* 6265 */ "SLLrr\0"
  /* 6271 */ "JMPLrr\0"
  /* 6278 */ "SRLrr\0"
  /* 6284 */ "SMULrr\0"
  /* 6291 */ "UMULrr\0"
  /* 6298 */ "WRWIMrr\0"
  /* 6306 */ "ANDNrr\0"
  /* 6313 */ "ORNrr\0"
  /* 6319 */ "ANDXNrr\0"
  /* 6327 */ "ORXNrr\0"
  /* 6334 */ "TRAPrr\0"
  /* 6341 */ "SWAPrr\0"
  /* 6348 */ "CMPrr\0"
  /* 6354 */ "STDCQrr\0"
  /* 6362 */ "STDFQrr\0"
  /* 6370 */ "WRTBRrr\0"
  /* 6378 */ "XNORrr\0"
  /* 6385 */ "XORrr\0"
  /* 6391 */ "WRPRrr\0"
  /* 6398 */ "WRASRrr\0"
  /* 6406 */ "LDCSRrr\0"
  /* 6414 */ "STCSRrr\0"
  /* 6422 */ "LDFSRrr\0"
  /* 6430 */ "STFSRrr\0"
  /* 6438 */ "LDXFSRrr\0"
  /* 6447 */ "STXFSRrr\0"
  /* 6456 */ "PWRPSRrr\0"
  /* 6465 */ "CASrr\0"
  /* 6471 */ "STrr\0"
  /* 6476 */ "RETTrr\0"
  /* 6483 */ "SDIVrr\0"
  /* 6490 */ "UDIVrr\0"
  /* 6497 */ "TSUBCCTVrr\0"
  /* 6508 */ "TADDCCTVrr\0"
  /* 6519 */ "LDSWrr\0"
  /* 6526 */ "SRAXrr\0"
  /* 6533 */ "SUBXrr\0"
  /* 6540 */ "TLS_ADDXrr\0"
  /* 6551 */ "TLS_LDXrr\0"
  /* 6561 */ "ANDXrr\0"
  /* 6568 */ "SLLXrr\0"
  /* 6575 */ "SRLXrr\0"
  /* 6582 */ "MULXrr\0"
  /* 6589 */ "XNORXrr\0"
  /* 6597 */ "XORXrr\0"
  /* 6604 */ "CASXrr\0"
  /* 6611 */ "STXrr\0"
  /* 6617 */ "SDIVXrr\0"
  /* 6625 */ "UDIVXrr\0"
  /* 6633 */ "MOVRGEZrr\0"
  /* 6643 */ "MOVRLEZrr\0"
  /* 6653 */ "MOVRGZrr\0"
  /* 6662 */ "MOVRLZrr\0"
  /* 6671 */ "MOVRNZrr\0"
  /* 6680 */ "MOVRRZrr\0"
  /* 6689 */ "BPGEZapt\0"
  /* 6698 */ "BPLEZapt\0"
  /* 6707 */ "BPGZapt\0"
  /* 6715 */ "BPLZapt\0"
  /* 6723 */ "BPNZapt\0"
  /* 6731 */ "BPZapt\0"
  /* 6738 */ "BPGEZnapt\0"
  /* 6748 */ "BPLEZnapt\0"
  /* 6758 */ "BPGZnapt\0"
  /* 6767 */ "BPLZnapt\0"
  /* 6776 */ "BPNZnapt\0"
  /* 6785 */ "BPZnapt\0"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const unsigned SparcInstrNameIndices[] = {
    2005U, 2469U, 3122U, 2709U, 2138U, 2119U, 2147U, 2294U, 
    1857U, 1872U, 1823U, 1899U, 3766U, 1725U, 4401U, 1836U, 
    2001U, 2128U, 1558U, 4776U, 1638U, 4321U, 1292U, 1509U, 
    1546U, 2820U, 2282U, 4250U, 1412U, 2927U, 1962U, 4239U, 
    1675U, 2900U, 2887U, 3158U, 4064U, 4087U, 2205U, 2261U, 
    2234U, 2164U, 4431U, 4461U, 1115U, 538U, 2397U, 4507U, 
    4514U, 2429U, 2436U, 2443U, 2453U, 1270U, 3374U, 3337U, 
    1821U, 2003U, 4658U, 1735U, 4032U, 3613U, 4336U, 3630U, 
    3284U, 872U, 3743U, 4261U, 3418U, 4368U, 1760U, 846U, 
    1347U, 4280U, 2544U, 3183U, 1003U, 947U, 977U, 988U, 
    928U, 958U, 1704U, 1688U, 3789U, 1913U, 1930U, 1131U, 
    544U, 1276U, 1229U, 3379U, 3343U, 4635U, 2660U, 4618U, 
    2643U, 1082U, 521U, 1538U, 1319U, 4051U, 824U, 3819U, 
    4445U, 864U, 4198U, 4186U, 4311U, 1954U, 4424U, 1886U, 
    4454U, 2191U, 3249U, 3235U, 2184U, 3242U, 3411U, 2315U, 
    2862U, 2855U, 4042U, 2782U, 1579U, 2766U, 1530U, 2774U, 
    1571U, 2758U, 1522U, 2798U, 2790U, 1987U, 1979U, 3950U, 
    3940U, 3930U, 3920U, 3970U, 3960U, 4695U, 4705U, 3980U, 
    3993U, 4715U, 4725U, 4006U, 4019U, 1040U, 500U, 2339U, 
    469U, 921U, 4486U, 2408U, 4528U, 2061U, 2946U, 178U, 
    1947U, 170U, 0U, 1850U, 4416U, 836U, 2043U, 2052U, 
    2837U, 2846U, 3531U, 2566U, 1769U, 2501U, 2511U, 1587U, 
    1602U, 2479U, 2490U, 1121U, 2075U, 2612U, 4587U, 2636U, 
    4611U, 3538U, 1338U, 1328U, 3117U, 4111U, 4139U, 4118U, 
    3299U, 4788U, 1803U, 4781U, 1785U, 2879U, 2829U, 1712U, 
    2197U, 3664U, 2676U, 4345U, 3275U, 4272U, 4298U, 4378U, 
    3145U, 1625U, 893U, 1068U, 507U, 2367U, 4493U, 2415U, 
    475U, 4353U, 3202U, 3218U, 4767U, 1654U, 1750U, 4078U, 
    2806U, 1047U, 2346U, 1023U, 2322U, 4553U, 2578U, 1099U, 
    2381U, 1254U, 3359U, 3321U, 4570U, 2595U, 4594U, 2619U, 
    4672U, 4679U, 2732U, 2912U, 4651U, 586U, 697U, 622U, 
    733U, 663U, 770U, 604U, 715U, 4083U, 4900U, 5937U, 
    5038U, 6075U, 5129U, 6166U, 915U, 560U, 5482U, 6544U, 
    5075U, 6119U, 3135U, 2299U, 4908U, 5945U, 4961U, 5998U, 
    5269U, 6306U, 6319U, 5495U, 6561U, 5103U, 6140U, 401U, 
    156U, 422U, 429U, 1306U, 454U, 5109U, 6146U, 2069U, 
    568U, 432U, 4159U, 4209U, 5608U, 6689U, 5657U, 6738U, 
    5626U, 6707U, 5677U, 6758U, 681U, 439U, 4168U, 4217U, 
    5617U, 6698U, 5667U, 6748U, 5634U, 6715U, 5686U, 6767U, 
    5642U, 6723U, 5695U, 6776U, 788U, 446U, 4177U, 4225U, 
    5650U, 6731U, 5704U, 6785U, 1645U, 2220U, 5221U, 6258U, 
    9U, 5858U, 6604U, 6465U, 1305U, 453U, 281U, 108U, 
    415U, 5296U, 6348U, 248U, 2093U, 2692U, 2529U, 75U, 
    2085U, 2683U, 2521U, 409U, 2101U, 2701U, 2537U, 1429U, 
    3025U, 3783U, 1147U, 2959U, 3557U, 488U, 1218U, 29U, 
    3436U, 186U, 3487U, 3585U, 1312U, 461U, 303U, 1399U, 
    320U, 130U, 337U, 147U, 255U, 82U, 264U, 91U, 
    3019U, 3712U, 1442U, 3038U, 3853U, 2980U, 2025U, 2993U, 
    3678U, 4741U, 1246U, 1153U, 3563U, 1016U, 3550U, 1365U, 
    2999U, 3684U, 1405U, 3718U, 1995U, 4521U, 5200U, 6237U, 
    312U, 1448U, 576U, 687U, 794U, 3044U, 641U, 750U, 
    804U, 1454U, 3050U, 3865U, 1474U, 3070U, 3885U, 1464U, 
    3060U, 3875U, 1483U, 3079U, 3894U, 1492U, 3088U, 3903U, 
    1501U, 3097U, 3912U, 3859U, 653U, 760U, 814U, 390U, 
    367U, 346U, 2108U, 4475U, 1190U, 378U, 355U, 2987U, 
    3651U, 1168U, 3578U, 1223U, 3591U, 1184U, 2974U, 3645U, 
    1160U, 3570U, 1196U, 3657U, 3264U, 3730U, 38U, 3446U, 
    195U, 3497U, 1210U, 1670U, 3598U, 3260U, 44U, 3453U, 
    201U, 3504U, 3725U, 273U, 100U, 4686U, 240U, 3522U, 
    67U, 3471U, 213U, 1617U, 232U, 3513U, 59U, 3462U, 
    1371U, 2031U, 3690U, 4755U, 329U, 139U, 289U, 116U, 
    1203U, 1435U, 3031U, 3846U, 225U, 52U, 23U, 3429U, 
    164U, 3480U, 296U, 123U, 1377U, 2037U, 3005U, 4761U, 
    1010U, 2953U, 3544U, 3269U, 3736U, 3316U, 3760U, 1383U, 
    3011U, 3704U, 2814U, 3671U, 5234U, 6271U, 5762U, 5354U, 
    6406U, 5052U, 6089U, 5755U, 5045U, 6082U, 5775U, 5153U, 
    6190U, 5092U, 6125U, 5783U, 5370U, 6422U, 5160U, 6197U, 
    5798U, 5173U, 6210U, 5722U, 4834U, 5871U, 5821U, 5193U, 
    6230U, 5745U, 4860U, 5897U, 5461U, 6519U, 5737U, 4847U, 
    5884U, 5836U, 5214U, 6251U, 5386U, 6438U, 5489U, 6555U, 
    5098U, 6135U, 5081U, 5071U, 4233U, 4812U, 4747U, 4918U, 
    5955U, 4934U, 5971U, 5552U, 6633U, 5572U, 6653U, 5562U, 
    6643U, 5581U, 6662U, 5590U, 6671U, 5599U, 6680U, 4535U, 
    4544U, 3696U, 5029U, 6066U, 1389U, 4995U, 6032U, 5516U, 
    6582U, 2875U, 4980U, 6017U, 4970U, 6007U, 5276U, 6313U, 
    6327U, 5524U, 6591U, 5328U, 6380U, 4395U, 2725U, 6102U, 
    4795U, 5712U, 5404U, 6456U, 3399U, 910U, 3394U, 3405U, 
    3111U, 2463U, 5136U, 6173U, 4074U, 2310U, 5418U, 6476U, 
    5146U, 6183U, 5004U, 6041U, 5536U, 6617U, 5425U, 6483U, 
    4820U, 4805U, 2749U, 2403U, 3256U, 5502U, 6568U, 5228U, 
    6265U, 4869U, 5906U, 4943U, 5980U, 5247U, 6284U, 5468U, 
    6526U, 4828U, 5852U, 5509U, 6575U, 5241U, 6278U, 5865U, 
    3105U, 5730U, 4841U, 5878U, 5362U, 6414U, 5065U, 6109U, 
    5768U, 5302U, 6354U, 5058U, 6095U, 5790U, 5310U, 6362U, 
    5166U, 6203U, 5116U, 6153U, 5814U, 5378U, 6430U, 5187U, 
    6224U, 5829U, 5208U, 6245U, 5806U, 5180U, 6217U, 5395U, 
    6447U, 5530U, 6611U, 5413U, 6471U, 4891U, 5928U, 4883U, 
    5920U, 5122U, 6159U, 5475U, 6533U, 4854U, 5891U, 5844U, 
    5289U, 6341U, 19U, 209U, 221U, 5450U, 6508U, 4899U, 
    5936U, 4927U, 5964U, 6540U, 6115U, 2225U, 6551U, 6131U, 
    5282U, 6334U, 5439U, 6497U, 4890U, 5927U, 5022U, 6059U, 
    5013U, 6050U, 5544U, 6625U, 5432U, 6490U, 4876U, 5913U, 
    4952U, 5989U, 2009U, 5254U, 6291U, 2869U, 1397U, 1175U, 
    2965U, 3604U, 3017U, 3710U, 574U, 639U, 651U, 4916U, 
    5953U, 5346U, 6398U, 5339U, 6391U, 5405U, 6457U, 5318U, 
    6370U, 5261U, 6298U, 4735U, 2017U, 4978U, 6015U, 6589U, 
    5326U, 6378U, 4987U, 6024U, 5523U, 6597U, 5333U, 6385U, 
};

#endif // GET_INSTRINFO_MC_DESC

