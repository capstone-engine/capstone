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
/* 16 */      MCD_OPC_CheckField, 25, 5, 0, 39, 31, 0, // Skip to: 7998
/* 23 */      MCD_OPC_Decode, 221, 5, 0, // Opcode: UNIMP
/* 27 */      MCD_OPC_FilterValue, 1, 127, 0, 0, // Skip to: 159
/* 32 */      MCD_OPC_ExtractField, 19, 3,  // Inst{21-19} ...
/* 35 */      MCD_OPC_FilterValue, 0, 31, 0, 0, // Skip to: 71
/* 40 */      MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 43 */      MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 57
/* 48 */      MCD_OPC_CheckPredicate, 0, 9, 31, 0, // Skip to: 7998
/* 53 */      MCD_OPC_Decode, 170, 2, 1, // Opcode: BPICCNT
/* 57 */      MCD_OPC_FilterValue, 1, 0, 31, 0, // Skip to: 7998
/* 62 */      MCD_OPC_CheckPredicate, 0, 251, 30, 0, // Skip to: 7998
/* 67 */      MCD_OPC_Decode, 169, 2, 1, // Opcode: BPICCANT
/* 71 */      MCD_OPC_FilterValue, 1, 31, 0, 0, // Skip to: 107
/* 76 */      MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 79 */      MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 93
/* 84 */      MCD_OPC_CheckPredicate, 0, 229, 30, 0, // Skip to: 7998
/* 89 */      MCD_OPC_Decode, 167, 2, 1, // Opcode: BPICC
/* 93 */      MCD_OPC_FilterValue, 1, 220, 30, 0, // Skip to: 7998
/* 98 */      MCD_OPC_CheckPredicate, 0, 215, 30, 0, // Skip to: 7998
/* 103 */     MCD_OPC_Decode, 168, 2, 1, // Opcode: BPICCA
/* 107 */     MCD_OPC_FilterValue, 4, 21, 0, 0, // Skip to: 133
/* 112 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 115 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 124
/* 120 */     MCD_OPC_Decode, 186, 2, 1, // Opcode: BPXCCNT
/* 124 */     MCD_OPC_FilterValue, 1, 189, 30, 0, // Skip to: 7998
/* 129 */     MCD_OPC_Decode, 185, 2, 1, // Opcode: BPXCCANT
/* 133 */     MCD_OPC_FilterValue, 5, 180, 30, 0, // Skip to: 7998
/* 138 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 141 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 150
/* 146 */     MCD_OPC_Decode, 183, 2, 1, // Opcode: BPXCC
/* 150 */     MCD_OPC_FilterValue, 1, 163, 30, 0, // Skip to: 7998
/* 155 */     MCD_OPC_Decode, 184, 2, 1, // Opcode: BPXCCA
/* 159 */     MCD_OPC_FilterValue, 2, 32, 0, 0, // Skip to: 196
/* 164 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 167 */     MCD_OPC_FilterValue, 0, 15, 0, 0, // Skip to: 187
/* 172 */     MCD_OPC_CheckField, 25, 4, 8, 4, 0, 0, // Skip to: 183
/* 179 */     MCD_OPC_Decode, 149, 2, 0, // Opcode: BA
/* 183 */     MCD_OPC_Decode, 150, 2, 2, // Opcode: BCOND
/* 187 */     MCD_OPC_FilterValue, 1, 126, 30, 0, // Skip to: 7998
/* 192 */     MCD_OPC_Decode, 151, 2, 2, // Opcode: BCONDA
/* 196 */     MCD_OPC_FilterValue, 3, 59, 1, 0, // Skip to: 516
/* 201 */     MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 204 */     MCD_OPC_FilterValue, 1, 21, 0, 0, // Skip to: 230
/* 209 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 212 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 221
/* 217 */     MCD_OPC_Decode, 189, 2, 3, // Opcode: BPZnapn
/* 221 */     MCD_OPC_FilterValue, 1, 92, 30, 0, // Skip to: 7998
/* 226 */     MCD_OPC_Decode, 190, 2, 3, // Opcode: BPZnapt
/* 230 */     MCD_OPC_FilterValue, 2, 21, 0, 0, // Skip to: 256
/* 235 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 238 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 247
/* 243 */     MCD_OPC_Decode, 173, 2, 3, // Opcode: BPLEZnapn
/* 247 */     MCD_OPC_FilterValue, 1, 66, 30, 0, // Skip to: 7998
/* 252 */     MCD_OPC_Decode, 174, 2, 3, // Opcode: BPLEZnapt
/* 256 */     MCD_OPC_FilterValue, 3, 21, 0, 0, // Skip to: 282
/* 261 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 264 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 273
/* 269 */     MCD_OPC_Decode, 177, 2, 3, // Opcode: BPLZnapn
/* 273 */     MCD_OPC_FilterValue, 1, 40, 30, 0, // Skip to: 7998
/* 278 */     MCD_OPC_Decode, 178, 2, 3, // Opcode: BPLZnapt
/* 282 */     MCD_OPC_FilterValue, 5, 21, 0, 0, // Skip to: 308
/* 287 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 290 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 299
/* 295 */     MCD_OPC_Decode, 181, 2, 3, // Opcode: BPNZnapn
/* 299 */     MCD_OPC_FilterValue, 1, 14, 30, 0, // Skip to: 7998
/* 304 */     MCD_OPC_Decode, 182, 2, 3, // Opcode: BPNZnapt
/* 308 */     MCD_OPC_FilterValue, 6, 21, 0, 0, // Skip to: 334
/* 313 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 316 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 325
/* 321 */     MCD_OPC_Decode, 165, 2, 3, // Opcode: BPGZnapn
/* 325 */     MCD_OPC_FilterValue, 1, 244, 29, 0, // Skip to: 7998
/* 330 */     MCD_OPC_Decode, 166, 2, 3, // Opcode: BPGZnapt
/* 334 */     MCD_OPC_FilterValue, 7, 21, 0, 0, // Skip to: 360
/* 339 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 342 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 351
/* 347 */     MCD_OPC_Decode, 161, 2, 3, // Opcode: BPGEZnapn
/* 351 */     MCD_OPC_FilterValue, 1, 218, 29, 0, // Skip to: 7998
/* 356 */     MCD_OPC_Decode, 162, 2, 3, // Opcode: BPGEZnapt
/* 360 */     MCD_OPC_FilterValue, 17, 21, 0, 0, // Skip to: 386
/* 365 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 368 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 377
/* 373 */     MCD_OPC_Decode, 187, 2, 3, // Opcode: BPZapn
/* 377 */     MCD_OPC_FilterValue, 1, 192, 29, 0, // Skip to: 7998
/* 382 */     MCD_OPC_Decode, 188, 2, 3, // Opcode: BPZapt
/* 386 */     MCD_OPC_FilterValue, 18, 21, 0, 0, // Skip to: 412
/* 391 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 394 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 403
/* 399 */     MCD_OPC_Decode, 171, 2, 3, // Opcode: BPLEZapn
/* 403 */     MCD_OPC_FilterValue, 1, 166, 29, 0, // Skip to: 7998
/* 408 */     MCD_OPC_Decode, 172, 2, 3, // Opcode: BPLEZapt
/* 412 */     MCD_OPC_FilterValue, 19, 21, 0, 0, // Skip to: 438
/* 417 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 420 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 429
/* 425 */     MCD_OPC_Decode, 175, 2, 3, // Opcode: BPLZapn
/* 429 */     MCD_OPC_FilterValue, 1, 140, 29, 0, // Skip to: 7998
/* 434 */     MCD_OPC_Decode, 176, 2, 3, // Opcode: BPLZapt
/* 438 */     MCD_OPC_FilterValue, 21, 21, 0, 0, // Skip to: 464
/* 443 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 446 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 455
/* 451 */     MCD_OPC_Decode, 179, 2, 3, // Opcode: BPNZapn
/* 455 */     MCD_OPC_FilterValue, 1, 114, 29, 0, // Skip to: 7998
/* 460 */     MCD_OPC_Decode, 180, 2, 3, // Opcode: BPNZapt
/* 464 */     MCD_OPC_FilterValue, 22, 21, 0, 0, // Skip to: 490
/* 469 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 472 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 481
/* 477 */     MCD_OPC_Decode, 163, 2, 3, // Opcode: BPGZapn
/* 481 */     MCD_OPC_FilterValue, 1, 88, 29, 0, // Skip to: 7998
/* 486 */     MCD_OPC_Decode, 164, 2, 3, // Opcode: BPGZapt
/* 490 */     MCD_OPC_FilterValue, 23, 79, 29, 0, // Skip to: 7998
/* 495 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 498 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 507
/* 503 */     MCD_OPC_Decode, 159, 2, 3, // Opcode: BPGEZapn
/* 507 */     MCD_OPC_FilterValue, 1, 62, 29, 0, // Skip to: 7998
/* 512 */     MCD_OPC_Decode, 160, 2, 3, // Opcode: BPGEZapt
/* 516 */     MCD_OPC_FilterValue, 4, 22, 0, 0, // Skip to: 543
/* 521 */     MCD_OPC_CheckField, 25, 5, 0, 11, 0, 0, // Skip to: 539
/* 528 */     MCD_OPC_CheckField, 0, 22, 0, 4, 0, 0, // Skip to: 539
/* 535 */     MCD_OPC_Decode, 204, 4, 4, // Opcode: NOP
/* 539 */     MCD_OPC_Decode, 241, 4, 5, // Opcode: SETHIi
/* 543 */     MCD_OPC_FilterValue, 5, 75, 0, 0, // Skip to: 623
/* 548 */     MCD_OPC_ExtractField, 19, 1,  // Inst{19} ...
/* 551 */     MCD_OPC_FilterValue, 0, 31, 0, 0, // Skip to: 587
/* 556 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 559 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 573
/* 564 */     MCD_OPC_CheckPredicate, 0, 5, 29, 0, // Skip to: 7998
/* 569 */     MCD_OPC_Decode, 158, 2, 6, // Opcode: BPFCCNT
/* 573 */     MCD_OPC_FilterValue, 1, 252, 28, 0, // Skip to: 7998
/* 578 */     MCD_OPC_CheckPredicate, 0, 247, 28, 0, // Skip to: 7998
/* 583 */     MCD_OPC_Decode, 157, 2, 6, // Opcode: BPFCCANT
/* 587 */     MCD_OPC_FilterValue, 1, 238, 28, 0, // Skip to: 7998
/* 592 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 595 */     MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 609
/* 600 */     MCD_OPC_CheckPredicate, 0, 225, 28, 0, // Skip to: 7998
/* 605 */     MCD_OPC_Decode, 155, 2, 6, // Opcode: BPFCC
/* 609 */     MCD_OPC_FilterValue, 1, 216, 28, 0, // Skip to: 7998
/* 614 */     MCD_OPC_CheckPredicate, 0, 211, 28, 0, // Skip to: 7998
/* 619 */     MCD_OPC_Decode, 156, 2, 6, // Opcode: BPFCCA
/* 623 */     MCD_OPC_FilterValue, 6, 21, 0, 0, // Skip to: 649
/* 628 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 631 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 640
/* 636 */     MCD_OPC_Decode, 231, 2, 2, // Opcode: FBCOND
/* 640 */     MCD_OPC_FilterValue, 1, 185, 28, 0, // Skip to: 7998
/* 645 */     MCD_OPC_Decode, 232, 2, 2, // Opcode: FBCONDA
/* 649 */     MCD_OPC_FilterValue, 7, 176, 28, 0, // Skip to: 7998
/* 654 */     MCD_OPC_ExtractField, 29, 1,  // Inst{29} ...
/* 657 */     MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 666
/* 662 */     MCD_OPC_Decode, 199, 2, 2, // Opcode: CBCOND
/* 666 */     MCD_OPC_FilterValue, 1, 159, 28, 0, // Skip to: 7998
/* 671 */     MCD_OPC_Decode, 200, 2, 2, // Opcode: CBCONDA
/* 675 */     MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 684
/* 680 */     MCD_OPC_Decode, 192, 2, 7, // Opcode: CALL
/* 684 */     MCD_OPC_FilterValue, 2, 173, 22, 0, // Skip to: 6494
/* 689 */     MCD_OPC_ExtractField, 19, 6,  // Inst{24-19} ...
/* 692 */     MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 725
/* 697 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 700 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 716
/* 705 */     MCD_OPC_CheckField, 5, 8, 0, 118, 28, 0, // Skip to: 7998
/* 712 */     MCD_OPC_Decode, 132, 2, 8, // Opcode: ADDrr
/* 716 */     MCD_OPC_FilterValue, 1, 109, 28, 0, // Skip to: 7998
/* 721 */     MCD_OPC_Decode, 131, 2, 9, // Opcode: ADDri
/* 725 */     MCD_OPC_FilterValue, 1, 28, 0, 0, // Skip to: 758
/* 730 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 733 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 749
/* 738 */     MCD_OPC_CheckField, 5, 8, 0, 85, 28, 0, // Skip to: 7998
/* 745 */     MCD_OPC_Decode, 145, 2, 8, // Opcode: ANDrr
/* 749 */     MCD_OPC_FilterValue, 1, 76, 28, 0, // Skip to: 7998
/* 754 */     MCD_OPC_Decode, 144, 2, 9, // Opcode: ANDri
/* 758 */     MCD_OPC_FilterValue, 2, 28, 0, 0, // Skip to: 791
/* 763 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 766 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 782
/* 771 */     MCD_OPC_CheckField, 5, 8, 0, 52, 28, 0, // Skip to: 7998
/* 778 */     MCD_OPC_Decode, 215, 4, 8, // Opcode: ORrr
/* 782 */     MCD_OPC_FilterValue, 1, 43, 28, 0, // Skip to: 7998
/* 787 */     MCD_OPC_Decode, 214, 4, 9, // Opcode: ORri
/* 791 */     MCD_OPC_FilterValue, 3, 28, 0, 0, // Skip to: 824
/* 796 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 799 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 815
/* 804 */     MCD_OPC_CheckField, 5, 8, 0, 19, 28, 0, // Skip to: 7998
/* 811 */     MCD_OPC_Decode, 255, 5, 8, // Opcode: XORrr
/* 815 */     MCD_OPC_FilterValue, 1, 10, 28, 0, // Skip to: 7998
/* 820 */     MCD_OPC_Decode, 254, 5, 9, // Opcode: XORri
/* 824 */     MCD_OPC_FilterValue, 4, 28, 0, 0, // Skip to: 857
/* 829 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 832 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 848
/* 837 */     MCD_OPC_CheckField, 5, 8, 0, 242, 27, 0, // Skip to: 7998
/* 844 */     MCD_OPC_Decode, 182, 5, 8, // Opcode: SUBrr
/* 848 */     MCD_OPC_FilterValue, 1, 233, 27, 0, // Skip to: 7998
/* 853 */     MCD_OPC_Decode, 181, 5, 9, // Opcode: SUBri
/* 857 */     MCD_OPC_FilterValue, 5, 28, 0, 0, // Skip to: 890
/* 862 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 865 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 881
/* 870 */     MCD_OPC_CheckField, 5, 8, 0, 209, 27, 0, // Skip to: 7998
/* 877 */     MCD_OPC_Decode, 140, 2, 8, // Opcode: ANDNrr
/* 881 */     MCD_OPC_FilterValue, 1, 200, 27, 0, // Skip to: 7998
/* 886 */     MCD_OPC_Decode, 139, 2, 9, // Opcode: ANDNri
/* 890 */     MCD_OPC_FilterValue, 6, 28, 0, 0, // Skip to: 923
/* 895 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 898 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 914
/* 903 */     MCD_OPC_CheckField, 5, 8, 0, 176, 27, 0, // Skip to: 7998
/* 910 */     MCD_OPC_Decode, 210, 4, 8, // Opcode: ORNrr
/* 914 */     MCD_OPC_FilterValue, 1, 167, 27, 0, // Skip to: 7998
/* 919 */     MCD_OPC_Decode, 209, 4, 9, // Opcode: ORNri
/* 923 */     MCD_OPC_FilterValue, 7, 28, 0, 0, // Skip to: 956
/* 928 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 931 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 947
/* 936 */     MCD_OPC_CheckField, 5, 8, 0, 143, 27, 0, // Skip to: 7998
/* 943 */     MCD_OPC_Decode, 249, 5, 8, // Opcode: XNORrr
/* 947 */     MCD_OPC_FilterValue, 1, 134, 27, 0, // Skip to: 7998
/* 952 */     MCD_OPC_Decode, 248, 5, 9, // Opcode: XNORri
/* 956 */     MCD_OPC_FilterValue, 8, 28, 0, 0, // Skip to: 989
/* 961 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 964 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 980
/* 969 */     MCD_OPC_CheckField, 5, 8, 0, 110, 27, 0, // Skip to: 7998
/* 976 */     MCD_OPC_Decode, 252, 1, 8, // Opcode: ADDCrr
/* 980 */     MCD_OPC_FilterValue, 1, 101, 27, 0, // Skip to: 7998
/* 985 */     MCD_OPC_Decode, 251, 1, 9, // Opcode: ADDCri
/* 989 */     MCD_OPC_FilterValue, 9, 28, 0, 0, // Skip to: 1022
/* 994 */     MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 997 */     MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1013
/* 1002 */    MCD_OPC_CheckField, 5, 8, 0, 77, 27, 0, // Skip to: 7998
/* 1009 */    MCD_OPC_Decode, 203, 4, 10, // Opcode: MULXrr
/* 1013 */    MCD_OPC_FilterValue, 1, 68, 27, 0, // Skip to: 7998
/* 1018 */    MCD_OPC_Decode, 202, 4, 11, // Opcode: MULXri
/* 1022 */    MCD_OPC_FilterValue, 10, 28, 0, 0, // Skip to: 1055
/* 1027 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1030 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1046
/* 1035 */    MCD_OPC_CheckField, 5, 8, 0, 44, 27, 0, // Skip to: 7998
/* 1042 */    MCD_OPC_Decode, 220, 5, 8, // Opcode: UMULrr
/* 1046 */    MCD_OPC_FilterValue, 1, 35, 27, 0, // Skip to: 7998
/* 1051 */    MCD_OPC_Decode, 219, 5, 9, // Opcode: UMULri
/* 1055 */    MCD_OPC_FilterValue, 11, 28, 0, 0, // Skip to: 1088
/* 1060 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1063 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1079
/* 1068 */    MCD_OPC_CheckField, 5, 8, 0, 11, 27, 0, // Skip to: 7998
/* 1075 */    MCD_OPC_Decode, 254, 4, 8, // Opcode: SMULrr
/* 1079 */    MCD_OPC_FilterValue, 1, 2, 27, 0, // Skip to: 7998
/* 1084 */    MCD_OPC_Decode, 253, 4, 9, // Opcode: SMULri
/* 1088 */    MCD_OPC_FilterValue, 12, 28, 0, 0, // Skip to: 1121
/* 1093 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1096 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1112
/* 1101 */    MCD_OPC_CheckField, 5, 8, 0, 234, 26, 0, // Skip to: 7998
/* 1108 */    MCD_OPC_Decode, 176, 5, 8, // Opcode: SUBCrr
/* 1112 */    MCD_OPC_FilterValue, 1, 225, 26, 0, // Skip to: 7998
/* 1117 */    MCD_OPC_Decode, 175, 5, 9, // Opcode: SUBCri
/* 1121 */    MCD_OPC_FilterValue, 13, 28, 0, 0, // Skip to: 1154
/* 1126 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1129 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1145
/* 1134 */    MCD_OPC_CheckField, 5, 8, 0, 201, 26, 0, // Skip to: 7998
/* 1141 */    MCD_OPC_Decode, 211, 5, 10, // Opcode: UDIVXrr
/* 1145 */    MCD_OPC_FilterValue, 1, 192, 26, 0, // Skip to: 7998
/* 1150 */    MCD_OPC_Decode, 210, 5, 11, // Opcode: UDIVXri
/* 1154 */    MCD_OPC_FilterValue, 14, 28, 0, 0, // Skip to: 1187
/* 1159 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1162 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1178
/* 1167 */    MCD_OPC_CheckField, 5, 8, 0, 168, 26, 0, // Skip to: 7998
/* 1174 */    MCD_OPC_Decode, 213, 5, 8, // Opcode: UDIVrr
/* 1178 */    MCD_OPC_FilterValue, 1, 159, 26, 0, // Skip to: 7998
/* 1183 */    MCD_OPC_Decode, 212, 5, 9, // Opcode: UDIVri
/* 1187 */    MCD_OPC_FilterValue, 15, 28, 0, 0, // Skip to: 1220
/* 1192 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1195 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1211
/* 1200 */    MCD_OPC_CheckField, 5, 8, 0, 135, 26, 0, // Skip to: 7998
/* 1207 */    MCD_OPC_Decode, 239, 4, 8, // Opcode: SDIVrr
/* 1211 */    MCD_OPC_FilterValue, 1, 126, 26, 0, // Skip to: 7998
/* 1216 */    MCD_OPC_Decode, 238, 4, 9, // Opcode: SDIVri
/* 1220 */    MCD_OPC_FilterValue, 16, 28, 0, 0, // Skip to: 1253
/* 1225 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1228 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1244
/* 1233 */    MCD_OPC_CheckField, 5, 8, 0, 102, 26, 0, // Skip to: 7998
/* 1240 */    MCD_OPC_Decode, 250, 1, 8, // Opcode: ADDCCrr
/* 1244 */    MCD_OPC_FilterValue, 1, 93, 26, 0, // Skip to: 7998
/* 1249 */    MCD_OPC_Decode, 249, 1, 9, // Opcode: ADDCCri
/* 1253 */    MCD_OPC_FilterValue, 17, 28, 0, 0, // Skip to: 1286
/* 1258 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1261 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1277
/* 1266 */    MCD_OPC_CheckField, 5, 8, 0, 69, 26, 0, // Skip to: 7998
/* 1273 */    MCD_OPC_Decode, 136, 2, 8, // Opcode: ANDCCrr
/* 1277 */    MCD_OPC_FilterValue, 1, 60, 26, 0, // Skip to: 7998
/* 1282 */    MCD_OPC_Decode, 135, 2, 9, // Opcode: ANDCCri
/* 1286 */    MCD_OPC_FilterValue, 18, 28, 0, 0, // Skip to: 1319
/* 1291 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1294 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1310
/* 1299 */    MCD_OPC_CheckField, 5, 8, 0, 36, 26, 0, // Skip to: 7998
/* 1306 */    MCD_OPC_Decode, 206, 4, 8, // Opcode: ORCCrr
/* 1310 */    MCD_OPC_FilterValue, 1, 27, 26, 0, // Skip to: 7998
/* 1315 */    MCD_OPC_Decode, 205, 4, 9, // Opcode: ORCCri
/* 1319 */    MCD_OPC_FilterValue, 19, 28, 0, 0, // Skip to: 1352
/* 1324 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1327 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1343
/* 1332 */    MCD_OPC_CheckField, 5, 8, 0, 3, 26, 0, // Skip to: 7998
/* 1339 */    MCD_OPC_Decode, 251, 5, 8, // Opcode: XORCCrr
/* 1343 */    MCD_OPC_FilterValue, 1, 250, 25, 0, // Skip to: 7998
/* 1348 */    MCD_OPC_Decode, 250, 5, 9, // Opcode: XORCCri
/* 1352 */    MCD_OPC_FilterValue, 20, 51, 0, 0, // Skip to: 1408
/* 1357 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1360 */    MCD_OPC_FilterValue, 0, 23, 0, 0, // Skip to: 1388
/* 1365 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 1368 */    MCD_OPC_FilterValue, 0, 225, 25, 0, // Skip to: 7998
/* 1373 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 1384
/* 1380 */    MCD_OPC_Decode, 205, 2, 12, // Opcode: CMPrr
/* 1384 */    MCD_OPC_Decode, 174, 5, 8, // Opcode: SUBCCrr
/* 1388 */    MCD_OPC_FilterValue, 1, 205, 25, 0, // Skip to: 7998
/* 1393 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 1404
/* 1400 */    MCD_OPC_Decode, 204, 2, 13, // Opcode: CMPri
/* 1404 */    MCD_OPC_Decode, 173, 5, 9, // Opcode: SUBCCri
/* 1408 */    MCD_OPC_FilterValue, 21, 28, 0, 0, // Skip to: 1441
/* 1413 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1416 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1432
/* 1421 */    MCD_OPC_CheckField, 5, 8, 0, 170, 25, 0, // Skip to: 7998
/* 1428 */    MCD_OPC_Decode, 138, 2, 8, // Opcode: ANDNCCrr
/* 1432 */    MCD_OPC_FilterValue, 1, 161, 25, 0, // Skip to: 7998
/* 1437 */    MCD_OPC_Decode, 137, 2, 9, // Opcode: ANDNCCri
/* 1441 */    MCD_OPC_FilterValue, 22, 28, 0, 0, // Skip to: 1474
/* 1446 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1449 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1465
/* 1454 */    MCD_OPC_CheckField, 5, 8, 0, 137, 25, 0, // Skip to: 7998
/* 1461 */    MCD_OPC_Decode, 208, 4, 8, // Opcode: ORNCCrr
/* 1465 */    MCD_OPC_FilterValue, 1, 128, 25, 0, // Skip to: 7998
/* 1470 */    MCD_OPC_Decode, 207, 4, 9, // Opcode: ORNCCri
/* 1474 */    MCD_OPC_FilterValue, 23, 28, 0, 0, // Skip to: 1507
/* 1479 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1482 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1498
/* 1487 */    MCD_OPC_CheckField, 5, 8, 0, 104, 25, 0, // Skip to: 7998
/* 1494 */    MCD_OPC_Decode, 246, 5, 8, // Opcode: XNORCCrr
/* 1498 */    MCD_OPC_FilterValue, 1, 95, 25, 0, // Skip to: 7998
/* 1503 */    MCD_OPC_Decode, 245, 5, 9, // Opcode: XNORCCri
/* 1507 */    MCD_OPC_FilterValue, 24, 28, 0, 0, // Skip to: 1540
/* 1512 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1515 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1531
/* 1520 */    MCD_OPC_CheckField, 5, 8, 0, 71, 25, 0, // Skip to: 7998
/* 1527 */    MCD_OPC_Decode, 254, 1, 8, // Opcode: ADDErr
/* 1531 */    MCD_OPC_FilterValue, 1, 62, 25, 0, // Skip to: 7998
/* 1536 */    MCD_OPC_Decode, 253, 1, 9, // Opcode: ADDEri
/* 1540 */    MCD_OPC_FilterValue, 26, 28, 0, 0, // Skip to: 1573
/* 1545 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1548 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1564
/* 1553 */    MCD_OPC_CheckField, 5, 8, 0, 38, 25, 0, // Skip to: 7998
/* 1560 */    MCD_OPC_Decode, 217, 5, 8, // Opcode: UMULCCrr
/* 1564 */    MCD_OPC_FilterValue, 1, 29, 25, 0, // Skip to: 7998
/* 1569 */    MCD_OPC_Decode, 216, 5, 9, // Opcode: UMULCCri
/* 1573 */    MCD_OPC_FilterValue, 27, 28, 0, 0, // Skip to: 1606
/* 1578 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1581 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1597
/* 1586 */    MCD_OPC_CheckField, 5, 8, 0, 5, 25, 0, // Skip to: 7998
/* 1593 */    MCD_OPC_Decode, 252, 4, 8, // Opcode: SMULCCrr
/* 1597 */    MCD_OPC_FilterValue, 1, 252, 24, 0, // Skip to: 7998
/* 1602 */    MCD_OPC_Decode, 251, 4, 9, // Opcode: SMULCCri
/* 1606 */    MCD_OPC_FilterValue, 28, 28, 0, 0, // Skip to: 1639
/* 1611 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1614 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1630
/* 1619 */    MCD_OPC_CheckField, 5, 8, 0, 228, 24, 0, // Skip to: 7998
/* 1626 */    MCD_OPC_Decode, 178, 5, 8, // Opcode: SUBErr
/* 1630 */    MCD_OPC_FilterValue, 1, 219, 24, 0, // Skip to: 7998
/* 1635 */    MCD_OPC_Decode, 177, 5, 9, // Opcode: SUBEri
/* 1639 */    MCD_OPC_FilterValue, 30, 28, 0, 0, // Skip to: 1672
/* 1644 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1647 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1663
/* 1652 */    MCD_OPC_CheckField, 5, 8, 0, 195, 24, 0, // Skip to: 7998
/* 1659 */    MCD_OPC_Decode, 209, 5, 8, // Opcode: UDIVCCrr
/* 1663 */    MCD_OPC_FilterValue, 1, 186, 24, 0, // Skip to: 7998
/* 1668 */    MCD_OPC_Decode, 208, 5, 9, // Opcode: UDIVCCri
/* 1672 */    MCD_OPC_FilterValue, 31, 28, 0, 0, // Skip to: 1705
/* 1677 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1680 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1696
/* 1685 */    MCD_OPC_CheckField, 5, 8, 0, 162, 24, 0, // Skip to: 7998
/* 1692 */    MCD_OPC_Decode, 235, 4, 8, // Opcode: SDIVCCrr
/* 1696 */    MCD_OPC_FilterValue, 1, 153, 24, 0, // Skip to: 7998
/* 1701 */    MCD_OPC_Decode, 234, 4, 9, // Opcode: SDIVCCri
/* 1705 */    MCD_OPC_FilterValue, 32, 28, 0, 0, // Skip to: 1738
/* 1710 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1713 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1729
/* 1718 */    MCD_OPC_CheckField, 5, 8, 0, 129, 24, 0, // Skip to: 7998
/* 1725 */    MCD_OPC_Decode, 192, 5, 8, // Opcode: TADDCCrr
/* 1729 */    MCD_OPC_FilterValue, 1, 120, 24, 0, // Skip to: 7998
/* 1734 */    MCD_OPC_Decode, 191, 5, 9, // Opcode: TADDCCri
/* 1738 */    MCD_OPC_FilterValue, 33, 28, 0, 0, // Skip to: 1771
/* 1743 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1746 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1762
/* 1751 */    MCD_OPC_CheckField, 5, 8, 0, 96, 24, 0, // Skip to: 7998
/* 1758 */    MCD_OPC_Decode, 205, 5, 8, // Opcode: TSUBCCrr
/* 1762 */    MCD_OPC_FilterValue, 1, 87, 24, 0, // Skip to: 7998
/* 1767 */    MCD_OPC_Decode, 204, 5, 9, // Opcode: TSUBCCri
/* 1771 */    MCD_OPC_FilterValue, 34, 28, 0, 0, // Skip to: 1804
/* 1776 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1779 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1795
/* 1784 */    MCD_OPC_CheckField, 5, 8, 0, 63, 24, 0, // Skip to: 7998
/* 1791 */    MCD_OPC_Decode, 190, 5, 8, // Opcode: TADDCCTVrr
/* 1795 */    MCD_OPC_FilterValue, 1, 54, 24, 0, // Skip to: 7998
/* 1800 */    MCD_OPC_Decode, 189, 5, 9, // Opcode: TADDCCTVri
/* 1804 */    MCD_OPC_FilterValue, 35, 28, 0, 0, // Skip to: 1837
/* 1809 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1812 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1828
/* 1817 */    MCD_OPC_CheckField, 5, 8, 0, 30, 24, 0, // Skip to: 7998
/* 1824 */    MCD_OPC_Decode, 203, 5, 8, // Opcode: TSUBCCTVrr
/* 1828 */    MCD_OPC_FilterValue, 1, 21, 24, 0, // Skip to: 7998
/* 1833 */    MCD_OPC_Decode, 202, 5, 9, // Opcode: TSUBCCTVri
/* 1837 */    MCD_OPC_FilterValue, 36, 28, 0, 0, // Skip to: 1870
/* 1842 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 1845 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 1861
/* 1850 */    MCD_OPC_CheckField, 5, 8, 0, 253, 23, 0, // Skip to: 7998
/* 1857 */    MCD_OPC_Decode, 201, 4, 8, // Opcode: MULSCCrr
/* 1861 */    MCD_OPC_FilterValue, 1, 244, 23, 0, // Skip to: 7998
/* 1866 */    MCD_OPC_Decode, 200, 4, 9, // Opcode: MULSCCri
/* 1870 */    MCD_OPC_FilterValue, 37, 39, 0, 0, // Skip to: 1914
/* 1875 */    MCD_OPC_ExtractField, 12, 2,  // Inst{13-12} ...
/* 1878 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1887
/* 1883 */    MCD_OPC_Decode, 248, 4, 8, // Opcode: SLLrr
/* 1887 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1896
/* 1892 */    MCD_OPC_Decode, 246, 4, 14, // Opcode: SLLXrr
/* 1896 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1905
/* 1901 */    MCD_OPC_Decode, 247, 4, 15, // Opcode: SLLri
/* 1905 */    MCD_OPC_FilterValue, 3, 200, 23, 0, // Skip to: 7998
/* 1910 */    MCD_OPC_Decode, 245, 4, 16, // Opcode: SLLXri
/* 1914 */    MCD_OPC_FilterValue, 38, 39, 0, 0, // Skip to: 1958
/* 1919 */    MCD_OPC_ExtractField, 12, 2,  // Inst{13-12} ...
/* 1922 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1931
/* 1927 */    MCD_OPC_Decode, 134, 5, 8, // Opcode: SRLrr
/* 1931 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1940
/* 1936 */    MCD_OPC_Decode, 132, 5, 14, // Opcode: SRLXrr
/* 1940 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1949
/* 1945 */    MCD_OPC_Decode, 133, 5, 15, // Opcode: SRLri
/* 1949 */    MCD_OPC_FilterValue, 3, 156, 23, 0, // Skip to: 7998
/* 1954 */    MCD_OPC_Decode, 131, 5, 16, // Opcode: SRLXri
/* 1958 */    MCD_OPC_FilterValue, 39, 39, 0, 0, // Skip to: 2002
/* 1963 */    MCD_OPC_ExtractField, 12, 2,  // Inst{13-12} ...
/* 1966 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 1975
/* 1971 */    MCD_OPC_Decode, 130, 5, 8, // Opcode: SRArr
/* 1975 */    MCD_OPC_FilterValue, 1, 4, 0, 0, // Skip to: 1984
/* 1980 */    MCD_OPC_Decode, 128, 5, 14, // Opcode: SRAXrr
/* 1984 */    MCD_OPC_FilterValue, 2, 4, 0, 0, // Skip to: 1993
/* 1989 */    MCD_OPC_Decode, 129, 5, 15, // Opcode: SRAri
/* 1993 */    MCD_OPC_FilterValue, 3, 112, 23, 0, // Skip to: 7998
/* 1998 */    MCD_OPC_Decode, 255, 4, 16, // Opcode: SRAXri
/* 2002 */    MCD_OPC_FilterValue, 40, 66, 0, 0, // Skip to: 2073
/* 2007 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2010 */    MCD_OPC_FilterValue, 0, 30, 0, 0, // Skip to: 2045
/* 2015 */    MCD_OPC_ExtractField, 0, 13,  // Inst{12-0} ...
/* 2018 */    MCD_OPC_FilterValue, 0, 87, 23, 0, // Skip to: 7998
/* 2023 */    MCD_OPC_CheckField, 25, 5, 0, 11, 0, 0, // Skip to: 2041
/* 2030 */    MCD_OPC_CheckField, 14, 5, 15, 4, 0, 0, // Skip to: 2041
/* 2037 */    MCD_OPC_Decode, 136, 5, 4, // Opcode: STBAR
/* 2041 */    MCD_OPC_Decode, 221, 4, 17, // Opcode: RDASR
/* 2045 */    MCD_OPC_FilterValue, 1, 60, 23, 0, // Skip to: 7998
/* 2050 */    MCD_OPC_CheckPredicate, 0, 55, 23, 0, // Skip to: 7998
/* 2055 */    MCD_OPC_CheckField, 25, 5, 0, 48, 23, 0, // Skip to: 7998
/* 2062 */    MCD_OPC_CheckField, 14, 5, 15, 41, 23, 0, // Skip to: 7998
/* 2069 */    MCD_OPC_Decode, 176, 4, 18, // Opcode: MEMBARi
/* 2073 */    MCD_OPC_FilterValue, 41, 11, 0, 0, // Skip to: 2089
/* 2078 */    MCD_OPC_CheckField, 0, 19, 0, 25, 23, 0, // Skip to: 7998
/* 2085 */    MCD_OPC_Decode, 223, 4, 19, // Opcode: RDPSR
/* 2089 */    MCD_OPC_FilterValue, 42, 28, 0, 0, // Skip to: 2122
/* 2094 */    MCD_OPC_ExtractField, 0, 14,  // Inst{13-0} ...
/* 2097 */    MCD_OPC_FilterValue, 0, 8, 23, 0, // Skip to: 7998
/* 2102 */    MCD_OPC_CheckField, 14, 5, 0, 4, 0, 0, // Skip to: 2113
/* 2109 */    MCD_OPC_Decode, 225, 4, 19, // Opcode: RDWIM
/* 2113 */    MCD_OPC_CheckPredicate, 0, 248, 22, 0, // Skip to: 7998
/* 2118 */    MCD_OPC_Decode, 222, 4, 20, // Opcode: RDPR
/* 2122 */    MCD_OPC_FilterValue, 43, 28, 0, 0, // Skip to: 2155
/* 2127 */    MCD_OPC_ExtractField, 0, 19,  // Inst{18-0} ...
/* 2130 */    MCD_OPC_FilterValue, 0, 231, 22, 0, // Skip to: 7998
/* 2135 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 2151
/* 2140 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 2151
/* 2147 */    MCD_OPC_Decode, 136, 3, 4, // Opcode: FLUSHW
/* 2151 */    MCD_OPC_Decode, 224, 4, 19, // Opcode: RDTBR
/* 2155 */    MCD_OPC_FilterValue, 44, 141, 0, 0, // Skip to: 2301
/* 2160 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2163 */    MCD_OPC_FilterValue, 0, 64, 0, 0, // Skip to: 2232
/* 2168 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 2171 */    MCD_OPC_FilterValue, 0, 25, 0, 0, // Skip to: 2201
/* 2176 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 2192
/* 2181 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 2192
/* 2188 */    MCD_OPC_Decode, 179, 4, 21, // Opcode: MOVFCCrr
/* 2192 */    MCD_OPC_CheckPredicate, 0, 169, 22, 0, // Skip to: 7998
/* 2197 */    MCD_OPC_Decode, 232, 5, 22, // Opcode: V9MOVFCCrr
/* 2201 */    MCD_OPC_FilterValue, 1, 160, 22, 0, // Skip to: 7998
/* 2206 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 2209 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 2223
/* 2214 */    MCD_OPC_CheckPredicate, 0, 147, 22, 0, // Skip to: 7998
/* 2219 */    MCD_OPC_Decode, 181, 4, 21, // Opcode: MOVICCrr
/* 2223 */    MCD_OPC_FilterValue, 2, 138, 22, 0, // Skip to: 7998
/* 2228 */    MCD_OPC_Decode, 198, 4, 21, // Opcode: MOVXCCrr
/* 2232 */    MCD_OPC_FilterValue, 1, 129, 22, 0, // Skip to: 7998
/* 2237 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 2240 */    MCD_OPC_FilterValue, 0, 25, 0, 0, // Skip to: 2270
/* 2245 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 2261
/* 2250 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 2261
/* 2257 */    MCD_OPC_Decode, 178, 4, 23, // Opcode: MOVFCCri
/* 2261 */    MCD_OPC_CheckPredicate, 0, 100, 22, 0, // Skip to: 7998
/* 2266 */    MCD_OPC_Decode, 231, 5, 24, // Opcode: V9MOVFCCri
/* 2270 */    MCD_OPC_FilterValue, 1, 91, 22, 0, // Skip to: 7998
/* 2275 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 2278 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 2292
/* 2283 */    MCD_OPC_CheckPredicate, 0, 78, 22, 0, // Skip to: 7998
/* 2288 */    MCD_OPC_Decode, 180, 4, 23, // Opcode: MOVICCri
/* 2292 */    MCD_OPC_FilterValue, 2, 69, 22, 0, // Skip to: 7998
/* 2297 */    MCD_OPC_Decode, 197, 4, 23, // Opcode: MOVXCCri
/* 2301 */    MCD_OPC_FilterValue, 45, 28, 0, 0, // Skip to: 2334
/* 2306 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2309 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2325
/* 2314 */    MCD_OPC_CheckField, 5, 8, 0, 45, 22, 0, // Skip to: 7998
/* 2321 */    MCD_OPC_Decode, 237, 4, 10, // Opcode: SDIVXrr
/* 2325 */    MCD_OPC_FilterValue, 1, 36, 22, 0, // Skip to: 7998
/* 2330 */    MCD_OPC_Decode, 236, 4, 11, // Opcode: SDIVXri
/* 2334 */    MCD_OPC_FilterValue, 46, 16, 0, 0, // Skip to: 2355
/* 2339 */    MCD_OPC_CheckPredicate, 0, 22, 22, 0, // Skip to: 7998
/* 2344 */    MCD_OPC_CheckField, 5, 14, 0, 15, 22, 0, // Skip to: 7998
/* 2351 */    MCD_OPC_Decode, 218, 4, 25, // Opcode: POPCrr
/* 2355 */    MCD_OPC_FilterValue, 47, 153, 0, 0, // Skip to: 2513
/* 2360 */    MCD_OPC_ExtractField, 10, 4,  // Inst{13-10} ...
/* 2363 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 2379
/* 2368 */    MCD_OPC_CheckField, 5, 5, 0, 247, 21, 0, // Skip to: 7998
/* 2375 */    MCD_OPC_Decode, 193, 4, 14, // Opcode: MOVRRZrr
/* 2379 */    MCD_OPC_FilterValue, 2, 11, 0, 0, // Skip to: 2395
/* 2384 */    MCD_OPC_CheckField, 5, 5, 0, 231, 21, 0, // Skip to: 7998
/* 2391 */    MCD_OPC_Decode, 187, 4, 14, // Opcode: MOVRLEZrr
/* 2395 */    MCD_OPC_FilterValue, 3, 11, 0, 0, // Skip to: 2411
/* 2400 */    MCD_OPC_CheckField, 5, 5, 0, 215, 21, 0, // Skip to: 7998
/* 2407 */    MCD_OPC_Decode, 189, 4, 14, // Opcode: MOVRLZrr
/* 2411 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 2427
/* 2416 */    MCD_OPC_CheckField, 5, 5, 0, 199, 21, 0, // Skip to: 7998
/* 2423 */    MCD_OPC_Decode, 191, 4, 14, // Opcode: MOVRNZrr
/* 2427 */    MCD_OPC_FilterValue, 6, 11, 0, 0, // Skip to: 2443
/* 2432 */    MCD_OPC_CheckField, 5, 5, 0, 183, 21, 0, // Skip to: 7998
/* 2439 */    MCD_OPC_Decode, 185, 4, 14, // Opcode: MOVRGZrr
/* 2443 */    MCD_OPC_FilterValue, 7, 11, 0, 0, // Skip to: 2459
/* 2448 */    MCD_OPC_CheckField, 5, 5, 0, 167, 21, 0, // Skip to: 7998
/* 2455 */    MCD_OPC_Decode, 183, 4, 14, // Opcode: MOVRGEZrr
/* 2459 */    MCD_OPC_FilterValue, 9, 4, 0, 0, // Skip to: 2468
/* 2464 */    MCD_OPC_Decode, 192, 4, 26, // Opcode: MOVRRZri
/* 2468 */    MCD_OPC_FilterValue, 10, 4, 0, 0, // Skip to: 2477
/* 2473 */    MCD_OPC_Decode, 186, 4, 26, // Opcode: MOVRLEZri
/* 2477 */    MCD_OPC_FilterValue, 11, 4, 0, 0, // Skip to: 2486
/* 2482 */    MCD_OPC_Decode, 188, 4, 26, // Opcode: MOVRLZri
/* 2486 */    MCD_OPC_FilterValue, 13, 4, 0, 0, // Skip to: 2495
/* 2491 */    MCD_OPC_Decode, 190, 4, 26, // Opcode: MOVRNZri
/* 2495 */    MCD_OPC_FilterValue, 14, 4, 0, 0, // Skip to: 2504
/* 2500 */    MCD_OPC_Decode, 184, 4, 26, // Opcode: MOVRGZri
/* 2504 */    MCD_OPC_FilterValue, 15, 113, 21, 0, // Skip to: 7998
/* 2509 */    MCD_OPC_Decode, 182, 4, 26, // Opcode: MOVRGEZri
/* 2513 */    MCD_OPC_FilterValue, 48, 51, 0, 0, // Skip to: 2569
/* 2518 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2521 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2537
/* 2526 */    MCD_OPC_CheckField, 5, 8, 0, 89, 21, 0, // Skip to: 7998
/* 2533 */    MCD_OPC_Decode, 234, 5, 27, // Opcode: WRASRrr
/* 2537 */    MCD_OPC_FilterValue, 1, 80, 21, 0, // Skip to: 7998
/* 2542 */    MCD_OPC_CheckPredicate, 0, 18, 0, 0, // Skip to: 2565
/* 2547 */    MCD_OPC_CheckField, 25, 5, 15, 11, 0, 0, // Skip to: 2565
/* 2554 */    MCD_OPC_CheckField, 14, 5, 0, 4, 0, 0, // Skip to: 2565
/* 2561 */    MCD_OPC_Decode, 244, 4, 28, // Opcode: SIR
/* 2565 */    MCD_OPC_Decode, 233, 5, 29, // Opcode: WRASRri
/* 2569 */    MCD_OPC_FilterValue, 49, 79, 0, 0, // Skip to: 2653
/* 2574 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2577 */    MCD_OPC_FilterValue, 0, 40, 0, 0, // Skip to: 2622
/* 2582 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 2585 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 2601
/* 2590 */    MCD_OPC_CheckField, 5, 8, 0, 25, 21, 0, // Skip to: 7998
/* 2597 */    MCD_OPC_Decode, 238, 5, 12, // Opcode: WRPSRrr
/* 2601 */    MCD_OPC_FilterValue, 1, 16, 21, 0, // Skip to: 7998
/* 2606 */    MCD_OPC_CheckPredicate, 1, 11, 21, 0, // Skip to: 7998
/* 2611 */    MCD_OPC_CheckField, 5, 8, 0, 4, 21, 0, // Skip to: 7998
/* 2618 */    MCD_OPC_Decode, 220, 4, 12, // Opcode: PWRPSRrr
/* 2622 */    MCD_OPC_FilterValue, 1, 251, 20, 0, // Skip to: 7998
/* 2627 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 2630 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 2639
/* 2635 */    MCD_OPC_Decode, 237, 5, 13, // Opcode: WRPSRri
/* 2639 */    MCD_OPC_FilterValue, 1, 234, 20, 0, // Skip to: 7998
/* 2644 */    MCD_OPC_CheckPredicate, 1, 229, 20, 0, // Skip to: 7998
/* 2649 */    MCD_OPC_Decode, 219, 4, 13, // Opcode: PWRPSRri
/* 2653 */    MCD_OPC_FilterValue, 50, 61, 0, 0, // Skip to: 2719
/* 2658 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2661 */    MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 2694
/* 2666 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 2669 */    MCD_OPC_FilterValue, 0, 204, 20, 0, // Skip to: 7998
/* 2674 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 2685
/* 2681 */    MCD_OPC_Decode, 242, 5, 12, // Opcode: WRWIMrr
/* 2685 */    MCD_OPC_CheckPredicate, 0, 188, 20, 0, // Skip to: 7998
/* 2690 */    MCD_OPC_Decode, 236, 5, 30, // Opcode: WRPRrr
/* 2694 */    MCD_OPC_FilterValue, 1, 179, 20, 0, // Skip to: 7998
/* 2699 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 2710
/* 2706 */    MCD_OPC_Decode, 241, 5, 13, // Opcode: WRWIMri
/* 2710 */    MCD_OPC_CheckPredicate, 0, 163, 20, 0, // Skip to: 7998
/* 2715 */    MCD_OPC_Decode, 235, 5, 31, // Opcode: WRPRri
/* 2719 */    MCD_OPC_FilterValue, 51, 42, 0, 0, // Skip to: 2766
/* 2724 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 2727 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 2750
/* 2732 */    MCD_OPC_CheckField, 25, 5, 0, 139, 20, 0, // Skip to: 7998
/* 2739 */    MCD_OPC_CheckField, 5, 8, 0, 132, 20, 0, // Skip to: 7998
/* 2746 */    MCD_OPC_Decode, 240, 5, 12, // Opcode: WRTBRrr
/* 2750 */    MCD_OPC_FilterValue, 1, 123, 20, 0, // Skip to: 7998
/* 2755 */    MCD_OPC_CheckField, 25, 5, 0, 116, 20, 0, // Skip to: 7998
/* 2762 */    MCD_OPC_Decode, 239, 5, 13, // Opcode: WRTBRri
/* 2766 */    MCD_OPC_FilterValue, 52, 43, 3, 0, // Skip to: 3582
/* 2771 */    MCD_OPC_ExtractField, 5, 9,  // Inst{13-5} ...
/* 2774 */    MCD_OPC_FilterValue, 1, 11, 0, 0, // Skip to: 2790
/* 2779 */    MCD_OPC_CheckField, 14, 5, 0, 92, 20, 0, // Skip to: 7998
/* 2786 */    MCD_OPC_Decode, 166, 3, 32, // Opcode: FMOVS
/* 2790 */    MCD_OPC_FilterValue, 2, 16, 0, 0, // Skip to: 2811
/* 2795 */    MCD_OPC_CheckPredicate, 0, 78, 20, 0, // Skip to: 7998
/* 2800 */    MCD_OPC_CheckField, 14, 5, 0, 71, 20, 0, // Skip to: 7998
/* 2807 */    MCD_OPC_Decode, 140, 3, 33, // Opcode: FMOVD
/* 2811 */    MCD_OPC_FilterValue, 3, 16, 0, 0, // Skip to: 2832
/* 2816 */    MCD_OPC_CheckPredicate, 0, 57, 20, 0, // Skip to: 7998
/* 2821 */    MCD_OPC_CheckField, 14, 5, 0, 50, 20, 0, // Skip to: 7998
/* 2828 */    MCD_OPC_Decode, 144, 3, 34, // Opcode: FMOVQ
/* 2832 */    MCD_OPC_FilterValue, 5, 11, 0, 0, // Skip to: 2848
/* 2837 */    MCD_OPC_CheckField, 14, 5, 0, 34, 20, 0, // Skip to: 7998
/* 2844 */    MCD_OPC_Decode, 186, 3, 32, // Opcode: FNEGS
/* 2848 */    MCD_OPC_FilterValue, 6, 16, 0, 0, // Skip to: 2869
/* 2853 */    MCD_OPC_CheckPredicate, 0, 20, 20, 0, // Skip to: 7998
/* 2858 */    MCD_OPC_CheckField, 14, 5, 0, 13, 20, 0, // Skip to: 7998
/* 2865 */    MCD_OPC_Decode, 184, 3, 33, // Opcode: FNEGD
/* 2869 */    MCD_OPC_FilterValue, 7, 16, 0, 0, // Skip to: 2890
/* 2874 */    MCD_OPC_CheckPredicate, 0, 255, 19, 0, // Skip to: 7998
/* 2879 */    MCD_OPC_CheckField, 14, 5, 0, 248, 19, 0, // Skip to: 7998
/* 2886 */    MCD_OPC_Decode, 185, 3, 34, // Opcode: FNEGQ
/* 2890 */    MCD_OPC_FilterValue, 9, 11, 0, 0, // Skip to: 2906
/* 2895 */    MCD_OPC_CheckField, 14, 5, 0, 232, 19, 0, // Skip to: 7998
/* 2902 */    MCD_OPC_Decode, 220, 2, 32, // Opcode: FABSS
/* 2906 */    MCD_OPC_FilterValue, 10, 16, 0, 0, // Skip to: 2927
/* 2911 */    MCD_OPC_CheckPredicate, 0, 218, 19, 0, // Skip to: 7998
/* 2916 */    MCD_OPC_CheckField, 14, 5, 0, 211, 19, 0, // Skip to: 7998
/* 2923 */    MCD_OPC_Decode, 218, 2, 33, // Opcode: FABSD
/* 2927 */    MCD_OPC_FilterValue, 11, 16, 0, 0, // Skip to: 2948
/* 2932 */    MCD_OPC_CheckPredicate, 0, 197, 19, 0, // Skip to: 7998
/* 2937 */    MCD_OPC_CheckField, 14, 5, 0, 190, 19, 0, // Skip to: 7998
/* 2944 */    MCD_OPC_Decode, 219, 2, 34, // Opcode: FABSQ
/* 2948 */    MCD_OPC_FilterValue, 41, 11, 0, 0, // Skip to: 2964
/* 2953 */    MCD_OPC_CheckField, 14, 5, 0, 174, 19, 0, // Skip to: 7998
/* 2960 */    MCD_OPC_Decode, 230, 3, 32, // Opcode: FSQRTS
/* 2964 */    MCD_OPC_FilterValue, 42, 11, 0, 0, // Skip to: 2980
/* 2969 */    MCD_OPC_CheckField, 14, 5, 0, 158, 19, 0, // Skip to: 7998
/* 2976 */    MCD_OPC_Decode, 228, 3, 33, // Opcode: FSQRTD
/* 2980 */    MCD_OPC_FilterValue, 43, 11, 0, 0, // Skip to: 2996
/* 2985 */    MCD_OPC_CheckField, 14, 5, 0, 142, 19, 0, // Skip to: 7998
/* 2992 */    MCD_OPC_Decode, 229, 3, 34, // Opcode: FSQRTQ
/* 2996 */    MCD_OPC_FilterValue, 65, 4, 0, 0, // Skip to: 3005
/* 3001 */    MCD_OPC_Decode, 223, 2, 35, // Opcode: FADDS
/* 3005 */    MCD_OPC_FilterValue, 66, 4, 0, 0, // Skip to: 3014
/* 3010 */    MCD_OPC_Decode, 221, 2, 36, // Opcode: FADDD
/* 3014 */    MCD_OPC_FilterValue, 67, 4, 0, 0, // Skip to: 3023
/* 3019 */    MCD_OPC_Decode, 222, 2, 37, // Opcode: FADDQ
/* 3023 */    MCD_OPC_FilterValue, 69, 4, 0, 0, // Skip to: 3032
/* 3028 */    MCD_OPC_Decode, 245, 3, 35, // Opcode: FSUBS
/* 3032 */    MCD_OPC_FilterValue, 70, 4, 0, 0, // Skip to: 3041
/* 3037 */    MCD_OPC_Decode, 243, 3, 36, // Opcode: FSUBD
/* 3041 */    MCD_OPC_FilterValue, 71, 4, 0, 0, // Skip to: 3050
/* 3046 */    MCD_OPC_Decode, 244, 3, 37, // Opcode: FSUBQ
/* 3050 */    MCD_OPC_FilterValue, 73, 4, 0, 0, // Skip to: 3059
/* 3055 */    MCD_OPC_Decode, 179, 3, 35, // Opcode: FMULS
/* 3059 */    MCD_OPC_FilterValue, 74, 4, 0, 0, // Skip to: 3068
/* 3064 */    MCD_OPC_Decode, 175, 3, 36, // Opcode: FMULD
/* 3068 */    MCD_OPC_FilterValue, 75, 4, 0, 0, // Skip to: 3077
/* 3073 */    MCD_OPC_Decode, 178, 3, 37, // Opcode: FMULQ
/* 3077 */    MCD_OPC_FilterValue, 77, 4, 0, 0, // Skip to: 3086
/* 3082 */    MCD_OPC_Decode, 247, 2, 35, // Opcode: FDIVS
/* 3086 */    MCD_OPC_FilterValue, 78, 4, 0, 0, // Skip to: 3095
/* 3091 */    MCD_OPC_Decode, 245, 2, 36, // Opcode: FDIVD
/* 3095 */    MCD_OPC_FilterValue, 79, 4, 0, 0, // Skip to: 3104
/* 3100 */    MCD_OPC_Decode, 246, 2, 37, // Opcode: FDIVQ
/* 3104 */    MCD_OPC_FilterValue, 81, 9, 0, 0, // Skip to: 3118
/* 3109 */    MCD_OPC_CheckPredicate, 2, 20, 19, 0, // Skip to: 7998
/* 3114 */    MCD_OPC_Decode, 181, 3, 36, // Opcode: FNADDS
/* 3118 */    MCD_OPC_FilterValue, 82, 9, 0, 0, // Skip to: 3132
/* 3123 */    MCD_OPC_CheckPredicate, 2, 6, 19, 0, // Skip to: 7998
/* 3128 */    MCD_OPC_Decode, 180, 3, 36, // Opcode: FNADDD
/* 3132 */    MCD_OPC_FilterValue, 89, 9, 0, 0, // Skip to: 3146
/* 3137 */    MCD_OPC_CheckPredicate, 2, 248, 18, 0, // Skip to: 7998
/* 3142 */    MCD_OPC_Decode, 190, 3, 36, // Opcode: FNMULS
/* 3146 */    MCD_OPC_FilterValue, 90, 9, 0, 0, // Skip to: 3160
/* 3151 */    MCD_OPC_CheckPredicate, 2, 234, 18, 0, // Skip to: 7998
/* 3156 */    MCD_OPC_Decode, 189, 3, 36, // Opcode: FNMULD
/* 3160 */    MCD_OPC_FilterValue, 97, 9, 0, 0, // Skip to: 3174
/* 3165 */    MCD_OPC_CheckPredicate, 2, 220, 18, 0, // Skip to: 7998
/* 3170 */    MCD_OPC_Decode, 255, 2, 36, // Opcode: FHADDS
/* 3174 */    MCD_OPC_FilterValue, 98, 9, 0, 0, // Skip to: 3188
/* 3179 */    MCD_OPC_CheckPredicate, 2, 206, 18, 0, // Skip to: 7998
/* 3184 */    MCD_OPC_Decode, 254, 2, 36, // Opcode: FHADDD
/* 3188 */    MCD_OPC_FilterValue, 101, 9, 0, 0, // Skip to: 3202
/* 3193 */    MCD_OPC_CheckPredicate, 2, 192, 18, 0, // Skip to: 7998
/* 3198 */    MCD_OPC_Decode, 129, 3, 36, // Opcode: FHSUBS
/* 3202 */    MCD_OPC_FilterValue, 102, 9, 0, 0, // Skip to: 3216
/* 3207 */    MCD_OPC_CheckPredicate, 2, 178, 18, 0, // Skip to: 7998
/* 3212 */    MCD_OPC_Decode, 128, 3, 36, // Opcode: FHSUBD
/* 3216 */    MCD_OPC_FilterValue, 105, 4, 0, 0, // Skip to: 3225
/* 3221 */    MCD_OPC_Decode, 227, 3, 38, // Opcode: FSMULD
/* 3225 */    MCD_OPC_FilterValue, 110, 4, 0, 0, // Skip to: 3234
/* 3230 */    MCD_OPC_Decode, 248, 2, 39, // Opcode: FDMULQ
/* 3234 */    MCD_OPC_FilterValue, 113, 9, 0, 0, // Skip to: 3248
/* 3239 */    MCD_OPC_CheckPredicate, 2, 146, 18, 0, // Skip to: 7998
/* 3244 */    MCD_OPC_Decode, 188, 3, 36, // Opcode: FNHADDS
/* 3248 */    MCD_OPC_FilterValue, 114, 9, 0, 0, // Skip to: 3262
/* 3253 */    MCD_OPC_CheckPredicate, 2, 132, 18, 0, // Skip to: 7998
/* 3258 */    MCD_OPC_Decode, 187, 3, 36, // Opcode: FNHADDD
/* 3262 */    MCD_OPC_FilterValue, 121, 9, 0, 0, // Skip to: 3276
/* 3267 */    MCD_OPC_CheckPredicate, 2, 118, 18, 0, // Skip to: 7998
/* 3272 */    MCD_OPC_Decode, 197, 3, 36, // Opcode: FNSMULD
/* 3276 */    MCD_OPC_FilterValue, 129, 1, 11, 0, 0, // Skip to: 3293
/* 3282 */    MCD_OPC_CheckField, 14, 5, 0, 101, 18, 0, // Skip to: 7998
/* 3289 */    MCD_OPC_Decode, 242, 3, 40, // Opcode: FSTOX
/* 3293 */    MCD_OPC_FilterValue, 130, 1, 11, 0, 0, // Skip to: 3310
/* 3299 */    MCD_OPC_CheckField, 14, 5, 0, 84, 18, 0, // Skip to: 7998
/* 3306 */    MCD_OPC_Decode, 252, 2, 33, // Opcode: FDTOX
/* 3310 */    MCD_OPC_FilterValue, 131, 1, 11, 0, 0, // Skip to: 3327
/* 3316 */    MCD_OPC_CheckField, 14, 5, 0, 67, 18, 0, // Skip to: 7998
/* 3323 */    MCD_OPC_Decode, 222, 3, 41, // Opcode: FQTOX
/* 3327 */    MCD_OPC_FilterValue, 132, 1, 11, 0, 0, // Skip to: 3344
/* 3333 */    MCD_OPC_CheckField, 14, 5, 0, 50, 18, 0, // Skip to: 7998
/* 3340 */    MCD_OPC_Decode, 252, 3, 42, // Opcode: FXTOS
/* 3344 */    MCD_OPC_FilterValue, 136, 1, 11, 0, 0, // Skip to: 3361
/* 3350 */    MCD_OPC_CheckField, 14, 5, 0, 33, 18, 0, // Skip to: 7998
/* 3357 */    MCD_OPC_Decode, 250, 3, 33, // Opcode: FXTOD
/* 3361 */    MCD_OPC_FilterValue, 140, 1, 11, 0, 0, // Skip to: 3378
/* 3367 */    MCD_OPC_CheckField, 14, 5, 0, 16, 18, 0, // Skip to: 7998
/* 3374 */    MCD_OPC_Decode, 251, 3, 43, // Opcode: FXTOQ
/* 3378 */    MCD_OPC_FilterValue, 196, 1, 11, 0, 0, // Skip to: 3395
/* 3384 */    MCD_OPC_CheckField, 14, 5, 0, 255, 17, 0, // Skip to: 7998
/* 3391 */    MCD_OPC_Decode, 132, 3, 32, // Opcode: FITOS
/* 3395 */    MCD_OPC_FilterValue, 198, 1, 11, 0, 0, // Skip to: 3412
/* 3401 */    MCD_OPC_CheckField, 14, 5, 0, 238, 17, 0, // Skip to: 7998
/* 3408 */    MCD_OPC_Decode, 251, 2, 42, // Opcode: FDTOS
/* 3412 */    MCD_OPC_FilterValue, 199, 1, 11, 0, 0, // Skip to: 3429
/* 3418 */    MCD_OPC_CheckField, 14, 5, 0, 221, 17, 0, // Skip to: 7998
/* 3425 */    MCD_OPC_Decode, 221, 3, 44, // Opcode: FQTOS
/* 3429 */    MCD_OPC_FilterValue, 200, 1, 11, 0, 0, // Skip to: 3446
/* 3435 */    MCD_OPC_CheckField, 14, 5, 0, 204, 17, 0, // Skip to: 7998
/* 3442 */    MCD_OPC_Decode, 130, 3, 40, // Opcode: FITOD
/* 3446 */    MCD_OPC_FilterValue, 201, 1, 11, 0, 0, // Skip to: 3463
/* 3452 */    MCD_OPC_CheckField, 14, 5, 0, 187, 17, 0, // Skip to: 7998
/* 3459 */    MCD_OPC_Decode, 239, 3, 40, // Opcode: FSTOD
/* 3463 */    MCD_OPC_FilterValue, 203, 1, 11, 0, 0, // Skip to: 3480
/* 3469 */    MCD_OPC_CheckField, 14, 5, 0, 170, 17, 0, // Skip to: 7998
/* 3476 */    MCD_OPC_Decode, 219, 3, 41, // Opcode: FQTOD
/* 3480 */    MCD_OPC_FilterValue, 204, 1, 11, 0, 0, // Skip to: 3497
/* 3486 */    MCD_OPC_CheckField, 14, 5, 0, 153, 17, 0, // Skip to: 7998
/* 3493 */    MCD_OPC_Decode, 131, 3, 45, // Opcode: FITOQ
/* 3497 */    MCD_OPC_FilterValue, 205, 1, 11, 0, 0, // Skip to: 3514
/* 3503 */    MCD_OPC_CheckField, 14, 5, 0, 136, 17, 0, // Skip to: 7998
/* 3510 */    MCD_OPC_Decode, 241, 3, 45, // Opcode: FSTOQ
/* 3514 */    MCD_OPC_FilterValue, 206, 1, 11, 0, 0, // Skip to: 3531
/* 3520 */    MCD_OPC_CheckField, 14, 5, 0, 119, 17, 0, // Skip to: 7998
/* 3527 */    MCD_OPC_Decode, 250, 2, 43, // Opcode: FDTOQ
/* 3531 */    MCD_OPC_FilterValue, 209, 1, 11, 0, 0, // Skip to: 3548
/* 3537 */    MCD_OPC_CheckField, 14, 5, 0, 102, 17, 0, // Skip to: 7998
/* 3544 */    MCD_OPC_Decode, 240, 3, 32, // Opcode: FSTOI
/* 3548 */    MCD_OPC_FilterValue, 210, 1, 11, 0, 0, // Skip to: 3565
/* 3554 */    MCD_OPC_CheckField, 14, 5, 0, 85, 17, 0, // Skip to: 7998
/* 3561 */    MCD_OPC_Decode, 249, 2, 42, // Opcode: FDTOI
/* 3565 */    MCD_OPC_FilterValue, 211, 1, 75, 17, 0, // Skip to: 7998
/* 3571 */    MCD_OPC_CheckField, 14, 5, 0, 68, 17, 0, // Skip to: 7998
/* 3578 */    MCD_OPC_Decode, 220, 3, 44, // Opcode: FQTOI
/* 3582 */    MCD_OPC_FilterValue, 53, 160, 2, 0, // Skip to: 4259
/* 3587 */    MCD_OPC_ExtractField, 5, 6,  // Inst{10-5} ...
/* 3590 */    MCD_OPC_FilterValue, 1, 86, 0, 0, // Skip to: 3681
/* 3595 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 3598 */    MCD_OPC_FilterValue, 0, 33, 0, 0, // Skip to: 3636
/* 3603 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 3606 */    MCD_OPC_FilterValue, 0, 35, 17, 0, // Skip to: 7998
/* 3611 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 3627
/* 3616 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 3627
/* 3623 */    MCD_OPC_Decode, 167, 3, 46, // Opcode: FMOVS_FCC
/* 3627 */    MCD_OPC_CheckPredicate, 0, 14, 17, 0, // Skip to: 7998
/* 3632 */    MCD_OPC_Decode, 230, 5, 47, // Opcode: V9FMOVS_FCC
/* 3636 */    MCD_OPC_FilterValue, 1, 5, 17, 0, // Skip to: 7998
/* 3641 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 3644 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 3665
/* 3649 */    MCD_OPC_CheckPredicate, 0, 248, 16, 0, // Skip to: 7998
/* 3654 */    MCD_OPC_CheckField, 18, 1, 0, 241, 16, 0, // Skip to: 7998
/* 3661 */    MCD_OPC_Decode, 168, 3, 46, // Opcode: FMOVS_ICC
/* 3665 */    MCD_OPC_FilterValue, 2, 232, 16, 0, // Skip to: 7998
/* 3670 */    MCD_OPC_CheckField, 18, 1, 0, 225, 16, 0, // Skip to: 7998
/* 3677 */    MCD_OPC_Decode, 169, 3, 46, // Opcode: FMOVS_XCC
/* 3681 */    MCD_OPC_FilterValue, 2, 86, 0, 0, // Skip to: 3772
/* 3686 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 3689 */    MCD_OPC_FilterValue, 0, 33, 0, 0, // Skip to: 3727
/* 3694 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 3697 */    MCD_OPC_FilterValue, 0, 200, 16, 0, // Skip to: 7998
/* 3702 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 3718
/* 3707 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 3718
/* 3714 */    MCD_OPC_Decode, 141, 3, 48, // Opcode: FMOVD_FCC
/* 3718 */    MCD_OPC_CheckPredicate, 0, 179, 16, 0, // Skip to: 7998
/* 3723 */    MCD_OPC_Decode, 228, 5, 49, // Opcode: V9FMOVD_FCC
/* 3727 */    MCD_OPC_FilterValue, 1, 170, 16, 0, // Skip to: 7998
/* 3732 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 3735 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 3756
/* 3740 */    MCD_OPC_CheckPredicate, 0, 157, 16, 0, // Skip to: 7998
/* 3745 */    MCD_OPC_CheckField, 18, 1, 0, 150, 16, 0, // Skip to: 7998
/* 3752 */    MCD_OPC_Decode, 142, 3, 48, // Opcode: FMOVD_ICC
/* 3756 */    MCD_OPC_FilterValue, 2, 141, 16, 0, // Skip to: 7998
/* 3761 */    MCD_OPC_CheckField, 18, 1, 0, 134, 16, 0, // Skip to: 7998
/* 3768 */    MCD_OPC_Decode, 143, 3, 48, // Opcode: FMOVD_XCC
/* 3772 */    MCD_OPC_FilterValue, 3, 86, 0, 0, // Skip to: 3863
/* 3777 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 3780 */    MCD_OPC_FilterValue, 0, 33, 0, 0, // Skip to: 3818
/* 3785 */    MCD_OPC_ExtractField, 18, 1,  // Inst{18} ...
/* 3788 */    MCD_OPC_FilterValue, 0, 109, 16, 0, // Skip to: 7998
/* 3793 */    MCD_OPC_CheckPredicate, 0, 11, 0, 0, // Skip to: 3809
/* 3798 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, 0, // Skip to: 3809
/* 3805 */    MCD_OPC_Decode, 145, 3, 50, // Opcode: FMOVQ_FCC
/* 3809 */    MCD_OPC_CheckPredicate, 0, 88, 16, 0, // Skip to: 7998
/* 3814 */    MCD_OPC_Decode, 229, 5, 51, // Opcode: V9FMOVQ_FCC
/* 3818 */    MCD_OPC_FilterValue, 1, 79, 16, 0, // Skip to: 7998
/* 3823 */    MCD_OPC_ExtractField, 11, 2,  // Inst{12-11} ...
/* 3826 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 3847
/* 3831 */    MCD_OPC_CheckPredicate, 0, 66, 16, 0, // Skip to: 7998
/* 3836 */    MCD_OPC_CheckField, 18, 1, 0, 59, 16, 0, // Skip to: 7998
/* 3843 */    MCD_OPC_Decode, 146, 3, 50, // Opcode: FMOVQ_ICC
/* 3847 */    MCD_OPC_FilterValue, 2, 50, 16, 0, // Skip to: 7998
/* 3852 */    MCD_OPC_CheckField, 18, 1, 0, 43, 16, 0, // Skip to: 7998
/* 3859 */    MCD_OPC_Decode, 147, 3, 50, // Opcode: FMOVQ_XCC
/* 3863 */    MCD_OPC_FilterValue, 5, 31, 0, 0, // Skip to: 3899
/* 3868 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 3871 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 3885
/* 3876 */    MCD_OPC_CheckPredicate, 0, 21, 16, 0, // Skip to: 7998
/* 3881 */    MCD_OPC_Decode, 156, 3, 52, // Opcode: FMOVRLEZS
/* 3885 */    MCD_OPC_FilterValue, 3, 12, 16, 0, // Skip to: 7998
/* 3890 */    MCD_OPC_CheckPredicate, 0, 7, 16, 0, // Skip to: 7998
/* 3895 */    MCD_OPC_Decode, 153, 3, 52, // Opcode: FMOVRGZS
/* 3899 */    MCD_OPC_FilterValue, 6, 31, 0, 0, // Skip to: 3935
/* 3904 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 3907 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 3921
/* 3912 */    MCD_OPC_CheckPredicate, 0, 241, 15, 0, // Skip to: 7998
/* 3917 */    MCD_OPC_Decode, 154, 3, 52, // Opcode: FMOVRLEZD
/* 3921 */    MCD_OPC_FilterValue, 3, 232, 15, 0, // Skip to: 7998
/* 3926 */    MCD_OPC_CheckPredicate, 0, 227, 15, 0, // Skip to: 7998
/* 3931 */    MCD_OPC_Decode, 151, 3, 52, // Opcode: FMOVRGZD
/* 3935 */    MCD_OPC_FilterValue, 7, 31, 0, 0, // Skip to: 3971
/* 3940 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 3943 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 3957
/* 3948 */    MCD_OPC_CheckPredicate, 0, 205, 15, 0, // Skip to: 7998
/* 3953 */    MCD_OPC_Decode, 155, 3, 52, // Opcode: FMOVRLEZQ
/* 3957 */    MCD_OPC_FilterValue, 3, 196, 15, 0, // Skip to: 7998
/* 3962 */    MCD_OPC_CheckPredicate, 0, 191, 15, 0, // Skip to: 7998
/* 3967 */    MCD_OPC_Decode, 152, 3, 52, // Opcode: FMOVRGZQ
/* 3971 */    MCD_OPC_FilterValue, 17, 11, 0, 0, // Skip to: 3987
/* 3976 */    MCD_OPC_CheckField, 11, 3, 1, 175, 15, 0, // Skip to: 7998
/* 3983 */    MCD_OPC_Decode, 227, 5, 53, // Opcode: V9FCMPS
/* 3987 */    MCD_OPC_FilterValue, 18, 11, 0, 0, // Skip to: 4003
/* 3992 */    MCD_OPC_CheckField, 11, 3, 1, 159, 15, 0, // Skip to: 7998
/* 3999 */    MCD_OPC_Decode, 222, 5, 54, // Opcode: V9FCMPD
/* 4003 */    MCD_OPC_FilterValue, 19, 11, 0, 0, // Skip to: 4019
/* 4008 */    MCD_OPC_CheckField, 11, 3, 1, 143, 15, 0, // Skip to: 7998
/* 4015 */    MCD_OPC_Decode, 226, 5, 55, // Opcode: V9FCMPQ
/* 4019 */    MCD_OPC_FilterValue, 21, 11, 0, 0, // Skip to: 4035
/* 4024 */    MCD_OPC_CheckField, 11, 3, 1, 127, 15, 0, // Skip to: 7998
/* 4031 */    MCD_OPC_Decode, 225, 5, 53, // Opcode: V9FCMPES
/* 4035 */    MCD_OPC_FilterValue, 22, 11, 0, 0, // Skip to: 4051
/* 4040 */    MCD_OPC_CheckField, 11, 3, 1, 111, 15, 0, // Skip to: 7998
/* 4047 */    MCD_OPC_Decode, 223, 5, 54, // Opcode: V9FCMPED
/* 4051 */    MCD_OPC_FilterValue, 23, 11, 0, 0, // Skip to: 4067
/* 4056 */    MCD_OPC_CheckField, 11, 3, 1, 95, 15, 0, // Skip to: 7998
/* 4063 */    MCD_OPC_Decode, 224, 5, 55, // Opcode: V9FCMPEQ
/* 4067 */    MCD_OPC_FilterValue, 37, 59, 0, 0, // Skip to: 4131
/* 4072 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 4075 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 4089
/* 4080 */    MCD_OPC_CheckPredicate, 0, 73, 15, 0, // Skip to: 7998
/* 4085 */    MCD_OPC_Decode, 165, 3, 52, // Opcode: FMOVRZS
/* 4089 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 4103
/* 4094 */    MCD_OPC_CheckPredicate, 0, 59, 15, 0, // Skip to: 7998
/* 4099 */    MCD_OPC_Decode, 159, 3, 52, // Opcode: FMOVRLZS
/* 4103 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 4117
/* 4108 */    MCD_OPC_CheckPredicate, 0, 45, 15, 0, // Skip to: 7998
/* 4113 */    MCD_OPC_Decode, 162, 3, 52, // Opcode: FMOVRNZS
/* 4117 */    MCD_OPC_FilterValue, 3, 36, 15, 0, // Skip to: 7998
/* 4122 */    MCD_OPC_CheckPredicate, 0, 31, 15, 0, // Skip to: 7998
/* 4127 */    MCD_OPC_Decode, 150, 3, 52, // Opcode: FMOVRGEZS
/* 4131 */    MCD_OPC_FilterValue, 38, 59, 0, 0, // Skip to: 4195
/* 4136 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 4139 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 4153
/* 4144 */    MCD_OPC_CheckPredicate, 0, 9, 15, 0, // Skip to: 7998
/* 4149 */    MCD_OPC_Decode, 163, 3, 52, // Opcode: FMOVRZD
/* 4153 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 4167
/* 4158 */    MCD_OPC_CheckPredicate, 0, 251, 14, 0, // Skip to: 7998
/* 4163 */    MCD_OPC_Decode, 157, 3, 52, // Opcode: FMOVRLZD
/* 4167 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 4181
/* 4172 */    MCD_OPC_CheckPredicate, 0, 237, 14, 0, // Skip to: 7998
/* 4177 */    MCD_OPC_Decode, 160, 3, 52, // Opcode: FMOVRNZD
/* 4181 */    MCD_OPC_FilterValue, 3, 228, 14, 0, // Skip to: 7998
/* 4186 */    MCD_OPC_CheckPredicate, 0, 223, 14, 0, // Skip to: 7998
/* 4191 */    MCD_OPC_Decode, 148, 3, 52, // Opcode: FMOVRGEZD
/* 4195 */    MCD_OPC_FilterValue, 39, 214, 14, 0, // Skip to: 7998
/* 4200 */    MCD_OPC_ExtractField, 11, 3,  // Inst{13-11} ...
/* 4203 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 4217
/* 4208 */    MCD_OPC_CheckPredicate, 0, 201, 14, 0, // Skip to: 7998
/* 4213 */    MCD_OPC_Decode, 164, 3, 52, // Opcode: FMOVRZQ
/* 4217 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 4231
/* 4222 */    MCD_OPC_CheckPredicate, 0, 187, 14, 0, // Skip to: 7998
/* 4227 */    MCD_OPC_Decode, 158, 3, 52, // Opcode: FMOVRLZQ
/* 4231 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 4245
/* 4236 */    MCD_OPC_CheckPredicate, 0, 173, 14, 0, // Skip to: 7998
/* 4241 */    MCD_OPC_Decode, 161, 3, 52, // Opcode: FMOVRNZQ
/* 4245 */    MCD_OPC_FilterValue, 3, 164, 14, 0, // Skip to: 7998
/* 4250 */    MCD_OPC_CheckPredicate, 0, 159, 14, 0, // Skip to: 7998
/* 4255 */    MCD_OPC_Decode, 149, 3, 52, // Opcode: FMOVRGEZQ
/* 4259 */    MCD_OPC_FilterValue, 54, 35, 7, 0, // Skip to: 6091
/* 4264 */    MCD_OPC_ExtractField, 5, 9,  // Inst{13-5} ...
/* 4267 */    MCD_OPC_FilterValue, 0, 9, 0, 0, // Skip to: 4281
/* 4272 */    MCD_OPC_CheckPredicate, 3, 137, 14, 0, // Skip to: 7998
/* 4277 */    MCD_OPC_Decode, 214, 2, 10, // Opcode: EDGE8
/* 4281 */    MCD_OPC_FilterValue, 1, 9, 0, 0, // Skip to: 4295
/* 4286 */    MCD_OPC_CheckPredicate, 4, 123, 14, 0, // Skip to: 7998
/* 4291 */    MCD_OPC_Decode, 217, 2, 10, // Opcode: EDGE8N
/* 4295 */    MCD_OPC_FilterValue, 2, 9, 0, 0, // Skip to: 4309
/* 4300 */    MCD_OPC_CheckPredicate, 3, 109, 14, 0, // Skip to: 7998
/* 4305 */    MCD_OPC_Decode, 215, 2, 10, // Opcode: EDGE8L
/* 4309 */    MCD_OPC_FilterValue, 3, 9, 0, 0, // Skip to: 4323
/* 4314 */    MCD_OPC_CheckPredicate, 4, 95, 14, 0, // Skip to: 7998
/* 4319 */    MCD_OPC_Decode, 216, 2, 10, // Opcode: EDGE8LN
/* 4323 */    MCD_OPC_FilterValue, 4, 9, 0, 0, // Skip to: 4337
/* 4328 */    MCD_OPC_CheckPredicate, 3, 81, 14, 0, // Skip to: 7998
/* 4333 */    MCD_OPC_Decode, 206, 2, 10, // Opcode: EDGE16
/* 4337 */    MCD_OPC_FilterValue, 5, 9, 0, 0, // Skip to: 4351
/* 4342 */    MCD_OPC_CheckPredicate, 4, 67, 14, 0, // Skip to: 7998
/* 4347 */    MCD_OPC_Decode, 209, 2, 10, // Opcode: EDGE16N
/* 4351 */    MCD_OPC_FilterValue, 6, 9, 0, 0, // Skip to: 4365
/* 4356 */    MCD_OPC_CheckPredicate, 3, 53, 14, 0, // Skip to: 7998
/* 4361 */    MCD_OPC_Decode, 207, 2, 10, // Opcode: EDGE16L
/* 4365 */    MCD_OPC_FilterValue, 7, 9, 0, 0, // Skip to: 4379
/* 4370 */    MCD_OPC_CheckPredicate, 4, 39, 14, 0, // Skip to: 7998
/* 4375 */    MCD_OPC_Decode, 208, 2, 10, // Opcode: EDGE16LN
/* 4379 */    MCD_OPC_FilterValue, 8, 9, 0, 0, // Skip to: 4393
/* 4384 */    MCD_OPC_CheckPredicate, 3, 25, 14, 0, // Skip to: 7998
/* 4389 */    MCD_OPC_Decode, 210, 2, 10, // Opcode: EDGE32
/* 4393 */    MCD_OPC_FilterValue, 9, 9, 0, 0, // Skip to: 4407
/* 4398 */    MCD_OPC_CheckPredicate, 4, 11, 14, 0, // Skip to: 7998
/* 4403 */    MCD_OPC_Decode, 213, 2, 10, // Opcode: EDGE32N
/* 4407 */    MCD_OPC_FilterValue, 10, 9, 0, 0, // Skip to: 4421
/* 4412 */    MCD_OPC_CheckPredicate, 3, 253, 13, 0, // Skip to: 7998
/* 4417 */    MCD_OPC_Decode, 211, 2, 10, // Opcode: EDGE32L
/* 4421 */    MCD_OPC_FilterValue, 11, 9, 0, 0, // Skip to: 4435
/* 4426 */    MCD_OPC_CheckPredicate, 4, 239, 13, 0, // Skip to: 7998
/* 4431 */    MCD_OPC_Decode, 212, 2, 10, // Opcode: EDGE32LN
/* 4435 */    MCD_OPC_FilterValue, 16, 9, 0, 0, // Skip to: 4449
/* 4440 */    MCD_OPC_CheckPredicate, 3, 225, 13, 0, // Skip to: 7998
/* 4445 */    MCD_OPC_Decode, 148, 2, 10, // Opcode: ARRAY8
/* 4449 */    MCD_OPC_FilterValue, 17, 9, 0, 0, // Skip to: 4463
/* 4454 */    MCD_OPC_CheckPredicate, 2, 211, 13, 0, // Skip to: 7998
/* 4459 */    MCD_OPC_Decode, 255, 1, 10, // Opcode: ADDXC
/* 4463 */    MCD_OPC_FilterValue, 18, 9, 0, 0, // Skip to: 4477
/* 4468 */    MCD_OPC_CheckPredicate, 3, 197, 13, 0, // Skip to: 7998
/* 4473 */    MCD_OPC_Decode, 146, 2, 10, // Opcode: ARRAY16
/* 4477 */    MCD_OPC_FilterValue, 19, 9, 0, 0, // Skip to: 4491
/* 4482 */    MCD_OPC_CheckPredicate, 2, 183, 13, 0, // Skip to: 7998
/* 4487 */    MCD_OPC_Decode, 128, 2, 10, // Opcode: ADDXCCC
/* 4491 */    MCD_OPC_FilterValue, 20, 9, 0, 0, // Skip to: 4505
/* 4496 */    MCD_OPC_CheckPredicate, 3, 169, 13, 0, // Skip to: 7998
/* 4501 */    MCD_OPC_Decode, 147, 2, 10, // Opcode: ARRAY32
/* 4505 */    MCD_OPC_FilterValue, 22, 9, 0, 0, // Skip to: 4519
/* 4510 */    MCD_OPC_CheckPredicate, 2, 155, 13, 0, // Skip to: 7998
/* 4515 */    MCD_OPC_Decode, 218, 5, 10, // Opcode: UMULXHI
/* 4519 */    MCD_OPC_FilterValue, 23, 16, 0, 0, // Skip to: 4540
/* 4524 */    MCD_OPC_CheckPredicate, 2, 141, 13, 0, // Skip to: 7998
/* 4529 */    MCD_OPC_CheckField, 14, 5, 0, 134, 13, 0, // Skip to: 7998
/* 4536 */    MCD_OPC_Decode, 175, 4, 56, // Opcode: LZCNT
/* 4540 */    MCD_OPC_FilterValue, 24, 9, 0, 0, // Skip to: 4554
/* 4545 */    MCD_OPC_CheckPredicate, 3, 120, 13, 0, // Skip to: 7998
/* 4550 */    MCD_OPC_Decode, 133, 2, 10, // Opcode: ALIGNADDR
/* 4554 */    MCD_OPC_FilterValue, 25, 9, 0, 0, // Skip to: 4568
/* 4559 */    MCD_OPC_CheckPredicate, 4, 106, 13, 0, // Skip to: 7998
/* 4564 */    MCD_OPC_Decode, 154, 2, 10, // Opcode: BMASK
/* 4568 */    MCD_OPC_FilterValue, 26, 9, 0, 0, // Skip to: 4582
/* 4573 */    MCD_OPC_CheckPredicate, 3, 92, 13, 0, // Skip to: 7998
/* 4578 */    MCD_OPC_Decode, 134, 2, 10, // Opcode: ALIGNADDRL
/* 4582 */    MCD_OPC_FilterValue, 27, 23, 0, 0, // Skip to: 4610
/* 4587 */    MCD_OPC_CheckPredicate, 2, 78, 13, 0, // Skip to: 7998
/* 4592 */    MCD_OPC_CheckField, 25, 5, 0, 71, 13, 0, // Skip to: 7998
/* 4599 */    MCD_OPC_CheckField, 14, 5, 0, 64, 13, 0, // Skip to: 7998
/* 4606 */    MCD_OPC_Decode, 203, 2, 57, // Opcode: CMASK8
/* 4610 */    MCD_OPC_FilterValue, 28, 9, 0, 0, // Skip to: 4624
/* 4615 */    MCD_OPC_CheckPredicate, 4, 50, 13, 0, // Skip to: 7998
/* 4620 */    MCD_OPC_Decode, 191, 2, 36, // Opcode: BSHUFFLE
/* 4624 */    MCD_OPC_FilterValue, 29, 23, 0, 0, // Skip to: 4652
/* 4629 */    MCD_OPC_CheckPredicate, 2, 36, 13, 0, // Skip to: 7998
/* 4634 */    MCD_OPC_CheckField, 25, 5, 0, 29, 13, 0, // Skip to: 7998
/* 4641 */    MCD_OPC_CheckField, 14, 5, 0, 22, 13, 0, // Skip to: 7998
/* 4648 */    MCD_OPC_Decode, 201, 2, 57, // Opcode: CMASK16
/* 4652 */    MCD_OPC_FilterValue, 31, 23, 0, 0, // Skip to: 4680
/* 4657 */    MCD_OPC_CheckPredicate, 2, 8, 13, 0, // Skip to: 7998
/* 4662 */    MCD_OPC_CheckField, 25, 5, 0, 1, 13, 0, // Skip to: 7998
/* 4669 */    MCD_OPC_CheckField, 14, 5, 0, 250, 12, 0, // Skip to: 7998
/* 4676 */    MCD_OPC_Decode, 202, 2, 57, // Opcode: CMASK32
/* 4680 */    MCD_OPC_FilterValue, 32, 9, 0, 0, // Skip to: 4694
/* 4685 */    MCD_OPC_CheckPredicate, 3, 236, 12, 0, // Skip to: 7998
/* 4690 */    MCD_OPC_Decode, 239, 2, 58, // Opcode: FCMPLE16
/* 4694 */    MCD_OPC_FilterValue, 33, 9, 0, 0, // Skip to: 4708
/* 4699 */    MCD_OPC_CheckPredicate, 2, 222, 12, 0, // Skip to: 7998
/* 4704 */    MCD_OPC_Decode, 225, 3, 36, // Opcode: FSLL16
/* 4708 */    MCD_OPC_FilterValue, 34, 9, 0, 0, // Skip to: 4722
/* 4713 */    MCD_OPC_CheckPredicate, 3, 208, 12, 0, // Skip to: 7998
/* 4718 */    MCD_OPC_Decode, 241, 2, 58, // Opcode: FCMPNE16
/* 4722 */    MCD_OPC_FilterValue, 35, 9, 0, 0, // Skip to: 4736
/* 4727 */    MCD_OPC_CheckPredicate, 2, 194, 12, 0, // Skip to: 7998
/* 4732 */    MCD_OPC_Decode, 237, 3, 36, // Opcode: FSRL16
/* 4736 */    MCD_OPC_FilterValue, 36, 9, 0, 0, // Skip to: 4750
/* 4741 */    MCD_OPC_CheckPredicate, 3, 180, 12, 0, // Skip to: 7998
/* 4746 */    MCD_OPC_Decode, 240, 2, 58, // Opcode: FCMPLE32
/* 4750 */    MCD_OPC_FilterValue, 37, 9, 0, 0, // Skip to: 4764
/* 4755 */    MCD_OPC_CheckPredicate, 2, 166, 12, 0, // Skip to: 7998
/* 4760 */    MCD_OPC_Decode, 226, 3, 36, // Opcode: FSLL32
/* 4764 */    MCD_OPC_FilterValue, 38, 9, 0, 0, // Skip to: 4778
/* 4769 */    MCD_OPC_CheckPredicate, 3, 152, 12, 0, // Skip to: 7998
/* 4774 */    MCD_OPC_Decode, 242, 2, 58, // Opcode: FCMPNE32
/* 4778 */    MCD_OPC_FilterValue, 39, 9, 0, 0, // Skip to: 4792
/* 4783 */    MCD_OPC_CheckPredicate, 2, 138, 12, 0, // Skip to: 7998
/* 4788 */    MCD_OPC_Decode, 238, 3, 36, // Opcode: FSRL32
/* 4792 */    MCD_OPC_FilterValue, 40, 9, 0, 0, // Skip to: 4806
/* 4797 */    MCD_OPC_CheckPredicate, 3, 124, 12, 0, // Skip to: 7998
/* 4802 */    MCD_OPC_Decode, 237, 2, 58, // Opcode: FCMPGT16
/* 4806 */    MCD_OPC_FilterValue, 41, 9, 0, 0, // Skip to: 4820
/* 4811 */    MCD_OPC_CheckPredicate, 2, 110, 12, 0, // Skip to: 7998
/* 4816 */    MCD_OPC_Decode, 223, 3, 36, // Opcode: FSLAS16
/* 4820 */    MCD_OPC_FilterValue, 42, 9, 0, 0, // Skip to: 4834
/* 4825 */    MCD_OPC_CheckPredicate, 3, 96, 12, 0, // Skip to: 7998
/* 4830 */    MCD_OPC_Decode, 235, 2, 58, // Opcode: FCMPEQ16
/* 4834 */    MCD_OPC_FilterValue, 43, 9, 0, 0, // Skip to: 4848
/* 4839 */    MCD_OPC_CheckPredicate, 2, 82, 12, 0, // Skip to: 7998
/* 4844 */    MCD_OPC_Decode, 231, 3, 36, // Opcode: FSRA16
/* 4848 */    MCD_OPC_FilterValue, 44, 9, 0, 0, // Skip to: 4862
/* 4853 */    MCD_OPC_CheckPredicate, 3, 68, 12, 0, // Skip to: 7998
/* 4858 */    MCD_OPC_Decode, 238, 2, 58, // Opcode: FCMPGT32
/* 4862 */    MCD_OPC_FilterValue, 45, 9, 0, 0, // Skip to: 4876
/* 4867 */    MCD_OPC_CheckPredicate, 2, 54, 12, 0, // Skip to: 7998
/* 4872 */    MCD_OPC_Decode, 224, 3, 36, // Opcode: FSLAS32
/* 4876 */    MCD_OPC_FilterValue, 46, 9, 0, 0, // Skip to: 4890
/* 4881 */    MCD_OPC_CheckPredicate, 3, 40, 12, 0, // Skip to: 7998
/* 4886 */    MCD_OPC_Decode, 236, 2, 58, // Opcode: FCMPEQ32
/* 4890 */    MCD_OPC_FilterValue, 47, 9, 0, 0, // Skip to: 4904
/* 4895 */    MCD_OPC_CheckPredicate, 2, 26, 12, 0, // Skip to: 7998
/* 4900 */    MCD_OPC_Decode, 232, 3, 36, // Opcode: FSRA32
/* 4904 */    MCD_OPC_FilterValue, 49, 9, 0, 0, // Skip to: 4918
/* 4909 */    MCD_OPC_CheckPredicate, 3, 12, 12, 0, // Skip to: 7998
/* 4914 */    MCD_OPC_Decode, 172, 3, 36, // Opcode: FMUL8X16
/* 4918 */    MCD_OPC_FilterValue, 51, 9, 0, 0, // Skip to: 4932
/* 4923 */    MCD_OPC_CheckPredicate, 3, 254, 11, 0, // Skip to: 7998
/* 4928 */    MCD_OPC_Decode, 174, 3, 36, // Opcode: FMUL8X16AU
/* 4932 */    MCD_OPC_FilterValue, 53, 9, 0, 0, // Skip to: 4946
/* 4937 */    MCD_OPC_CheckPredicate, 3, 240, 11, 0, // Skip to: 7998
/* 4942 */    MCD_OPC_Decode, 173, 3, 36, // Opcode: FMUL8X16AL
/* 4946 */    MCD_OPC_FilterValue, 54, 9, 0, 0, // Skip to: 4960
/* 4951 */    MCD_OPC_CheckPredicate, 3, 226, 11, 0, // Skip to: 7998
/* 4956 */    MCD_OPC_Decode, 170, 3, 36, // Opcode: FMUL8SUX16
/* 4960 */    MCD_OPC_FilterValue, 55, 9, 0, 0, // Skip to: 4974
/* 4965 */    MCD_OPC_CheckPredicate, 3, 212, 11, 0, // Skip to: 7998
/* 4970 */    MCD_OPC_Decode, 171, 3, 36, // Opcode: FMUL8ULX16
/* 4974 */    MCD_OPC_FilterValue, 56, 9, 0, 0, // Skip to: 4988
/* 4979 */    MCD_OPC_CheckPredicate, 3, 198, 11, 0, // Skip to: 7998
/* 4984 */    MCD_OPC_Decode, 176, 3, 36, // Opcode: FMULD8SUX16
/* 4988 */    MCD_OPC_FilterValue, 57, 9, 0, 0, // Skip to: 5002
/* 4993 */    MCD_OPC_CheckPredicate, 3, 184, 11, 0, // Skip to: 7998
/* 4998 */    MCD_OPC_Decode, 177, 3, 36, // Opcode: FMULD8ULX16
/* 5002 */    MCD_OPC_FilterValue, 58, 9, 0, 0, // Skip to: 5016
/* 5007 */    MCD_OPC_CheckPredicate, 3, 170, 11, 0, // Skip to: 7998
/* 5012 */    MCD_OPC_Decode, 207, 3, 36, // Opcode: FPACK32
/* 5016 */    MCD_OPC_FilterValue, 59, 16, 0, 0, // Skip to: 5037
/* 5021 */    MCD_OPC_CheckPredicate, 3, 156, 11, 0, // Skip to: 7998
/* 5026 */    MCD_OPC_CheckField, 14, 5, 0, 149, 11, 0, // Skip to: 7998
/* 5033 */    MCD_OPC_Decode, 206, 3, 33, // Opcode: FPACK16
/* 5037 */    MCD_OPC_FilterValue, 61, 16, 0, 0, // Skip to: 5058
/* 5042 */    MCD_OPC_CheckPredicate, 3, 135, 11, 0, // Skip to: 7998
/* 5047 */    MCD_OPC_CheckField, 14, 5, 0, 128, 11, 0, // Skip to: 7998
/* 5054 */    MCD_OPC_Decode, 208, 3, 33, // Opcode: FPACKFIX
/* 5058 */    MCD_OPC_FilterValue, 62, 9, 0, 0, // Skip to: 5072
/* 5063 */    MCD_OPC_CheckPredicate, 3, 114, 11, 0, // Skip to: 7998
/* 5068 */    MCD_OPC_Decode, 216, 4, 36, // Opcode: PDIST
/* 5072 */    MCD_OPC_FilterValue, 63, 9, 0, 0, // Skip to: 5086
/* 5077 */    MCD_OPC_CheckPredicate, 2, 100, 11, 0, // Skip to: 7998
/* 5082 */    MCD_OPC_Decode, 217, 4, 36, // Opcode: PDISTN
/* 5086 */    MCD_OPC_FilterValue, 64, 9, 0, 0, // Skip to: 5100
/* 5091 */    MCD_OPC_CheckPredicate, 2, 86, 11, 0, // Skip to: 7998
/* 5096 */    MCD_OPC_Decode, 139, 3, 36, // Opcode: FMEAN16
/* 5100 */    MCD_OPC_FilterValue, 66, 9, 0, 0, // Skip to: 5114
/* 5105 */    MCD_OPC_CheckPredicate, 2, 72, 11, 0, // Skip to: 7998
/* 5110 */    MCD_OPC_Decode, 213, 3, 36, // Opcode: FPADD64
/* 5114 */    MCD_OPC_FilterValue, 68, 9, 0, 0, // Skip to: 5128
/* 5119 */    MCD_OPC_CheckPredicate, 2, 58, 11, 0, // Skip to: 7998
/* 5124 */    MCD_OPC_Decode, 233, 2, 36, // Opcode: FCHKSM16
/* 5128 */    MCD_OPC_FilterValue, 72, 9, 0, 0, // Skip to: 5142
/* 5133 */    MCD_OPC_CheckPredicate, 3, 44, 11, 0, // Skip to: 7998
/* 5138 */    MCD_OPC_Decode, 224, 2, 36, // Opcode: FALIGNADATA
/* 5142 */    MCD_OPC_FilterValue, 75, 9, 0, 0, // Skip to: 5156
/* 5147 */    MCD_OPC_CheckPredicate, 3, 30, 11, 0, // Skip to: 7998
/* 5152 */    MCD_OPC_Decode, 214, 3, 36, // Opcode: FPMERGE
/* 5156 */    MCD_OPC_FilterValue, 77, 16, 0, 0, // Skip to: 5177
/* 5161 */    MCD_OPC_CheckPredicate, 3, 16, 11, 0, // Skip to: 7998
/* 5166 */    MCD_OPC_CheckField, 14, 5, 0, 9, 11, 0, // Skip to: 7998
/* 5173 */    MCD_OPC_Decode, 253, 2, 33, // Opcode: FEXPAND
/* 5177 */    MCD_OPC_FilterValue, 80, 9, 0, 0, // Skip to: 5191
/* 5182 */    MCD_OPC_CheckPredicate, 3, 251, 10, 0, // Skip to: 7998
/* 5187 */    MCD_OPC_Decode, 209, 3, 36, // Opcode: FPADD16
/* 5191 */    MCD_OPC_FilterValue, 81, 9, 0, 0, // Skip to: 5205
/* 5196 */    MCD_OPC_CheckPredicate, 3, 237, 10, 0, // Skip to: 7998
/* 5201 */    MCD_OPC_Decode, 210, 3, 36, // Opcode: FPADD16S
/* 5205 */    MCD_OPC_FilterValue, 82, 9, 0, 0, // Skip to: 5219
/* 5210 */    MCD_OPC_CheckPredicate, 3, 223, 10, 0, // Skip to: 7998
/* 5215 */    MCD_OPC_Decode, 211, 3, 36, // Opcode: FPADD32
/* 5219 */    MCD_OPC_FilterValue, 83, 9, 0, 0, // Skip to: 5233
/* 5224 */    MCD_OPC_CheckPredicate, 3, 209, 10, 0, // Skip to: 7998
/* 5229 */    MCD_OPC_Decode, 212, 3, 36, // Opcode: FPADD32S
/* 5233 */    MCD_OPC_FilterValue, 84, 9, 0, 0, // Skip to: 5247
/* 5238 */    MCD_OPC_CheckPredicate, 3, 195, 10, 0, // Skip to: 7998
/* 5243 */    MCD_OPC_Decode, 215, 3, 36, // Opcode: FPSUB16
/* 5247 */    MCD_OPC_FilterValue, 85, 9, 0, 0, // Skip to: 5261
/* 5252 */    MCD_OPC_CheckPredicate, 3, 181, 10, 0, // Skip to: 7998
/* 5257 */    MCD_OPC_Decode, 216, 3, 36, // Opcode: FPSUB16S
/* 5261 */    MCD_OPC_FilterValue, 86, 9, 0, 0, // Skip to: 5275
/* 5266 */    MCD_OPC_CheckPredicate, 3, 167, 10, 0, // Skip to: 7998
/* 5271 */    MCD_OPC_Decode, 217, 3, 36, // Opcode: FPSUB32
/* 5275 */    MCD_OPC_FilterValue, 87, 9, 0, 0, // Skip to: 5289
/* 5280 */    MCD_OPC_CheckPredicate, 3, 153, 10, 0, // Skip to: 7998
/* 5285 */    MCD_OPC_Decode, 218, 3, 36, // Opcode: FPSUB32S
/* 5289 */    MCD_OPC_FilterValue, 96, 23, 0, 0, // Skip to: 5317
/* 5294 */    MCD_OPC_CheckPredicate, 3, 139, 10, 0, // Skip to: 7998
/* 5299 */    MCD_OPC_CheckField, 14, 5, 0, 132, 10, 0, // Skip to: 7998
/* 5306 */    MCD_OPC_CheckField, 0, 5, 0, 125, 10, 0, // Skip to: 7998
/* 5313 */    MCD_OPC_Decode, 253, 3, 59, // Opcode: FZERO
/* 5317 */    MCD_OPC_FilterValue, 97, 23, 0, 0, // Skip to: 5345
/* 5322 */    MCD_OPC_CheckPredicate, 3, 111, 10, 0, // Skip to: 7998
/* 5327 */    MCD_OPC_CheckField, 14, 5, 0, 104, 10, 0, // Skip to: 7998
/* 5334 */    MCD_OPC_CheckField, 0, 5, 0, 97, 10, 0, // Skip to: 7998
/* 5341 */    MCD_OPC_Decode, 254, 3, 60, // Opcode: FZEROS
/* 5345 */    MCD_OPC_FilterValue, 98, 9, 0, 0, // Skip to: 5359
/* 5350 */    MCD_OPC_CheckPredicate, 3, 83, 10, 0, // Skip to: 7998
/* 5355 */    MCD_OPC_Decode, 191, 3, 36, // Opcode: FNOR
/* 5359 */    MCD_OPC_FilterValue, 99, 9, 0, 0, // Skip to: 5373
/* 5364 */    MCD_OPC_CheckPredicate, 3, 69, 10, 0, // Skip to: 7998
/* 5369 */    MCD_OPC_Decode, 192, 3, 35, // Opcode: FNORS
/* 5373 */    MCD_OPC_FilterValue, 100, 9, 0, 0, // Skip to: 5387
/* 5378 */    MCD_OPC_CheckPredicate, 3, 55, 10, 0, // Skip to: 7998
/* 5383 */    MCD_OPC_Decode, 228, 2, 36, // Opcode: FANDNOT2
/* 5387 */    MCD_OPC_FilterValue, 101, 9, 0, 0, // Skip to: 5401
/* 5392 */    MCD_OPC_CheckPredicate, 3, 41, 10, 0, // Skip to: 7998
/* 5397 */    MCD_OPC_Decode, 229, 2, 35, // Opcode: FANDNOT2S
/* 5401 */    MCD_OPC_FilterValue, 102, 16, 0, 0, // Skip to: 5422
/* 5406 */    MCD_OPC_CheckPredicate, 3, 27, 10, 0, // Skip to: 7998
/* 5411 */    MCD_OPC_CheckField, 14, 5, 0, 20, 10, 0, // Skip to: 7998
/* 5418 */    MCD_OPC_Decode, 195, 3, 33, // Opcode: FNOT2
/* 5422 */    MCD_OPC_FilterValue, 103, 16, 0, 0, // Skip to: 5443
/* 5427 */    MCD_OPC_CheckPredicate, 3, 6, 10, 0, // Skip to: 7998
/* 5432 */    MCD_OPC_CheckField, 14, 5, 0, 255, 9, 0, // Skip to: 7998
/* 5439 */    MCD_OPC_Decode, 196, 3, 32, // Opcode: FNOT2S
/* 5443 */    MCD_OPC_FilterValue, 104, 9, 0, 0, // Skip to: 5457
/* 5448 */    MCD_OPC_CheckPredicate, 3, 241, 9, 0, // Skip to: 7998
/* 5453 */    MCD_OPC_Decode, 226, 2, 36, // Opcode: FANDNOT1
/* 5457 */    MCD_OPC_FilterValue, 105, 9, 0, 0, // Skip to: 5471
/* 5462 */    MCD_OPC_CheckPredicate, 3, 227, 9, 0, // Skip to: 7998
/* 5467 */    MCD_OPC_Decode, 227, 2, 35, // Opcode: FANDNOT1S
/* 5471 */    MCD_OPC_FilterValue, 106, 16, 0, 0, // Skip to: 5492
/* 5476 */    MCD_OPC_CheckPredicate, 3, 213, 9, 0, // Skip to: 7998
/* 5481 */    MCD_OPC_CheckField, 0, 5, 0, 206, 9, 0, // Skip to: 7998
/* 5488 */    MCD_OPC_Decode, 193, 3, 61, // Opcode: FNOT1
/* 5492 */    MCD_OPC_FilterValue, 107, 16, 0, 0, // Skip to: 5513
/* 5497 */    MCD_OPC_CheckPredicate, 3, 192, 9, 0, // Skip to: 7998
/* 5502 */    MCD_OPC_CheckField, 0, 5, 0, 185, 9, 0, // Skip to: 7998
/* 5509 */    MCD_OPC_Decode, 194, 3, 62, // Opcode: FNOT1S
/* 5513 */    MCD_OPC_FilterValue, 108, 9, 0, 0, // Skip to: 5527
/* 5518 */    MCD_OPC_CheckPredicate, 3, 171, 9, 0, // Skip to: 7998
/* 5523 */    MCD_OPC_Decode, 248, 3, 36, // Opcode: FXOR
/* 5527 */    MCD_OPC_FilterValue, 109, 9, 0, 0, // Skip to: 5541
/* 5532 */    MCD_OPC_CheckPredicate, 3, 157, 9, 0, // Skip to: 7998
/* 5537 */    MCD_OPC_Decode, 249, 3, 35, // Opcode: FXORS
/* 5541 */    MCD_OPC_FilterValue, 110, 9, 0, 0, // Skip to: 5555
/* 5546 */    MCD_OPC_CheckPredicate, 3, 143, 9, 0, // Skip to: 7998
/* 5551 */    MCD_OPC_Decode, 182, 3, 36, // Opcode: FNAND
/* 5555 */    MCD_OPC_FilterValue, 111, 9, 0, 0, // Skip to: 5569
/* 5560 */    MCD_OPC_CheckPredicate, 3, 129, 9, 0, // Skip to: 7998
/* 5565 */    MCD_OPC_Decode, 183, 3, 35, // Opcode: FNANDS
/* 5569 */    MCD_OPC_FilterValue, 112, 9, 0, 0, // Skip to: 5583
/* 5574 */    MCD_OPC_CheckPredicate, 3, 115, 9, 0, // Skip to: 7998
/* 5579 */    MCD_OPC_Decode, 225, 2, 36, // Opcode: FAND
/* 5583 */    MCD_OPC_FilterValue, 113, 9, 0, 0, // Skip to: 5597
/* 5588 */    MCD_OPC_CheckPredicate, 3, 101, 9, 0, // Skip to: 7998
/* 5593 */    MCD_OPC_Decode, 230, 2, 35, // Opcode: FANDS
/* 5597 */    MCD_OPC_FilterValue, 114, 9, 0, 0, // Skip to: 5611
/* 5602 */    MCD_OPC_CheckPredicate, 3, 87, 9, 0, // Skip to: 7998
/* 5607 */    MCD_OPC_Decode, 246, 3, 36, // Opcode: FXNOR
/* 5611 */    MCD_OPC_FilterValue, 115, 9, 0, 0, // Skip to: 5625
/* 5616 */    MCD_OPC_CheckPredicate, 3, 73, 9, 0, // Skip to: 7998
/* 5621 */    MCD_OPC_Decode, 247, 3, 35, // Opcode: FXNORS
/* 5625 */    MCD_OPC_FilterValue, 116, 16, 0, 0, // Skip to: 5646
/* 5630 */    MCD_OPC_CheckPredicate, 3, 59, 9, 0, // Skip to: 7998
/* 5635 */    MCD_OPC_CheckField, 0, 5, 0, 52, 9, 0, // Skip to: 7998
/* 5642 */    MCD_OPC_Decode, 233, 3, 61, // Opcode: FSRC1
/* 5646 */    MCD_OPC_FilterValue, 117, 16, 0, 0, // Skip to: 5667
/* 5651 */    MCD_OPC_CheckPredicate, 3, 38, 9, 0, // Skip to: 7998
/* 5656 */    MCD_OPC_CheckField, 0, 5, 0, 31, 9, 0, // Skip to: 7998
/* 5663 */    MCD_OPC_Decode, 234, 3, 62, // Opcode: FSRC1S
/* 5667 */    MCD_OPC_FilterValue, 118, 9, 0, 0, // Skip to: 5681
/* 5672 */    MCD_OPC_CheckPredicate, 3, 17, 9, 0, // Skip to: 7998
/* 5677 */    MCD_OPC_Decode, 203, 3, 36, // Opcode: FORNOT2
/* 5681 */    MCD_OPC_FilterValue, 119, 9, 0, 0, // Skip to: 5695
/* 5686 */    MCD_OPC_CheckPredicate, 3, 3, 9, 0, // Skip to: 7998
/* 5691 */    MCD_OPC_Decode, 204, 3, 35, // Opcode: FORNOT2S
/* 5695 */    MCD_OPC_FilterValue, 120, 16, 0, 0, // Skip to: 5716
/* 5700 */    MCD_OPC_CheckPredicate, 3, 245, 8, 0, // Skip to: 7998
/* 5705 */    MCD_OPC_CheckField, 14, 5, 0, 238, 8, 0, // Skip to: 7998
/* 5712 */    MCD_OPC_Decode, 235, 3, 33, // Opcode: FSRC2
/* 5716 */    MCD_OPC_FilterValue, 121, 16, 0, 0, // Skip to: 5737
/* 5721 */    MCD_OPC_CheckPredicate, 3, 224, 8, 0, // Skip to: 7998
/* 5726 */    MCD_OPC_CheckField, 14, 5, 0, 217, 8, 0, // Skip to: 7998
/* 5733 */    MCD_OPC_Decode, 236, 3, 32, // Opcode: FSRC2S
/* 5737 */    MCD_OPC_FilterValue, 122, 9, 0, 0, // Skip to: 5751
/* 5742 */    MCD_OPC_CheckPredicate, 3, 203, 8, 0, // Skip to: 7998
/* 5747 */    MCD_OPC_Decode, 201, 3, 36, // Opcode: FORNOT1
/* 5751 */    MCD_OPC_FilterValue, 123, 9, 0, 0, // Skip to: 5765
/* 5756 */    MCD_OPC_CheckPredicate, 3, 189, 8, 0, // Skip to: 7998
/* 5761 */    MCD_OPC_Decode, 202, 3, 35, // Opcode: FORNOT1S
/* 5765 */    MCD_OPC_FilterValue, 124, 9, 0, 0, // Skip to: 5779
/* 5770 */    MCD_OPC_CheckPredicate, 3, 175, 8, 0, // Skip to: 7998
/* 5775 */    MCD_OPC_Decode, 200, 3, 36, // Opcode: FOR
/* 5779 */    MCD_OPC_FilterValue, 125, 9, 0, 0, // Skip to: 5793
/* 5784 */    MCD_OPC_CheckPredicate, 3, 161, 8, 0, // Skip to: 7998
/* 5789 */    MCD_OPC_Decode, 205, 3, 35, // Opcode: FORS
/* 5793 */    MCD_OPC_FilterValue, 126, 23, 0, 0, // Skip to: 5821
/* 5798 */    MCD_OPC_CheckPredicate, 3, 147, 8, 0, // Skip to: 7998
/* 5803 */    MCD_OPC_CheckField, 14, 5, 0, 140, 8, 0, // Skip to: 7998
/* 5810 */    MCD_OPC_CheckField, 0, 5, 0, 133, 8, 0, // Skip to: 7998
/* 5817 */    MCD_OPC_Decode, 198, 3, 59, // Opcode: FONE
/* 5821 */    MCD_OPC_FilterValue, 127, 23, 0, 0, // Skip to: 5849
/* 5826 */    MCD_OPC_CheckPredicate, 3, 119, 8, 0, // Skip to: 7998
/* 5831 */    MCD_OPC_CheckField, 14, 5, 0, 112, 8, 0, // Skip to: 7998
/* 5838 */    MCD_OPC_CheckField, 0, 5, 0, 105, 8, 0, // Skip to: 7998
/* 5845 */    MCD_OPC_Decode, 199, 3, 60, // Opcode: FONES
/* 5849 */    MCD_OPC_FilterValue, 128, 1, 30, 0, 0, // Skip to: 5885
/* 5855 */    MCD_OPC_CheckPredicate, 3, 90, 8, 0, // Skip to: 7998
/* 5860 */    MCD_OPC_CheckField, 25, 5, 0, 83, 8, 0, // Skip to: 7998
/* 5867 */    MCD_OPC_CheckField, 14, 5, 0, 76, 8, 0, // Skip to: 7998
/* 5874 */    MCD_OPC_CheckField, 0, 5, 0, 69, 8, 0, // Skip to: 7998
/* 5881 */    MCD_OPC_Decode, 242, 4, 4, // Opcode: SHUTDOWN
/* 5885 */    MCD_OPC_FilterValue, 129, 1, 30, 0, 0, // Skip to: 5921
/* 5891 */    MCD_OPC_CheckPredicate, 4, 54, 8, 0, // Skip to: 7998
/* 5896 */    MCD_OPC_CheckField, 25, 5, 0, 47, 8, 0, // Skip to: 7998
/* 5903 */    MCD_OPC_CheckField, 14, 5, 0, 40, 8, 0, // Skip to: 7998
/* 5910 */    MCD_OPC_CheckField, 0, 5, 0, 33, 8, 0, // Skip to: 7998
/* 5917 */    MCD_OPC_Decode, 243, 4, 4, // Opcode: SIAM
/* 5921 */    MCD_OPC_FilterValue, 144, 2, 16, 0, 0, // Skip to: 5943
/* 5927 */    MCD_OPC_CheckPredicate, 2, 18, 8, 0, // Skip to: 7998
/* 5932 */    MCD_OPC_CheckField, 14, 5, 0, 11, 8, 0, // Skip to: 7998
/* 5939 */    MCD_OPC_Decode, 177, 4, 63, // Opcode: MOVDTOX
/* 5943 */    MCD_OPC_FilterValue, 145, 2, 16, 0, 0, // Skip to: 5965
/* 5949 */    MCD_OPC_CheckPredicate, 2, 252, 7, 0, // Skip to: 7998
/* 5954 */    MCD_OPC_CheckField, 14, 5, 0, 245, 7, 0, // Skip to: 7998
/* 5961 */    MCD_OPC_Decode, 195, 4, 63, // Opcode: MOVSTOUW
/* 5965 */    MCD_OPC_FilterValue, 147, 2, 16, 0, 0, // Skip to: 5987
/* 5971 */    MCD_OPC_CheckPredicate, 2, 230, 7, 0, // Skip to: 7998
/* 5976 */    MCD_OPC_CheckField, 14, 5, 0, 223, 7, 0, // Skip to: 7998
/* 5983 */    MCD_OPC_Decode, 194, 4, 63, // Opcode: MOVSTOSW
/* 5987 */    MCD_OPC_FilterValue, 149, 2, 9, 0, 0, // Skip to: 6002
/* 5993 */    MCD_OPC_CheckPredicate, 2, 208, 7, 0, // Skip to: 7998
/* 5998 */    MCD_OPC_Decode, 243, 5, 10, // Opcode: XMULX
/* 6002 */    MCD_OPC_FilterValue, 151, 2, 9, 0, 0, // Skip to: 6017
/* 6008 */    MCD_OPC_CheckPredicate, 2, 193, 7, 0, // Skip to: 7998
/* 6013 */    MCD_OPC_Decode, 244, 5, 10, // Opcode: XMULXHI
/* 6017 */    MCD_OPC_FilterValue, 152, 2, 16, 0, 0, // Skip to: 6039
/* 6023 */    MCD_OPC_CheckPredicate, 2, 178, 7, 0, // Skip to: 7998
/* 6028 */    MCD_OPC_CheckField, 14, 5, 0, 171, 7, 0, // Skip to: 7998
/* 6035 */    MCD_OPC_Decode, 199, 4, 64, // Opcode: MOVXTOD
/* 6039 */    MCD_OPC_FilterValue, 153, 2, 16, 0, 0, // Skip to: 6061
/* 6045 */    MCD_OPC_CheckPredicate, 2, 156, 7, 0, // Skip to: 7998
/* 6050 */    MCD_OPC_CheckField, 14, 5, 0, 149, 7, 0, // Skip to: 7998
/* 6057 */    MCD_OPC_Decode, 196, 4, 64, // Opcode: MOVWTOS
/* 6061 */    MCD_OPC_FilterValue, 209, 2, 9, 0, 0, // Skip to: 6076
/* 6067 */    MCD_OPC_CheckPredicate, 2, 134, 7, 0, // Skip to: 7998
/* 6072 */    MCD_OPC_Decode, 134, 3, 54, // Opcode: FLCMPS
/* 6076 */    MCD_OPC_FilterValue, 210, 2, 124, 7, 0, // Skip to: 7998
/* 6082 */    MCD_OPC_CheckPredicate, 2, 119, 7, 0, // Skip to: 7998
/* 6087 */    MCD_OPC_Decode, 133, 3, 54, // Opcode: FLCMPD
/* 6091 */    MCD_OPC_FilterValue, 56, 28, 0, 0, // Skip to: 6124
/* 6096 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6099 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6115
/* 6104 */    MCD_OPC_CheckField, 5, 8, 0, 95, 7, 0, // Skip to: 7998
/* 6111 */    MCD_OPC_Decode, 128, 4, 65, // Opcode: JMPLrr
/* 6115 */    MCD_OPC_FilterValue, 1, 86, 7, 0, // Skip to: 7998
/* 6120 */    MCD_OPC_Decode, 255, 3, 65, // Opcode: JMPLri
/* 6124 */    MCD_OPC_FilterValue, 57, 42, 0, 0, // Skip to: 6171
/* 6129 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6132 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 6155
/* 6137 */    MCD_OPC_CheckField, 25, 5, 0, 62, 7, 0, // Skip to: 7998
/* 6144 */    MCD_OPC_CheckField, 5, 8, 0, 55, 7, 0, // Skip to: 7998
/* 6151 */    MCD_OPC_Decode, 231, 4, 66, // Opcode: RETTrr
/* 6155 */    MCD_OPC_FilterValue, 1, 46, 7, 0, // Skip to: 7998
/* 6160 */    MCD_OPC_CheckField, 25, 5, 0, 39, 7, 0, // Skip to: 7998
/* 6167 */    MCD_OPC_Decode, 230, 4, 66, // Opcode: RETTri
/* 6171 */    MCD_OPC_FilterValue, 58, 119, 0, 0, // Skip to: 6295
/* 6176 */    MCD_OPC_ExtractField, 8, 6,  // Inst{13-8} ...
/* 6179 */    MCD_OPC_FilterValue, 16, 18, 0, 0, // Skip to: 6202
/* 6184 */    MCD_OPC_CheckField, 29, 1, 0, 15, 7, 0, // Skip to: 7998
/* 6191 */    MCD_OPC_CheckField, 5, 3, 0, 8, 7, 0, // Skip to: 7998
/* 6198 */    MCD_OPC_Decode, 207, 5, 67, // Opcode: TXCCrr
/* 6202 */    MCD_OPC_FilterValue, 32, 72, 0, 0, // Skip to: 6279
/* 6207 */    MCD_OPC_ExtractField, 0, 8,  // Inst{7-0} ...
/* 6210 */    MCD_OPC_FilterValue, 1, 18, 0, 0, // Skip to: 6233
/* 6215 */    MCD_OPC_CheckField, 25, 5, 8, 240, 6, 0, // Skip to: 7998
/* 6222 */    MCD_OPC_CheckField, 14, 5, 0, 233, 6, 0, // Skip to: 7998
/* 6229 */    MCD_OPC_Decode, 186, 5, 4, // Opcode: TA1
/* 6233 */    MCD_OPC_FilterValue, 3, 18, 0, 0, // Skip to: 6256
/* 6238 */    MCD_OPC_CheckField, 25, 5, 8, 217, 6, 0, // Skip to: 7998
/* 6245 */    MCD_OPC_CheckField, 14, 5, 0, 210, 6, 0, // Skip to: 7998
/* 6252 */    MCD_OPC_Decode, 187, 5, 4, // Opcode: TA3
/* 6256 */    MCD_OPC_FilterValue, 5, 201, 6, 0, // Skip to: 7998
/* 6261 */    MCD_OPC_CheckField, 25, 5, 8, 194, 6, 0, // Skip to: 7998
/* 6268 */    MCD_OPC_CheckField, 14, 5, 0, 187, 6, 0, // Skip to: 7998
/* 6275 */    MCD_OPC_Decode, 188, 5, 4, // Opcode: TA5
/* 6279 */    MCD_OPC_FilterValue, 48, 178, 6, 0, // Skip to: 7998
/* 6284 */    MCD_OPC_CheckField, 29, 1, 0, 171, 6, 0, // Skip to: 7998
/* 6291 */    MCD_OPC_Decode, 206, 5, 68, // Opcode: TXCCri
/* 6295 */    MCD_OPC_FilterValue, 59, 62, 0, 0, // Skip to: 6362
/* 6300 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6303 */    MCD_OPC_FilterValue, 0, 38, 0, 0, // Skip to: 6346
/* 6308 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 6311 */    MCD_OPC_FilterValue, 0, 146, 6, 0, // Skip to: 7998
/* 6316 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 6319 */    MCD_OPC_FilterValue, 0, 138, 6, 0, // Skip to: 7998
/* 6324 */    MCD_OPC_CheckField, 14, 5, 0, 11, 0, 0, // Skip to: 6342
/* 6331 */    MCD_OPC_CheckField, 0, 5, 0, 4, 0, 0, // Skip to: 6342
/* 6338 */    MCD_OPC_Decode, 135, 3, 4, // Opcode: FLUSH
/* 6342 */    MCD_OPC_Decode, 138, 3, 4, // Opcode: FLUSHrr
/* 6346 */    MCD_OPC_FilterValue, 1, 111, 6, 0, // Skip to: 7998
/* 6351 */    MCD_OPC_CheckField, 25, 5, 0, 104, 6, 0, // Skip to: 7998
/* 6358 */    MCD_OPC_Decode, 137, 3, 4, // Opcode: FLUSHri
/* 6362 */    MCD_OPC_FilterValue, 60, 28, 0, 0, // Skip to: 6395
/* 6367 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6370 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6386
/* 6375 */    MCD_OPC_CheckField, 5, 8, 0, 80, 6, 0, // Skip to: 7998
/* 6382 */    MCD_OPC_Decode, 233, 4, 8, // Opcode: SAVErr
/* 6386 */    MCD_OPC_FilterValue, 1, 71, 6, 0, // Skip to: 7998
/* 6391 */    MCD_OPC_Decode, 232, 4, 9, // Opcode: SAVEri
/* 6395 */    MCD_OPC_FilterValue, 61, 28, 0, 0, // Skip to: 6428
/* 6400 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6403 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6419
/* 6408 */    MCD_OPC_CheckField, 5, 8, 0, 47, 6, 0, // Skip to: 7998
/* 6415 */    MCD_OPC_Decode, 227, 4, 8, // Opcode: RESTORErr
/* 6419 */    MCD_OPC_FilterValue, 1, 38, 6, 0, // Skip to: 7998
/* 6424 */    MCD_OPC_Decode, 226, 4, 9, // Opcode: RESTOREri
/* 6428 */    MCD_OPC_FilterValue, 62, 28, 0, 0, // Skip to: 6461
/* 6433 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6436 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6452
/* 6441 */    MCD_OPC_CheckField, 5, 8, 0, 14, 6, 0, // Skip to: 7998
/* 6448 */    MCD_OPC_Decode, 215, 5, 8, // Opcode: UMACrr
/* 6452 */    MCD_OPC_FilterValue, 1, 5, 6, 0, // Skip to: 7998
/* 6457 */    MCD_OPC_Decode, 214, 5, 9, // Opcode: UMACri
/* 6461 */    MCD_OPC_FilterValue, 63, 252, 5, 0, // Skip to: 7998
/* 6466 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6469 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6485
/* 6474 */    MCD_OPC_CheckField, 5, 8, 0, 237, 5, 0, // Skip to: 7998
/* 6481 */    MCD_OPC_Decode, 250, 4, 8, // Opcode: SMACrr
/* 6485 */    MCD_OPC_FilterValue, 1, 228, 5, 0, // Skip to: 7998
/* 6490 */    MCD_OPC_Decode, 249, 4, 9, // Opcode: SMACri
/* 6494 */    MCD_OPC_FilterValue, 3, 219, 5, 0, // Skip to: 7998
/* 6499 */    MCD_OPC_ExtractField, 19, 6,  // Inst{24-19} ...
/* 6502 */    MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 6535
/* 6507 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6510 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6526
/* 6515 */    MCD_OPC_CheckField, 5, 8, 0, 196, 5, 0, // Skip to: 7998
/* 6522 */    MCD_OPC_Decode, 172, 4, 69, // Opcode: LDrr
/* 6526 */    MCD_OPC_FilterValue, 1, 187, 5, 0, // Skip to: 7998
/* 6531 */    MCD_OPC_Decode, 171, 4, 69, // Opcode: LDri
/* 6535 */    MCD_OPC_FilterValue, 1, 28, 0, 0, // Skip to: 6568
/* 6540 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6543 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6559
/* 6548 */    MCD_OPC_CheckField, 5, 8, 0, 163, 5, 0, // Skip to: 7998
/* 6555 */    MCD_OPC_Decode, 163, 4, 69, // Opcode: LDUBrr
/* 6559 */    MCD_OPC_FilterValue, 1, 154, 5, 0, // Skip to: 7998
/* 6564 */    MCD_OPC_Decode, 162, 4, 69, // Opcode: LDUBri
/* 6568 */    MCD_OPC_FilterValue, 2, 28, 0, 0, // Skip to: 6601
/* 6573 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6576 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6592
/* 6581 */    MCD_OPC_CheckField, 5, 8, 0, 130, 5, 0, // Skip to: 7998
/* 6588 */    MCD_OPC_Decode, 166, 4, 69, // Opcode: LDUHrr
/* 6592 */    MCD_OPC_FilterValue, 1, 121, 5, 0, // Skip to: 7998
/* 6597 */    MCD_OPC_Decode, 165, 4, 69, // Opcode: LDUHri
/* 6601 */    MCD_OPC_FilterValue, 3, 28, 0, 0, // Skip to: 6634
/* 6606 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6609 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6625
/* 6614 */    MCD_OPC_CheckField, 5, 8, 0, 97, 5, 0, // Skip to: 7998
/* 6621 */    MCD_OPC_Decode, 141, 4, 70, // Opcode: LDDrr
/* 6625 */    MCD_OPC_FilterValue, 1, 88, 5, 0, // Skip to: 7998
/* 6630 */    MCD_OPC_Decode, 140, 4, 70, // Opcode: LDDri
/* 6634 */    MCD_OPC_FilterValue, 4, 28, 0, 0, // Skip to: 6667
/* 6639 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6642 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6658
/* 6647 */    MCD_OPC_CheckField, 5, 8, 0, 64, 5, 0, // Skip to: 7998
/* 6654 */    MCD_OPC_Decode, 172, 5, 71, // Opcode: STrr
/* 6658 */    MCD_OPC_FilterValue, 1, 55, 5, 0, // Skip to: 7998
/* 6663 */    MCD_OPC_Decode, 171, 5, 71, // Opcode: STri
/* 6667 */    MCD_OPC_FilterValue, 5, 28, 0, 0, // Skip to: 6700
/* 6672 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6675 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6691
/* 6680 */    MCD_OPC_CheckField, 5, 8, 0, 31, 5, 0, // Skip to: 7998
/* 6687 */    MCD_OPC_Decode, 139, 5, 71, // Opcode: STBrr
/* 6691 */    MCD_OPC_FilterValue, 1, 22, 5, 0, // Skip to: 7998
/* 6696 */    MCD_OPC_Decode, 138, 5, 71, // Opcode: STBri
/* 6700 */    MCD_OPC_FilterValue, 6, 28, 0, 0, // Skip to: 6733
/* 6705 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6708 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6724
/* 6713 */    MCD_OPC_CheckField, 5, 8, 0, 254, 4, 0, // Skip to: 7998
/* 6720 */    MCD_OPC_Decode, 163, 5, 71, // Opcode: STHrr
/* 6724 */    MCD_OPC_FilterValue, 1, 245, 4, 0, // Skip to: 7998
/* 6729 */    MCD_OPC_Decode, 162, 5, 71, // Opcode: STHri
/* 6733 */    MCD_OPC_FilterValue, 7, 28, 0, 0, // Skip to: 6766
/* 6738 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6741 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6757
/* 6746 */    MCD_OPC_CheckField, 5, 8, 0, 221, 4, 0, // Skip to: 7998
/* 6753 */    MCD_OPC_Decode, 155, 5, 72, // Opcode: STDrr
/* 6757 */    MCD_OPC_FilterValue, 1, 212, 4, 0, // Skip to: 7998
/* 6762 */    MCD_OPC_Decode, 154, 5, 72, // Opcode: STDri
/* 6766 */    MCD_OPC_FilterValue, 8, 28, 0, 0, // Skip to: 6799
/* 6771 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6774 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6790
/* 6779 */    MCD_OPC_CheckField, 5, 8, 0, 188, 4, 0, // Skip to: 7998
/* 6786 */    MCD_OPC_Decode, 160, 4, 69, // Opcode: LDSWrr
/* 6790 */    MCD_OPC_FilterValue, 1, 179, 4, 0, // Skip to: 7998
/* 6795 */    MCD_OPC_Decode, 159, 4, 69, // Opcode: LDSWri
/* 6799 */    MCD_OPC_FilterValue, 9, 28, 0, 0, // Skip to: 6832
/* 6804 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6807 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6823
/* 6812 */    MCD_OPC_CheckField, 5, 8, 0, 155, 4, 0, // Skip to: 7998
/* 6819 */    MCD_OPC_Decode, 152, 4, 69, // Opcode: LDSBrr
/* 6823 */    MCD_OPC_FilterValue, 1, 146, 4, 0, // Skip to: 7998
/* 6828 */    MCD_OPC_Decode, 151, 4, 69, // Opcode: LDSBri
/* 6832 */    MCD_OPC_FilterValue, 10, 28, 0, 0, // Skip to: 6865
/* 6837 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6840 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6856
/* 6845 */    MCD_OPC_CheckField, 5, 8, 0, 122, 4, 0, // Skip to: 7998
/* 6852 */    MCD_OPC_Decode, 155, 4, 69, // Opcode: LDSHrr
/* 6856 */    MCD_OPC_FilterValue, 1, 113, 4, 0, // Skip to: 7998
/* 6861 */    MCD_OPC_Decode, 154, 4, 69, // Opcode: LDSHri
/* 6865 */    MCD_OPC_FilterValue, 11, 28, 0, 0, // Skip to: 6898
/* 6870 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6873 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6889
/* 6878 */    MCD_OPC_CheckField, 5, 8, 0, 89, 4, 0, // Skip to: 7998
/* 6885 */    MCD_OPC_Decode, 170, 4, 69, // Opcode: LDXrr
/* 6889 */    MCD_OPC_FilterValue, 1, 80, 4, 0, // Skip to: 7998
/* 6894 */    MCD_OPC_Decode, 169, 4, 69, // Opcode: LDXri
/* 6898 */    MCD_OPC_FilterValue, 13, 28, 0, 0, // Skip to: 6931
/* 6903 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6906 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6922
/* 6911 */    MCD_OPC_CheckField, 5, 8, 0, 56, 4, 0, // Skip to: 7998
/* 6918 */    MCD_OPC_Decode, 158, 4, 4, // Opcode: LDSTUBrr
/* 6922 */    MCD_OPC_FilterValue, 1, 47, 4, 0, // Skip to: 7998
/* 6927 */    MCD_OPC_Decode, 157, 4, 4, // Opcode: LDSTUBri
/* 6931 */    MCD_OPC_FilterValue, 14, 28, 0, 0, // Skip to: 6964
/* 6936 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6939 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6955
/* 6944 */    MCD_OPC_CheckField, 5, 8, 0, 23, 4, 0, // Skip to: 7998
/* 6951 */    MCD_OPC_Decode, 170, 5, 71, // Opcode: STXrr
/* 6955 */    MCD_OPC_FilterValue, 1, 14, 4, 0, // Skip to: 7998
/* 6960 */    MCD_OPC_Decode, 169, 5, 71, // Opcode: STXri
/* 6964 */    MCD_OPC_FilterValue, 15, 28, 0, 0, // Skip to: 6997
/* 6969 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 6972 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 6988
/* 6977 */    MCD_OPC_CheckField, 5, 8, 0, 246, 3, 0, // Skip to: 7998
/* 6984 */    MCD_OPC_Decode, 185, 5, 73, // Opcode: SWAPrr
/* 6988 */    MCD_OPC_FilterValue, 1, 237, 3, 0, // Skip to: 7998
/* 6993 */    MCD_OPC_Decode, 184, 5, 73, // Opcode: SWAPri
/* 6997 */    MCD_OPC_FilterValue, 16, 11, 0, 0, // Skip to: 7013
/* 7002 */    MCD_OPC_CheckField, 13, 1, 0, 221, 3, 0, // Skip to: 7998
/* 7009 */    MCD_OPC_Decode, 129, 4, 69, // Opcode: LDArr
/* 7013 */    MCD_OPC_FilterValue, 17, 11, 0, 0, // Skip to: 7029
/* 7018 */    MCD_OPC_CheckField, 13, 1, 0, 205, 3, 0, // Skip to: 7998
/* 7025 */    MCD_OPC_Decode, 161, 4, 69, // Opcode: LDUBArr
/* 7029 */    MCD_OPC_FilterValue, 18, 11, 0, 0, // Skip to: 7045
/* 7034 */    MCD_OPC_CheckField, 13, 1, 0, 189, 3, 0, // Skip to: 7998
/* 7041 */    MCD_OPC_Decode, 164, 4, 69, // Opcode: LDUHArr
/* 7045 */    MCD_OPC_FilterValue, 19, 11, 0, 0, // Skip to: 7061
/* 7050 */    MCD_OPC_CheckField, 13, 1, 0, 173, 3, 0, // Skip to: 7998
/* 7057 */    MCD_OPC_Decode, 134, 4, 70, // Opcode: LDDArr
/* 7061 */    MCD_OPC_FilterValue, 20, 11, 0, 0, // Skip to: 7077
/* 7066 */    MCD_OPC_CheckField, 13, 1, 0, 157, 3, 0, // Skip to: 7998
/* 7073 */    MCD_OPC_Decode, 135, 5, 71, // Opcode: STArr
/* 7077 */    MCD_OPC_FilterValue, 21, 11, 0, 0, // Skip to: 7093
/* 7082 */    MCD_OPC_CheckField, 13, 1, 0, 141, 3, 0, // Skip to: 7998
/* 7089 */    MCD_OPC_Decode, 137, 5, 71, // Opcode: STBArr
/* 7093 */    MCD_OPC_FilterValue, 22, 11, 0, 0, // Skip to: 7109
/* 7098 */    MCD_OPC_CheckField, 13, 1, 0, 125, 3, 0, // Skip to: 7998
/* 7105 */    MCD_OPC_Decode, 161, 5, 71, // Opcode: STHArr
/* 7109 */    MCD_OPC_FilterValue, 23, 11, 0, 0, // Skip to: 7125
/* 7114 */    MCD_OPC_CheckField, 13, 1, 0, 109, 3, 0, // Skip to: 7998
/* 7121 */    MCD_OPC_Decode, 144, 5, 72, // Opcode: STDArr
/* 7125 */    MCD_OPC_FilterValue, 25, 11, 0, 0, // Skip to: 7141
/* 7130 */    MCD_OPC_CheckField, 13, 1, 0, 93, 3, 0, // Skip to: 7998
/* 7137 */    MCD_OPC_Decode, 150, 4, 69, // Opcode: LDSBArr
/* 7141 */    MCD_OPC_FilterValue, 26, 11, 0, 0, // Skip to: 7157
/* 7146 */    MCD_OPC_CheckField, 13, 1, 0, 77, 3, 0, // Skip to: 7998
/* 7153 */    MCD_OPC_Decode, 153, 4, 69, // Opcode: LDSHArr
/* 7157 */    MCD_OPC_FilterValue, 29, 11, 0, 0, // Skip to: 7173
/* 7162 */    MCD_OPC_CheckField, 13, 1, 0, 61, 3, 0, // Skip to: 7998
/* 7169 */    MCD_OPC_Decode, 156, 4, 74, // Opcode: LDSTUBArr
/* 7173 */    MCD_OPC_FilterValue, 31, 11, 0, 0, // Skip to: 7189
/* 7178 */    MCD_OPC_CheckField, 13, 1, 0, 45, 3, 0, // Skip to: 7998
/* 7185 */    MCD_OPC_Decode, 183, 5, 73, // Opcode: SWAPArr
/* 7189 */    MCD_OPC_FilterValue, 32, 28, 0, 0, // Skip to: 7222
/* 7194 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7197 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7213
/* 7202 */    MCD_OPC_CheckField, 5, 8, 0, 21, 3, 0, // Skip to: 7998
/* 7209 */    MCD_OPC_Decode, 146, 4, 75, // Opcode: LDFrr
/* 7213 */    MCD_OPC_FilterValue, 1, 12, 3, 0, // Skip to: 7998
/* 7218 */    MCD_OPC_Decode, 145, 4, 75, // Opcode: LDFri
/* 7222 */    MCD_OPC_FilterValue, 33, 79, 0, 0, // Skip to: 7306
/* 7227 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7230 */    MCD_OPC_FilterValue, 0, 40, 0, 0, // Skip to: 7275
/* 7235 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7238 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7254
/* 7243 */    MCD_OPC_CheckField, 5, 8, 0, 236, 2, 0, // Skip to: 7998
/* 7250 */    MCD_OPC_Decode, 144, 4, 75, // Opcode: LDFSRrr
/* 7254 */    MCD_OPC_FilterValue, 1, 227, 2, 0, // Skip to: 7998
/* 7259 */    MCD_OPC_CheckPredicate, 0, 222, 2, 0, // Skip to: 7998
/* 7264 */    MCD_OPC_CheckField, 5, 8, 0, 215, 2, 0, // Skip to: 7998
/* 7271 */    MCD_OPC_Decode, 168, 4, 75, // Opcode: LDXFSRrr
/* 7275 */    MCD_OPC_FilterValue, 1, 206, 2, 0, // Skip to: 7998
/* 7280 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7283 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7292
/* 7288 */    MCD_OPC_Decode, 143, 4, 75, // Opcode: LDFSRri
/* 7292 */    MCD_OPC_FilterValue, 1, 189, 2, 0, // Skip to: 7998
/* 7297 */    MCD_OPC_CheckPredicate, 0, 184, 2, 0, // Skip to: 7998
/* 7302 */    MCD_OPC_Decode, 167, 4, 75, // Opcode: LDXFSRri
/* 7306 */    MCD_OPC_FilterValue, 34, 38, 0, 0, // Skip to: 7349
/* 7311 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7314 */    MCD_OPC_FilterValue, 0, 16, 0, 0, // Skip to: 7335
/* 7319 */    MCD_OPC_CheckPredicate, 0, 162, 2, 0, // Skip to: 7998
/* 7324 */    MCD_OPC_CheckField, 5, 8, 0, 155, 2, 0, // Skip to: 7998
/* 7331 */    MCD_OPC_Decode, 149, 4, 76, // Opcode: LDQFrr
/* 7335 */    MCD_OPC_FilterValue, 1, 146, 2, 0, // Skip to: 7998
/* 7340 */    MCD_OPC_CheckPredicate, 0, 141, 2, 0, // Skip to: 7998
/* 7345 */    MCD_OPC_Decode, 148, 4, 76, // Opcode: LDQFri
/* 7349 */    MCD_OPC_FilterValue, 35, 28, 0, 0, // Skip to: 7382
/* 7354 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7357 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7373
/* 7362 */    MCD_OPC_CheckField, 5, 8, 0, 117, 2, 0, // Skip to: 7998
/* 7369 */    MCD_OPC_Decode, 139, 4, 77, // Opcode: LDDFrr
/* 7373 */    MCD_OPC_FilterValue, 1, 108, 2, 0, // Skip to: 7998
/* 7378 */    MCD_OPC_Decode, 138, 4, 77, // Opcode: LDDFri
/* 7382 */    MCD_OPC_FilterValue, 36, 28, 0, 0, // Skip to: 7415
/* 7387 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7390 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7406
/* 7395 */    MCD_OPC_CheckField, 5, 8, 0, 84, 2, 0, // Skip to: 7998
/* 7402 */    MCD_OPC_Decode, 160, 5, 78, // Opcode: STFrr
/* 7406 */    MCD_OPC_FilterValue, 1, 75, 2, 0, // Skip to: 7998
/* 7411 */    MCD_OPC_Decode, 159, 5, 78, // Opcode: STFri
/* 7415 */    MCD_OPC_FilterValue, 37, 79, 0, 0, // Skip to: 7499
/* 7420 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7423 */    MCD_OPC_FilterValue, 0, 40, 0, 0, // Skip to: 7468
/* 7428 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7431 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7447
/* 7436 */    MCD_OPC_CheckField, 5, 8, 0, 43, 2, 0, // Skip to: 7998
/* 7443 */    MCD_OPC_Decode, 158, 5, 78, // Opcode: STFSRrr
/* 7447 */    MCD_OPC_FilterValue, 1, 34, 2, 0, // Skip to: 7998
/* 7452 */    MCD_OPC_CheckPredicate, 0, 29, 2, 0, // Skip to: 7998
/* 7457 */    MCD_OPC_CheckField, 5, 8, 0, 22, 2, 0, // Skip to: 7998
/* 7464 */    MCD_OPC_Decode, 168, 5, 78, // Opcode: STXFSRrr
/* 7468 */    MCD_OPC_FilterValue, 1, 13, 2, 0, // Skip to: 7998
/* 7473 */    MCD_OPC_ExtractField, 25, 5,  // Inst{29-25} ...
/* 7476 */    MCD_OPC_FilterValue, 0, 4, 0, 0, // Skip to: 7485
/* 7481 */    MCD_OPC_Decode, 157, 5, 78, // Opcode: STFSRri
/* 7485 */    MCD_OPC_FilterValue, 1, 252, 1, 0, // Skip to: 7998
/* 7490 */    MCD_OPC_CheckPredicate, 0, 247, 1, 0, // Skip to: 7998
/* 7495 */    MCD_OPC_Decode, 167, 5, 78, // Opcode: STXFSRri
/* 7499 */    MCD_OPC_FilterValue, 38, 61, 0, 0, // Skip to: 7565
/* 7504 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7507 */    MCD_OPC_FilterValue, 0, 28, 0, 0, // Skip to: 7540
/* 7512 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 7515 */    MCD_OPC_FilterValue, 0, 222, 1, 0, // Skip to: 7998
/* 7520 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 7531
/* 7527 */    MCD_OPC_Decode, 151, 5, 78, // Opcode: STDFQrr
/* 7531 */    MCD_OPC_CheckPredicate, 0, 206, 1, 0, // Skip to: 7998
/* 7536 */    MCD_OPC_Decode, 166, 5, 79, // Opcode: STQFrr
/* 7540 */    MCD_OPC_FilterValue, 1, 197, 1, 0, // Skip to: 7998
/* 7545 */    MCD_OPC_CheckField, 25, 5, 0, 4, 0, 0, // Skip to: 7556
/* 7552 */    MCD_OPC_Decode, 150, 5, 78, // Opcode: STDFQri
/* 7556 */    MCD_OPC_CheckPredicate, 0, 181, 1, 0, // Skip to: 7998
/* 7561 */    MCD_OPC_Decode, 165, 5, 79, // Opcode: STQFri
/* 7565 */    MCD_OPC_FilterValue, 39, 28, 0, 0, // Skip to: 7598
/* 7570 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7573 */    MCD_OPC_FilterValue, 0, 11, 0, 0, // Skip to: 7589
/* 7578 */    MCD_OPC_CheckField, 5, 8, 0, 157, 1, 0, // Skip to: 7998
/* 7585 */    MCD_OPC_Decode, 153, 5, 80, // Opcode: STDFrr
/* 7589 */    MCD_OPC_FilterValue, 1, 148, 1, 0, // Skip to: 7998
/* 7594 */    MCD_OPC_Decode, 152, 5, 80, // Opcode: STDFri
/* 7598 */    MCD_OPC_FilterValue, 48, 37, 0, 0, // Skip to: 7640
/* 7603 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7606 */    MCD_OPC_FilterValue, 0, 20, 0, 0, // Skip to: 7631
/* 7611 */    MCD_OPC_CheckField, 5, 8, 0, 4, 0, 0, // Skip to: 7622
/* 7618 */    MCD_OPC_Decode, 133, 4, 81, // Opcode: LDCrr
/* 7622 */    MCD_OPC_CheckPredicate, 0, 115, 1, 0, // Skip to: 7998
/* 7627 */    MCD_OPC_Decode, 142, 4, 75, // Opcode: LDFArr
/* 7631 */    MCD_OPC_FilterValue, 1, 106, 1, 0, // Skip to: 7998
/* 7636 */    MCD_OPC_Decode, 132, 4, 81, // Opcode: LDCri
/* 7640 */    MCD_OPC_FilterValue, 49, 42, 0, 0, // Skip to: 7687
/* 7645 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7648 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 7671
/* 7653 */    MCD_OPC_CheckField, 25, 5, 0, 82, 1, 0, // Skip to: 7998
/* 7660 */    MCD_OPC_CheckField, 5, 8, 0, 75, 1, 0, // Skip to: 7998
/* 7667 */    MCD_OPC_Decode, 131, 4, 81, // Opcode: LDCSRrr
/* 7671 */    MCD_OPC_FilterValue, 1, 66, 1, 0, // Skip to: 7998
/* 7676 */    MCD_OPC_CheckField, 25, 5, 0, 59, 1, 0, // Skip to: 7998
/* 7683 */    MCD_OPC_Decode, 130, 4, 81, // Opcode: LDCSRri
/* 7687 */    MCD_OPC_FilterValue, 50, 16, 0, 0, // Skip to: 7708
/* 7692 */    MCD_OPC_CheckPredicate, 0, 45, 1, 0, // Skip to: 7998
/* 7697 */    MCD_OPC_CheckField, 13, 1, 0, 38, 1, 0, // Skip to: 7998
/* 7704 */    MCD_OPC_Decode, 147, 4, 76, // Opcode: LDQFArr
/* 7708 */    MCD_OPC_FilterValue, 51, 37, 0, 0, // Skip to: 7750
/* 7713 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7716 */    MCD_OPC_FilterValue, 0, 20, 0, 0, // Skip to: 7741
/* 7721 */    MCD_OPC_CheckField, 5, 8, 0, 4, 0, 0, // Skip to: 7732
/* 7728 */    MCD_OPC_Decode, 136, 4, 82, // Opcode: LDDCrr
/* 7732 */    MCD_OPC_CheckPredicate, 0, 5, 1, 0, // Skip to: 7998
/* 7737 */    MCD_OPC_Decode, 137, 4, 77, // Opcode: LDDFArr
/* 7741 */    MCD_OPC_FilterValue, 1, 252, 0, 0, // Skip to: 7998
/* 7746 */    MCD_OPC_Decode, 135, 4, 82, // Opcode: LDDCri
/* 7750 */    MCD_OPC_FilterValue, 52, 37, 0, 0, // Skip to: 7792
/* 7755 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7758 */    MCD_OPC_FilterValue, 0, 20, 0, 0, // Skip to: 7783
/* 7763 */    MCD_OPC_CheckField, 5, 8, 0, 4, 0, 0, // Skip to: 7774
/* 7770 */    MCD_OPC_Decode, 143, 5, 83, // Opcode: STCrr
/* 7774 */    MCD_OPC_CheckPredicate, 0, 219, 0, 0, // Skip to: 7998
/* 7779 */    MCD_OPC_Decode, 156, 5, 78, // Opcode: STFArr
/* 7783 */    MCD_OPC_FilterValue, 1, 210, 0, 0, // Skip to: 7998
/* 7788 */    MCD_OPC_Decode, 142, 5, 83, // Opcode: STCri
/* 7792 */    MCD_OPC_FilterValue, 53, 42, 0, 0, // Skip to: 7839
/* 7797 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7800 */    MCD_OPC_FilterValue, 0, 18, 0, 0, // Skip to: 7823
/* 7805 */    MCD_OPC_CheckField, 25, 5, 0, 186, 0, 0, // Skip to: 7998
/* 7812 */    MCD_OPC_CheckField, 5, 8, 0, 179, 0, 0, // Skip to: 7998
/* 7819 */    MCD_OPC_Decode, 141, 5, 83, // Opcode: STCSRrr
/* 7823 */    MCD_OPC_FilterValue, 1, 170, 0, 0, // Skip to: 7998
/* 7828 */    MCD_OPC_CheckField, 25, 5, 0, 163, 0, 0, // Skip to: 7998
/* 7835 */    MCD_OPC_Decode, 140, 5, 83, // Opcode: STCSRri
/* 7839 */    MCD_OPC_FilterValue, 54, 51, 0, 0, // Skip to: 7895
/* 7844 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7847 */    MCD_OPC_FilterValue, 0, 27, 0, 0, // Skip to: 7879
/* 7852 */    MCD_OPC_CheckField, 25, 5, 0, 11, 0, 0, // Skip to: 7870
/* 7859 */    MCD_OPC_CheckField, 5, 8, 0, 4, 0, 0, // Skip to: 7870
/* 7866 */    MCD_OPC_Decode, 146, 5, 83, // Opcode: STDCQrr
/* 7870 */    MCD_OPC_CheckPredicate, 0, 123, 0, 0, // Skip to: 7998
/* 7875 */    MCD_OPC_Decode, 164, 5, 79, // Opcode: STQFArr
/* 7879 */    MCD_OPC_FilterValue, 1, 114, 0, 0, // Skip to: 7998
/* 7884 */    MCD_OPC_CheckField, 25, 5, 0, 107, 0, 0, // Skip to: 7998
/* 7891 */    MCD_OPC_Decode, 145, 5, 83, // Opcode: STDCQri
/* 7895 */    MCD_OPC_FilterValue, 55, 37, 0, 0, // Skip to: 7937
/* 7900 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7903 */    MCD_OPC_FilterValue, 0, 20, 0, 0, // Skip to: 7928
/* 7908 */    MCD_OPC_CheckField, 5, 8, 0, 4, 0, 0, // Skip to: 7919
/* 7915 */    MCD_OPC_Decode, 148, 5, 84, // Opcode: STDCrr
/* 7919 */    MCD_OPC_CheckPredicate, 0, 74, 0, 0, // Skip to: 7998
/* 7924 */    MCD_OPC_Decode, 149, 5, 80, // Opcode: STDFArr
/* 7928 */    MCD_OPC_FilterValue, 1, 65, 0, 0, // Skip to: 7998
/* 7933 */    MCD_OPC_Decode, 147, 5, 84, // Opcode: STDCri
/* 7937 */    MCD_OPC_FilterValue, 60, 39, 0, 0, // Skip to: 7981
/* 7942 */    MCD_OPC_ExtractField, 13, 1,  // Inst{13} ...
/* 7945 */    MCD_OPC_FilterValue, 0, 48, 0, 0, // Skip to: 7998
/* 7950 */    MCD_OPC_ExtractField, 5, 8,  // Inst{12-5} ...
/* 7953 */    MCD_OPC_FilterValue, 10, 4, 0, 0, // Skip to: 7962
/* 7958 */    MCD_OPC_Decode, 195, 2, 85, // Opcode: CASAasi10
/* 7962 */    MCD_OPC_FilterValue, 128, 1, 9, 0, 0, // Skip to: 7977
/* 7968 */    MCD_OPC_CheckPredicate, 0, 4, 0, 0, // Skip to: 7977
/* 7973 */    MCD_OPC_Decode, 198, 2, 85, // Opcode: CASrr
/* 7977 */    MCD_OPC_Decode, 196, 2, 86, // Opcode: CASArr
/* 7981 */    MCD_OPC_FilterValue, 62, 12, 0, 0, // Skip to: 7998
/* 7986 */    MCD_OPC_CheckField, 5, 9, 128, 1, 4, 0, 0, // Skip to: 7998
/* 7994 */    MCD_OPC_Decode, 197, 2, 87, // Opcode: CASXrr
/* 7998 */    MCD_OPC_Fail,
  0
};

static const uint8_t DecoderTableSparcV832[] = {
/* 0 */       MCD_OPC_ExtractField, 8, 6,  // Inst{13-8} ...
/* 3 */       MCD_OPC_FilterValue, 0, 25, 0, 0, // Skip to: 33
/* 8 */       MCD_OPC_CheckField, 29, 3, 4, 41, 0, 0, // Skip to: 56
/* 15 */      MCD_OPC_CheckField, 19, 6, 58, 34, 0, 0, // Skip to: 56
/* 22 */      MCD_OPC_CheckField, 5, 3, 0, 27, 0, 0, // Skip to: 56
/* 29 */      MCD_OPC_Decode, 201, 5, 88, // Opcode: TRAPrr
/* 33 */      MCD_OPC_FilterValue, 32, 18, 0, 0, // Skip to: 56
/* 38 */      MCD_OPC_CheckField, 29, 3, 4, 11, 0, 0, // Skip to: 56
/* 45 */      MCD_OPC_CheckField, 19, 6, 58, 4, 0, 0, // Skip to: 56
/* 52 */      MCD_OPC_Decode, 200, 5, 88, // Opcode: TRAPri
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
/* 34 */      MCD_OPC_Decode, 194, 5, 88, // Opcode: TICCrr
/* 38 */      MCD_OPC_FilterValue, 32, 23, 0, 0, // Skip to: 66
/* 43 */      MCD_OPC_CheckPredicate, 0, 18, 0, 0, // Skip to: 66
/* 48 */      MCD_OPC_CheckField, 29, 3, 4, 11, 0, 0, // Skip to: 66
/* 55 */      MCD_OPC_CheckField, 19, 6, 58, 4, 0, 0, // Skip to: 66
/* 62 */      MCD_OPC_Decode, 193, 5, 88, // Opcode: TICCri
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
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeASRRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 18:\
    tmp = fieldFromInstruction(insn, 0, 13);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 19:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
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
    if (DecodeLoadCP(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 82:\
    if (DecodeLoadCPPair(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 83:\
    if (DecodeStoreCP(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 84:\
    if (DecodeStoreCPPair(MI, insn, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 85:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeIntRegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
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
    tmp = fieldFromInstruction(insn, 5, 8);\
    MCOperand_CreateImm0(MI, tmp);\
    return S;\
  case 87:\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 14, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 0, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    tmp = fieldFromInstruction(insn, 25, 5);\
    if (DecodeI64RegsRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) { return MCDisassembler_Fail; }\
    return S;\
  case 88:\
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
#define SP_PIL 11
#define SP_PSR 12
#define SP_PSTATE 13
#define SP_TBA 14
#define SP_TBR 15
#define SP_TICK 16
#define SP_TL 17
#define SP_TNPC 18
#define SP_TPC 19
#define SP_TSTATE 20
#define SP_TT 21
#define SP_WIM 22
#define SP_WSTATE 23
#define SP_Y 24
#define SP_ASR1 25
#define SP_ASR2 26
#define SP_ASR3 27
#define SP_ASR4 28
#define SP_ASR5 29
#define SP_ASR6 30
#define SP_ASR7 31
#define SP_ASR8 32
#define SP_ASR9 33
#define SP_ASR10 34
#define SP_ASR11 35
#define SP_ASR12 36
#define SP_ASR13 37
#define SP_ASR14 38
#define SP_ASR15 39
#define SP_ASR16 40
#define SP_ASR17 41
#define SP_ASR18 42
#define SP_ASR19 43
#define SP_ASR20 44
#define SP_ASR21 45
#define SP_ASR22 46
#define SP_ASR23 47
#define SP_ASR24 48
#define SP_ASR25 49
#define SP_ASR26 50
#define SP_ASR27 51
#define SP_ASR28 52
#define SP_ASR29 53
#define SP_ASR30 54
#define SP_ASR31 55
#define SP_C0 56
#define SP_C1 57
#define SP_C2 58
#define SP_C3 59
#define SP_C4 60
#define SP_C5 61
#define SP_C6 62
#define SP_C7 63
#define SP_C8 64
#define SP_C9 65
#define SP_C10 66
#define SP_C11 67
#define SP_C12 68
#define SP_C13 69
#define SP_C14 70
#define SP_C15 71
#define SP_C16 72
#define SP_C17 73
#define SP_C18 74
#define SP_C19 75
#define SP_C20 76
#define SP_C21 77
#define SP_C22 78
#define SP_C23 79
#define SP_C24 80
#define SP_C25 81
#define SP_C26 82
#define SP_C27 83
#define SP_C28 84
#define SP_C29 85
#define SP_C30 86
#define SP_C31 87
#define SP_D0 88
#define SP_D1 89
#define SP_D2 90
#define SP_D3 91
#define SP_D4 92
#define SP_D5 93
#define SP_D6 94
#define SP_D7 95
#define SP_D8 96
#define SP_D9 97
#define SP_D10 98
#define SP_D11 99
#define SP_D12 100
#define SP_D13 101
#define SP_D14 102
#define SP_D15 103
#define SP_D16 104
#define SP_D17 105
#define SP_D18 106
#define SP_D19 107
#define SP_D20 108
#define SP_D21 109
#define SP_D22 110
#define SP_D23 111
#define SP_D24 112
#define SP_D25 113
#define SP_D26 114
#define SP_D27 115
#define SP_D28 116
#define SP_D29 117
#define SP_D30 118
#define SP_D31 119
#define SP_F0 120
#define SP_F1 121
#define SP_F2 122
#define SP_F3 123
#define SP_F4 124
#define SP_F5 125
#define SP_F6 126
#define SP_F7 127
#define SP_F8 128
#define SP_F9 129
#define SP_F10 130
#define SP_F11 131
#define SP_F12 132
#define SP_F13 133
#define SP_F14 134
#define SP_F15 135
#define SP_F16 136
#define SP_F17 137
#define SP_F18 138
#define SP_F19 139
#define SP_F20 140
#define SP_F21 141
#define SP_F22 142
#define SP_F23 143
#define SP_F24 144
#define SP_F25 145
#define SP_F26 146
#define SP_F27 147
#define SP_F28 148
#define SP_F29 149
#define SP_F30 150
#define SP_F31 151
#define SP_FCC0 152
#define SP_FCC1 153
#define SP_FCC2 154
#define SP_FCC3 155
#define SP_G0 156
#define SP_G1 157
#define SP_G2 158
#define SP_G3 159
#define SP_G4 160
#define SP_G5 161
#define SP_G6 162
#define SP_G7 163
#define SP_I0 164
#define SP_I1 165
#define SP_I2 166
#define SP_I3 167
#define SP_I4 168
#define SP_I5 169
#define SP_I6 170
#define SP_I7 171
#define SP_L0 172
#define SP_L1 173
#define SP_L2 174
#define SP_L3 175
#define SP_L4 176
#define SP_L5 177
#define SP_L6 178
#define SP_L7 179
#define SP_O0 180
#define SP_O1 181
#define SP_O2 182
#define SP_O3 183
#define SP_O4 184
#define SP_O5 185
#define SP_O6 186
#define SP_O7 187
#define SP_Q0 188
#define SP_Q1 189
#define SP_Q2 190
#define SP_Q3 191
#define SP_Q4 192
#define SP_Q5 193
#define SP_Q6 194
#define SP_Q7 195
#define SP_Q8 196
#define SP_Q9 197
#define SP_Q10 198
#define SP_Q11 199
#define SP_Q12 200
#define SP_Q13 201
#define SP_Q14 202
#define SP_Q15 203
#define SP_C0_C1 204
#define SP_C2_C3 205
#define SP_C4_C5 206
#define SP_C6_C7 207
#define SP_C8_C9 208
#define SP_C10_C11 209
#define SP_C12_C13 210
#define SP_C14_C15 211
#define SP_C16_C17 212
#define SP_C18_C19 213
#define SP_C20_C21 214
#define SP_C22_C23 215
#define SP_C24_C25 216
#define SP_C26_C27 217
#define SP_C28_C29 218
#define SP_C30_C31 219
#define SP_G0_G1 220
#define SP_G2_G3 221
#define SP_G4_G5 222
#define SP_G6_G7 223
#define SP_I0_I1 224
#define SP_I2_I3 225
#define SP_I4_I5 226
#define SP_I6_I7 227
#define SP_L0_L1 228
#define SP_L2_L3 229
#define SP_L4_L5 230
#define SP_L6_L7 231
#define SP_O0_O1 232
#define SP_O2_O3 233
#define SP_O4_O5 234
#define SP_O6_O7 235
#define SP_NUM_TARGET_REGS 236


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
#define SP_DBG_LABEL	 16
#define SP_REG_SEQUENCE	 17
#define SP_COPY	 18
#define SP_BUNDLE	 19
#define SP_LIFETIME_START	 20
#define SP_LIFETIME_END	 21
#define SP_PSEUDO_PROBE	 22
#define SP_STACKMAP	 23
#define SP_FENTRY_CALL	 24
#define SP_PATCHPOINT	 25
#define SP_LOAD_STACK_GUARD	 26
#define SP_PREALLOCATED_SETUP	 27
#define SP_PREALLOCATED_ARG	 28
#define SP_STATEPOINT	 29
#define SP_LOCAL_ESCAPE	 30
#define SP_FAULTING_OP	 31
#define SP_PATCHABLE_OP	 32
#define SP_PATCHABLE_FUNCTION_ENTER	 33
#define SP_PATCHABLE_RET	 34
#define SP_PATCHABLE_FUNCTION_EXIT	 35
#define SP_PATCHABLE_TAIL_CALL	 36
#define SP_PATCHABLE_EVENT_CALL	 37
#define SP_PATCHABLE_TYPED_EVENT_CALL	 38
#define SP_ICALL_BRANCH_FUNNEL	 39
#define SP_G_ASSERT_SEXT	 40
#define SP_G_ASSERT_ZEXT	 41
#define SP_G_ADD	 42
#define SP_G_SUB	 43
#define SP_G_MUL	 44
#define SP_G_SDIV	 45
#define SP_G_UDIV	 46
#define SP_G_SREM	 47
#define SP_G_UREM	 48
#define SP_G_SDIVREM	 49
#define SP_G_UDIVREM	 50
#define SP_G_AND	 51
#define SP_G_OR	 52
#define SP_G_XOR	 53
#define SP_G_IMPLICIT_DEF	 54
#define SP_G_PHI	 55
#define SP_G_FRAME_INDEX	 56
#define SP_G_GLOBAL_VALUE	 57
#define SP_G_EXTRACT	 58
#define SP_G_UNMERGE_VALUES	 59
#define SP_G_INSERT	 60
#define SP_G_MERGE_VALUES	 61
#define SP_G_BUILD_VECTOR	 62
#define SP_G_BUILD_VECTOR_TRUNC	 63
#define SP_G_CONCAT_VECTORS	 64
#define SP_G_PTRTOINT	 65
#define SP_G_INTTOPTR	 66
#define SP_G_BITCAST	 67
#define SP_G_FREEZE	 68
#define SP_G_INTRINSIC_TRUNC	 69
#define SP_G_INTRINSIC_ROUND	 70
#define SP_G_INTRINSIC_LRINT	 71
#define SP_G_INTRINSIC_ROUNDEVEN	 72
#define SP_G_READCYCLECOUNTER	 73
#define SP_G_LOAD	 74
#define SP_G_SEXTLOAD	 75
#define SP_G_ZEXTLOAD	 76
#define SP_G_INDEXED_LOAD	 77
#define SP_G_INDEXED_SEXTLOAD	 78
#define SP_G_INDEXED_ZEXTLOAD	 79
#define SP_G_STORE	 80
#define SP_G_INDEXED_STORE	 81
#define SP_G_ATOMIC_CMPXCHG_WITH_SUCCESS	 82
#define SP_G_ATOMIC_CMPXCHG	 83
#define SP_G_ATOMICRMW_XCHG	 84
#define SP_G_ATOMICRMW_ADD	 85
#define SP_G_ATOMICRMW_SUB	 86
#define SP_G_ATOMICRMW_AND	 87
#define SP_G_ATOMICRMW_NAND	 88
#define SP_G_ATOMICRMW_OR	 89
#define SP_G_ATOMICRMW_XOR	 90
#define SP_G_ATOMICRMW_MAX	 91
#define SP_G_ATOMICRMW_MIN	 92
#define SP_G_ATOMICRMW_UMAX	 93
#define SP_G_ATOMICRMW_UMIN	 94
#define SP_G_ATOMICRMW_FADD	 95
#define SP_G_ATOMICRMW_FSUB	 96
#define SP_G_FENCE	 97
#define SP_G_BRCOND	 98
#define SP_G_BRINDIRECT	 99
#define SP_G_INTRINSIC	 100
#define SP_G_INTRINSIC_W_SIDE_EFFECTS	 101
#define SP_G_ANYEXT	 102
#define SP_G_TRUNC	 103
#define SP_G_CONSTANT	 104
#define SP_G_FCONSTANT	 105
#define SP_G_VASTART	 106
#define SP_G_VAARG	 107
#define SP_G_SEXT	 108
#define SP_G_SEXT_INREG	 109
#define SP_G_ZEXT	 110
#define SP_G_SHL	 111
#define SP_G_LSHR	 112
#define SP_G_ASHR	 113
#define SP_G_FSHL	 114
#define SP_G_FSHR	 115
#define SP_G_ROTR	 116
#define SP_G_ROTL	 117
#define SP_G_ICMP	 118
#define SP_G_FCMP	 119
#define SP_G_SELECT	 120
#define SP_G_UADDO	 121
#define SP_G_UADDE	 122
#define SP_G_USUBO	 123
#define SP_G_USUBE	 124
#define SP_G_SADDO	 125
#define SP_G_SADDE	 126
#define SP_G_SSUBO	 127
#define SP_G_SSUBE	 128
#define SP_G_UMULO	 129
#define SP_G_SMULO	 130
#define SP_G_UMULH	 131
#define SP_G_SMULH	 132
#define SP_G_UADDSAT	 133
#define SP_G_SADDSAT	 134
#define SP_G_USUBSAT	 135
#define SP_G_SSUBSAT	 136
#define SP_G_USHLSAT	 137
#define SP_G_SSHLSAT	 138
#define SP_G_SMULFIX	 139
#define SP_G_UMULFIX	 140
#define SP_G_SMULFIXSAT	 141
#define SP_G_UMULFIXSAT	 142
#define SP_G_SDIVFIX	 143
#define SP_G_UDIVFIX	 144
#define SP_G_SDIVFIXSAT	 145
#define SP_G_UDIVFIXSAT	 146
#define SP_G_FADD	 147
#define SP_G_FSUB	 148
#define SP_G_FMUL	 149
#define SP_G_FMA	 150
#define SP_G_FMAD	 151
#define SP_G_FDIV	 152
#define SP_G_FREM	 153
#define SP_G_FPOW	 154
#define SP_G_FPOWI	 155
#define SP_G_FEXP	 156
#define SP_G_FEXP2	 157
#define SP_G_FLOG	 158
#define SP_G_FLOG2	 159
#define SP_G_FLOG10	 160
#define SP_G_FNEG	 161
#define SP_G_FPEXT	 162
#define SP_G_FPTRUNC	 163
#define SP_G_FPTOSI	 164
#define SP_G_FPTOUI	 165
#define SP_G_SITOFP	 166
#define SP_G_UITOFP	 167
#define SP_G_FABS	 168
#define SP_G_FCOPYSIGN	 169
#define SP_G_FCANONICALIZE	 170
#define SP_G_FMINNUM	 171
#define SP_G_FMAXNUM	 172
#define SP_G_FMINNUM_IEEE	 173
#define SP_G_FMAXNUM_IEEE	 174
#define SP_G_FMINIMUM	 175
#define SP_G_FMAXIMUM	 176
#define SP_G_PTR_ADD	 177
#define SP_G_PTRMASK	 178
#define SP_G_SMIN	 179
#define SP_G_SMAX	 180
#define SP_G_UMIN	 181
#define SP_G_UMAX	 182
#define SP_G_ABS	 183
#define SP_G_BR	 184
#define SP_G_BRJT	 185
#define SP_G_INSERT_VECTOR_ELT	 186
#define SP_G_EXTRACT_VECTOR_ELT	 187
#define SP_G_SHUFFLE_VECTOR	 188
#define SP_G_CTTZ	 189
#define SP_G_CTTZ_ZERO_UNDEF	 190
#define SP_G_CTLZ	 191
#define SP_G_CTLZ_ZERO_UNDEF	 192
#define SP_G_CTPOP	 193
#define SP_G_BSWAP	 194
#define SP_G_BITREVERSE	 195
#define SP_G_FCEIL	 196
#define SP_G_FCOS	 197
#define SP_G_FSIN	 198
#define SP_G_FSQRT	 199
#define SP_G_FFLOOR	 200
#define SP_G_FRINT	 201
#define SP_G_FNEARBYINT	 202
#define SP_G_ADDRSPACE_CAST	 203
#define SP_G_BLOCK_ADDR	 204
#define SP_G_JUMP_TABLE	 205
#define SP_G_DYN_STACKALLOC	 206
#define SP_G_STRICT_FADD	 207
#define SP_G_STRICT_FSUB	 208
#define SP_G_STRICT_FMUL	 209
#define SP_G_STRICT_FDIV	 210
#define SP_G_STRICT_FREM	 211
#define SP_G_STRICT_FMA	 212
#define SP_G_STRICT_FSQRT	 213
#define SP_G_READ_REGISTER	 214
#define SP_G_WRITE_REGISTER	 215
#define SP_G_MEMCPY	 216
#define SP_G_MEMMOVE	 217
#define SP_G_MEMSET	 218
#define SP_G_BZERO	 219
#define SP_G_VECREDUCE_SEQ_FADD	 220
#define SP_G_VECREDUCE_SEQ_FMUL	 221
#define SP_G_VECREDUCE_FADD	 222
#define SP_G_VECREDUCE_FMUL	 223
#define SP_G_VECREDUCE_FMAX	 224
#define SP_G_VECREDUCE_FMIN	 225
#define SP_G_VECREDUCE_ADD	 226
#define SP_G_VECREDUCE_MUL	 227
#define SP_G_VECREDUCE_AND	 228
#define SP_G_VECREDUCE_OR	 229
#define SP_G_VECREDUCE_XOR	 230
#define SP_G_VECREDUCE_SMAX	 231
#define SP_G_VECREDUCE_SMIN	 232
#define SP_G_VECREDUCE_UMAX	 233
#define SP_G_VECREDUCE_UMIN	 234
#define SP_G_SBFX	 235
#define SP_G_UBFX	 236
#define SP_ADJCALLSTACKDOWN	 237
#define SP_ADJCALLSTACKUP	 238
#define SP_GETPCX	 239
#define SP_SELECT_CC_DFP_FCC	 240
#define SP_SELECT_CC_DFP_ICC	 241
#define SP_SELECT_CC_FP_FCC	 242
#define SP_SELECT_CC_FP_ICC	 243
#define SP_SELECT_CC_Int_FCC	 244
#define SP_SELECT_CC_Int_ICC	 245
#define SP_SELECT_CC_QFP_FCC	 246
#define SP_SELECT_CC_QFP_ICC	 247
#define SP_SET	 248
#define SP_ADDCCri	 249
#define SP_ADDCCrr	 250
#define SP_ADDCri	 251
#define SP_ADDCrr	 252
#define SP_ADDEri	 253
#define SP_ADDErr	 254
#define SP_ADDXC	 255
#define SP_ADDXCCC	 256
#define SP_ADDXri	 257
#define SP_ADDXrr	 258
#define SP_ADDri	 259
#define SP_ADDrr	 260
#define SP_ALIGNADDR	 261
#define SP_ALIGNADDRL	 262
#define SP_ANDCCri	 263
#define SP_ANDCCrr	 264
#define SP_ANDNCCri	 265
#define SP_ANDNCCrr	 266
#define SP_ANDNri	 267
#define SP_ANDNrr	 268
#define SP_ANDXNrr	 269
#define SP_ANDXri	 270
#define SP_ANDXrr	 271
#define SP_ANDri	 272
#define SP_ANDrr	 273
#define SP_ARRAY16	 274
#define SP_ARRAY32	 275
#define SP_ARRAY8	 276
#define SP_BA	 277
#define SP_BCOND	 278
#define SP_BCONDA	 279
#define SP_BINDri	 280
#define SP_BINDrr	 281
#define SP_BMASK	 282
#define SP_BPFCC	 283
#define SP_BPFCCA	 284
#define SP_BPFCCANT	 285
#define SP_BPFCCNT	 286
#define SP_BPGEZapn	 287
#define SP_BPGEZapt	 288
#define SP_BPGEZnapn	 289
#define SP_BPGEZnapt	 290
#define SP_BPGZapn	 291
#define SP_BPGZapt	 292
#define SP_BPGZnapn	 293
#define SP_BPGZnapt	 294
#define SP_BPICC	 295
#define SP_BPICCA	 296
#define SP_BPICCANT	 297
#define SP_BPICCNT	 298
#define SP_BPLEZapn	 299
#define SP_BPLEZapt	 300
#define SP_BPLEZnapn	 301
#define SP_BPLEZnapt	 302
#define SP_BPLZapn	 303
#define SP_BPLZapt	 304
#define SP_BPLZnapn	 305
#define SP_BPLZnapt	 306
#define SP_BPNZapn	 307
#define SP_BPNZapt	 308
#define SP_BPNZnapn	 309
#define SP_BPNZnapt	 310
#define SP_BPXCC	 311
#define SP_BPXCCA	 312
#define SP_BPXCCANT	 313
#define SP_BPXCCNT	 314
#define SP_BPZapn	 315
#define SP_BPZapt	 316
#define SP_BPZnapn	 317
#define SP_BPZnapt	 318
#define SP_BSHUFFLE	 319
#define SP_CALL	 320
#define SP_CALLri	 321
#define SP_CALLrr	 322
#define SP_CASAasi10	 323
#define SP_CASArr	 324
#define SP_CASXrr	 325
#define SP_CASrr	 326
#define SP_CBCOND	 327
#define SP_CBCONDA	 328
#define SP_CMASK16	 329
#define SP_CMASK32	 330
#define SP_CMASK8	 331
#define SP_CMPri	 332
#define SP_CMPrr	 333
#define SP_EDGE16	 334
#define SP_EDGE16L	 335
#define SP_EDGE16LN	 336
#define SP_EDGE16N	 337
#define SP_EDGE32	 338
#define SP_EDGE32L	 339
#define SP_EDGE32LN	 340
#define SP_EDGE32N	 341
#define SP_EDGE8	 342
#define SP_EDGE8L	 343
#define SP_EDGE8LN	 344
#define SP_EDGE8N	 345
#define SP_FABSD	 346
#define SP_FABSQ	 347
#define SP_FABSS	 348
#define SP_FADDD	 349
#define SP_FADDQ	 350
#define SP_FADDS	 351
#define SP_FALIGNADATA	 352
#define SP_FAND	 353
#define SP_FANDNOT1	 354
#define SP_FANDNOT1S	 355
#define SP_FANDNOT2	 356
#define SP_FANDNOT2S	 357
#define SP_FANDS	 358
#define SP_FBCOND	 359
#define SP_FBCONDA	 360
#define SP_FCHKSM16	 361
#define SP_FCMPD	 362
#define SP_FCMPEQ16	 363
#define SP_FCMPEQ32	 364
#define SP_FCMPGT16	 365
#define SP_FCMPGT32	 366
#define SP_FCMPLE16	 367
#define SP_FCMPLE32	 368
#define SP_FCMPNE16	 369
#define SP_FCMPNE32	 370
#define SP_FCMPQ	 371
#define SP_FCMPS	 372
#define SP_FDIVD	 373
#define SP_FDIVQ	 374
#define SP_FDIVS	 375
#define SP_FDMULQ	 376
#define SP_FDTOI	 377
#define SP_FDTOQ	 378
#define SP_FDTOS	 379
#define SP_FDTOX	 380
#define SP_FEXPAND	 381
#define SP_FHADDD	 382
#define SP_FHADDS	 383
#define SP_FHSUBD	 384
#define SP_FHSUBS	 385
#define SP_FITOD	 386
#define SP_FITOQ	 387
#define SP_FITOS	 388
#define SP_FLCMPD	 389
#define SP_FLCMPS	 390
#define SP_FLUSH	 391
#define SP_FLUSHW	 392
#define SP_FLUSHri	 393
#define SP_FLUSHrr	 394
#define SP_FMEAN16	 395
#define SP_FMOVD	 396
#define SP_FMOVD_FCC	 397
#define SP_FMOVD_ICC	 398
#define SP_FMOVD_XCC	 399
#define SP_FMOVQ	 400
#define SP_FMOVQ_FCC	 401
#define SP_FMOVQ_ICC	 402
#define SP_FMOVQ_XCC	 403
#define SP_FMOVRGEZD	 404
#define SP_FMOVRGEZQ	 405
#define SP_FMOVRGEZS	 406
#define SP_FMOVRGZD	 407
#define SP_FMOVRGZQ	 408
#define SP_FMOVRGZS	 409
#define SP_FMOVRLEZD	 410
#define SP_FMOVRLEZQ	 411
#define SP_FMOVRLEZS	 412
#define SP_FMOVRLZD	 413
#define SP_FMOVRLZQ	 414
#define SP_FMOVRLZS	 415
#define SP_FMOVRNZD	 416
#define SP_FMOVRNZQ	 417
#define SP_FMOVRNZS	 418
#define SP_FMOVRZD	 419
#define SP_FMOVRZQ	 420
#define SP_FMOVRZS	 421
#define SP_FMOVS	 422
#define SP_FMOVS_FCC	 423
#define SP_FMOVS_ICC	 424
#define SP_FMOVS_XCC	 425
#define SP_FMUL8SUX16	 426
#define SP_FMUL8ULX16	 427
#define SP_FMUL8X16	 428
#define SP_FMUL8X16AL	 429
#define SP_FMUL8X16AU	 430
#define SP_FMULD	 431
#define SP_FMULD8SUX16	 432
#define SP_FMULD8ULX16	 433
#define SP_FMULQ	 434
#define SP_FMULS	 435
#define SP_FNADDD	 436
#define SP_FNADDS	 437
#define SP_FNAND	 438
#define SP_FNANDS	 439
#define SP_FNEGD	 440
#define SP_FNEGQ	 441
#define SP_FNEGS	 442
#define SP_FNHADDD	 443
#define SP_FNHADDS	 444
#define SP_FNMULD	 445
#define SP_FNMULS	 446
#define SP_FNOR	 447
#define SP_FNORS	 448
#define SP_FNOT1	 449
#define SP_FNOT1S	 450
#define SP_FNOT2	 451
#define SP_FNOT2S	 452
#define SP_FNSMULD	 453
#define SP_FONE	 454
#define SP_FONES	 455
#define SP_FOR	 456
#define SP_FORNOT1	 457
#define SP_FORNOT1S	 458
#define SP_FORNOT2	 459
#define SP_FORNOT2S	 460
#define SP_FORS	 461
#define SP_FPACK16	 462
#define SP_FPACK32	 463
#define SP_FPACKFIX	 464
#define SP_FPADD16	 465
#define SP_FPADD16S	 466
#define SP_FPADD32	 467
#define SP_FPADD32S	 468
#define SP_FPADD64	 469
#define SP_FPMERGE	 470
#define SP_FPSUB16	 471
#define SP_FPSUB16S	 472
#define SP_FPSUB32	 473
#define SP_FPSUB32S	 474
#define SP_FQTOD	 475
#define SP_FQTOI	 476
#define SP_FQTOS	 477
#define SP_FQTOX	 478
#define SP_FSLAS16	 479
#define SP_FSLAS32	 480
#define SP_FSLL16	 481
#define SP_FSLL32	 482
#define SP_FSMULD	 483
#define SP_FSQRTD	 484
#define SP_FSQRTQ	 485
#define SP_FSQRTS	 486
#define SP_FSRA16	 487
#define SP_FSRA32	 488
#define SP_FSRC1	 489
#define SP_FSRC1S	 490
#define SP_FSRC2	 491
#define SP_FSRC2S	 492
#define SP_FSRL16	 493
#define SP_FSRL32	 494
#define SP_FSTOD	 495
#define SP_FSTOI	 496
#define SP_FSTOQ	 497
#define SP_FSTOX	 498
#define SP_FSUBD	 499
#define SP_FSUBQ	 500
#define SP_FSUBS	 501
#define SP_FXNOR	 502
#define SP_FXNORS	 503
#define SP_FXOR	 504
#define SP_FXORS	 505
#define SP_FXTOD	 506
#define SP_FXTOQ	 507
#define SP_FXTOS	 508
#define SP_FZERO	 509
#define SP_FZEROS	 510
#define SP_JMPLri	 511
#define SP_JMPLrr	 512
#define SP_LDArr	 513
#define SP_LDCSRri	 514
#define SP_LDCSRrr	 515
#define SP_LDCri	 516
#define SP_LDCrr	 517
#define SP_LDDArr	 518
#define SP_LDDCri	 519
#define SP_LDDCrr	 520
#define SP_LDDFArr	 521
#define SP_LDDFri	 522
#define SP_LDDFrr	 523
#define SP_LDDri	 524
#define SP_LDDrr	 525
#define SP_LDFArr	 526
#define SP_LDFSRri	 527
#define SP_LDFSRrr	 528
#define SP_LDFri	 529
#define SP_LDFrr	 530
#define SP_LDQFArr	 531
#define SP_LDQFri	 532
#define SP_LDQFrr	 533
#define SP_LDSBArr	 534
#define SP_LDSBri	 535
#define SP_LDSBrr	 536
#define SP_LDSHArr	 537
#define SP_LDSHri	 538
#define SP_LDSHrr	 539
#define SP_LDSTUBArr	 540
#define SP_LDSTUBri	 541
#define SP_LDSTUBrr	 542
#define SP_LDSWri	 543
#define SP_LDSWrr	 544
#define SP_LDUBArr	 545
#define SP_LDUBri	 546
#define SP_LDUBrr	 547
#define SP_LDUHArr	 548
#define SP_LDUHri	 549
#define SP_LDUHrr	 550
#define SP_LDXFSRri	 551
#define SP_LDXFSRrr	 552
#define SP_LDXri	 553
#define SP_LDXrr	 554
#define SP_LDri	 555
#define SP_LDrr	 556
#define SP_LEAX_ADDri	 557
#define SP_LEA_ADDri	 558
#define SP_LZCNT	 559
#define SP_MEMBARi	 560
#define SP_MOVDTOX	 561
#define SP_MOVFCCri	 562
#define SP_MOVFCCrr	 563
#define SP_MOVICCri	 564
#define SP_MOVICCrr	 565
#define SP_MOVRGEZri	 566
#define SP_MOVRGEZrr	 567
#define SP_MOVRGZri	 568
#define SP_MOVRGZrr	 569
#define SP_MOVRLEZri	 570
#define SP_MOVRLEZrr	 571
#define SP_MOVRLZri	 572
#define SP_MOVRLZrr	 573
#define SP_MOVRNZri	 574
#define SP_MOVRNZrr	 575
#define SP_MOVRRZri	 576
#define SP_MOVRRZrr	 577
#define SP_MOVSTOSW	 578
#define SP_MOVSTOUW	 579
#define SP_MOVWTOS	 580
#define SP_MOVXCCri	 581
#define SP_MOVXCCrr	 582
#define SP_MOVXTOD	 583
#define SP_MULSCCri	 584
#define SP_MULSCCrr	 585
#define SP_MULXri	 586
#define SP_MULXrr	 587
#define SP_NOP	 588
#define SP_ORCCri	 589
#define SP_ORCCrr	 590
#define SP_ORNCCri	 591
#define SP_ORNCCrr	 592
#define SP_ORNri	 593
#define SP_ORNrr	 594
#define SP_ORXNrr	 595
#define SP_ORXri	 596
#define SP_ORXrr	 597
#define SP_ORri	 598
#define SP_ORrr	 599
#define SP_PDIST	 600
#define SP_PDISTN	 601
#define SP_POPCrr	 602
#define SP_PWRPSRri	 603
#define SP_PWRPSRrr	 604
#define SP_RDASR	 605
#define SP_RDPR	 606
#define SP_RDPSR	 607
#define SP_RDTBR	 608
#define SP_RDWIM	 609
#define SP_RESTOREri	 610
#define SP_RESTORErr	 611
#define SP_RET	 612
#define SP_RETL	 613
#define SP_RETTri	 614
#define SP_RETTrr	 615
#define SP_SAVEri	 616
#define SP_SAVErr	 617
#define SP_SDIVCCri	 618
#define SP_SDIVCCrr	 619
#define SP_SDIVXri	 620
#define SP_SDIVXrr	 621
#define SP_SDIVri	 622
#define SP_SDIVrr	 623
#define SP_SETHIXi	 624
#define SP_SETHIi	 625
#define SP_SHUTDOWN	 626
#define SP_SIAM	 627
#define SP_SIR	 628
#define SP_SLLXri	 629
#define SP_SLLXrr	 630
#define SP_SLLri	 631
#define SP_SLLrr	 632
#define SP_SMACri	 633
#define SP_SMACrr	 634
#define SP_SMULCCri	 635
#define SP_SMULCCrr	 636
#define SP_SMULri	 637
#define SP_SMULrr	 638
#define SP_SRAXri	 639
#define SP_SRAXrr	 640
#define SP_SRAri	 641
#define SP_SRArr	 642
#define SP_SRLXri	 643
#define SP_SRLXrr	 644
#define SP_SRLri	 645
#define SP_SRLrr	 646
#define SP_STArr	 647
#define SP_STBAR	 648
#define SP_STBArr	 649
#define SP_STBri	 650
#define SP_STBrr	 651
#define SP_STCSRri	 652
#define SP_STCSRrr	 653
#define SP_STCri	 654
#define SP_STCrr	 655
#define SP_STDArr	 656
#define SP_STDCQri	 657
#define SP_STDCQrr	 658
#define SP_STDCri	 659
#define SP_STDCrr	 660
#define SP_STDFArr	 661
#define SP_STDFQri	 662
#define SP_STDFQrr	 663
#define SP_STDFri	 664
#define SP_STDFrr	 665
#define SP_STDri	 666
#define SP_STDrr	 667
#define SP_STFArr	 668
#define SP_STFSRri	 669
#define SP_STFSRrr	 670
#define SP_STFri	 671
#define SP_STFrr	 672
#define SP_STHArr	 673
#define SP_STHri	 674
#define SP_STHrr	 675
#define SP_STQFArr	 676
#define SP_STQFri	 677
#define SP_STQFrr	 678
#define SP_STXFSRri	 679
#define SP_STXFSRrr	 680
#define SP_STXri	 681
#define SP_STXrr	 682
#define SP_STri	 683
#define SP_STrr	 684
#define SP_SUBCCri	 685
#define SP_SUBCCrr	 686
#define SP_SUBCri	 687
#define SP_SUBCrr	 688
#define SP_SUBEri	 689
#define SP_SUBErr	 690
#define SP_SUBXri	 691
#define SP_SUBXrr	 692
#define SP_SUBri	 693
#define SP_SUBrr	 694
#define SP_SWAPArr	 695
#define SP_SWAPri	 696
#define SP_SWAPrr	 697
#define SP_TA1	 698
#define SP_TA3	 699
#define SP_TA5	 700
#define SP_TADDCCTVri	 701
#define SP_TADDCCTVrr	 702
#define SP_TADDCCri	 703
#define SP_TADDCCrr	 704
#define SP_TICCri	 705
#define SP_TICCrr	 706
#define SP_TLS_ADDXrr	 707
#define SP_TLS_ADDrr	 708
#define SP_TLS_CALL	 709
#define SP_TLS_LDXrr	 710
#define SP_TLS_LDrr	 711
#define SP_TRAPri	 712
#define SP_TRAPrr	 713
#define SP_TSUBCCTVri	 714
#define SP_TSUBCCTVrr	 715
#define SP_TSUBCCri	 716
#define SP_TSUBCCrr	 717
#define SP_TXCCri	 718
#define SP_TXCCrr	 719
#define SP_UDIVCCri	 720
#define SP_UDIVCCrr	 721
#define SP_UDIVXri	 722
#define SP_UDIVXrr	 723
#define SP_UDIVri	 724
#define SP_UDIVrr	 725
#define SP_UMACri	 726
#define SP_UMACrr	 727
#define SP_UMULCCri	 728
#define SP_UMULCCrr	 729
#define SP_UMULXHI	 730
#define SP_UMULri	 731
#define SP_UMULrr	 732
#define SP_UNIMP	 733
#define SP_V9FCMPD	 734
#define SP_V9FCMPED	 735
#define SP_V9FCMPEQ	 736
#define SP_V9FCMPES	 737
#define SP_V9FCMPQ	 738
#define SP_V9FCMPS	 739
#define SP_V9FMOVD_FCC	 740
#define SP_V9FMOVQ_FCC	 741
#define SP_V9FMOVS_FCC	 742
#define SP_V9MOVFCCri	 743
#define SP_V9MOVFCCrr	 744
#define SP_WRASRri	 745
#define SP_WRASRrr	 746
#define SP_WRPRri	 747
#define SP_WRPRrr	 748
#define SP_WRPSRri	 749
#define SP_WRPSRrr	 750
#define SP_WRTBRri	 751
#define SP_WRTBRrr	 752
#define SP_WRWIMri	 753
#define SP_WRWIMrr	 754
#define SP_XMULX	 755
#define SP_XMULXHI	 756
#define SP_XNORCCri	 757
#define SP_XNORCCrr	 758
#define SP_XNORXrr	 759
#define SP_XNORri	 760
#define SP_XNORrr	 761
#define SP_XORCCri	 762
#define SP_XORCCrr	 763
#define SP_XORXri	 764
#define SP_XORXrr	 765
#define SP_XORri	 766
#define SP_XORrr	 767
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
  /* 0 */ 64871, 1, 1, 1, 0,
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
  /* 85 */ 65183, 1, 0,
  /* 88 */ 65235, 1, 0,
  /* 91 */ 65263, 1, 0,
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

static const char SparcRegStrings[] = {
  /* 0 */ 'C', '1', '0', 0,
  /* 4 */ 'D', '1', '0', 0,
  /* 8 */ 'F', '1', '0', 0,
  /* 12 */ 'Q', '1', '0', 0,
  /* 16 */ 'A', 'S', 'R', '1', '0', 0,
  /* 22 */ 'C', '2', '0', 0,
  /* 26 */ 'D', '2', '0', 0,
  /* 30 */ 'F', '2', '0', 0,
  /* 34 */ 'A', 'S', 'R', '2', '0', 0,
  /* 40 */ 'C', '3', '0', 0,
  /* 44 */ 'D', '3', '0', 0,
  /* 48 */ 'F', '3', '0', 0,
  /* 52 */ 'A', 'S', 'R', '3', '0', 0,
  /* 58 */ 'F', 'C', 'C', '0', 0,
  /* 63 */ 'D', '0', 0,
  /* 66 */ 'F', '0', 0,
  /* 69 */ 'G', '0', 0,
  /* 72 */ 'I', '0', 0,
  /* 75 */ 'L', '0', 0,
  /* 78 */ 'O', '0', 0,
  /* 81 */ 'Q', '0', 0,
  /* 84 */ 'C', '1', '0', '_', 'C', '1', '1', 0,
  /* 92 */ 'D', '1', '1', 0,
  /* 96 */ 'F', '1', '1', 0,
  /* 100 */ 'Q', '1', '1', 0,
  /* 104 */ 'A', 'S', 'R', '1', '1', 0,
  /* 110 */ 'C', '2', '0', '_', 'C', '2', '1', 0,
  /* 118 */ 'D', '2', '1', 0,
  /* 122 */ 'F', '2', '1', 0,
  /* 126 */ 'A', 'S', 'R', '2', '1', 0,
  /* 132 */ 'C', '3', '0', '_', 'C', '3', '1', 0,
  /* 140 */ 'D', '3', '1', 0,
  /* 144 */ 'F', '3', '1', 0,
  /* 148 */ 'A', 'S', 'R', '3', '1', 0,
  /* 154 */ 'F', 'C', 'C', '1', 0,
  /* 159 */ 'C', '0', '_', 'C', '1', 0,
  /* 165 */ 'D', '1', 0,
  /* 168 */ 'F', '1', 0,
  /* 171 */ 'G', '0', '_', 'G', '1', 0,
  /* 177 */ 'I', '0', '_', 'I', '1', 0,
  /* 183 */ 'L', '0', '_', 'L', '1', 0,
  /* 189 */ 'O', '0', '_', 'O', '1', 0,
  /* 195 */ 'Q', '1', 0,
  /* 198 */ 'A', 'S', 'R', '1', 0,
  /* 203 */ 'C', '1', '2', 0,
  /* 207 */ 'D', '1', '2', 0,
  /* 211 */ 'F', '1', '2', 0,
  /* 215 */ 'Q', '1', '2', 0,
  /* 219 */ 'A', 'S', 'R', '1', '2', 0,
  /* 225 */ 'C', '2', '2', 0,
  /* 229 */ 'D', '2', '2', 0,
  /* 233 */ 'F', '2', '2', 0,
  /* 237 */ 'A', 'S', 'R', '2', '2', 0,
  /* 243 */ 'F', 'C', 'C', '2', 0,
  /* 248 */ 'D', '2', 0,
  /* 251 */ 'F', '2', 0,
  /* 254 */ 'G', '2', 0,
  /* 257 */ 'I', '2', 0,
  /* 260 */ 'L', '2', 0,
  /* 263 */ 'O', '2', 0,
  /* 266 */ 'Q', '2', 0,
  /* 269 */ 'A', 'S', 'R', '2', 0,
  /* 274 */ 'C', '1', '2', '_', 'C', '1', '3', 0,
  /* 282 */ 'D', '1', '3', 0,
  /* 286 */ 'F', '1', '3', 0,
  /* 290 */ 'Q', '1', '3', 0,
  /* 294 */ 'A', 'S', 'R', '1', '3', 0,
  /* 300 */ 'C', '2', '2', '_', 'C', '2', '3', 0,
  /* 308 */ 'D', '2', '3', 0,
  /* 312 */ 'F', '2', '3', 0,
  /* 316 */ 'A', 'S', 'R', '2', '3', 0,
  /* 322 */ 'F', 'C', 'C', '3', 0,
  /* 327 */ 'C', '2', '_', 'C', '3', 0,
  /* 333 */ 'D', '3', 0,
  /* 336 */ 'F', '3', 0,
  /* 339 */ 'G', '2', '_', 'G', '3', 0,
  /* 345 */ 'I', '2', '_', 'I', '3', 0,
  /* 351 */ 'L', '2', '_', 'L', '3', 0,
  /* 357 */ 'O', '2', '_', 'O', '3', 0,
  /* 363 */ 'Q', '3', 0,
  /* 366 */ 'A', 'S', 'R', '3', 0,
  /* 371 */ 'C', '1', '4', 0,
  /* 375 */ 'D', '1', '4', 0,
  /* 379 */ 'F', '1', '4', 0,
  /* 383 */ 'Q', '1', '4', 0,
  /* 387 */ 'A', 'S', 'R', '1', '4', 0,
  /* 393 */ 'C', '2', '4', 0,
  /* 397 */ 'D', '2', '4', 0,
  /* 401 */ 'F', '2', '4', 0,
  /* 405 */ 'A', 'S', 'R', '2', '4', 0,
  /* 411 */ 'C', '4', 0,
  /* 414 */ 'D', '4', 0,
  /* 417 */ 'F', '4', 0,
  /* 420 */ 'G', '4', 0,
  /* 423 */ 'I', '4', 0,
  /* 426 */ 'L', '4', 0,
  /* 429 */ 'O', '4', 0,
  /* 432 */ 'Q', '4', 0,
  /* 435 */ 'A', 'S', 'R', '4', 0,
  /* 440 */ 'C', '1', '4', '_', 'C', '1', '5', 0,
  /* 448 */ 'D', '1', '5', 0,
  /* 452 */ 'F', '1', '5', 0,
  /* 456 */ 'Q', '1', '5', 0,
  /* 460 */ 'A', 'S', 'R', '1', '5', 0,
  /* 466 */ 'C', '2', '4', '_', 'C', '2', '5', 0,
  /* 474 */ 'D', '2', '5', 0,
  /* 478 */ 'F', '2', '5', 0,
  /* 482 */ 'A', 'S', 'R', '2', '5', 0,
  /* 488 */ 'C', '4', '_', 'C', '5', 0,
  /* 494 */ 'D', '5', 0,
  /* 497 */ 'F', '5', 0,
  /* 500 */ 'G', '4', '_', 'G', '5', 0,
  /* 506 */ 'I', '4', '_', 'I', '5', 0,
  /* 512 */ 'L', '4', '_', 'L', '5', 0,
  /* 518 */ 'O', '4', '_', 'O', '5', 0,
  /* 524 */ 'Q', '5', 0,
  /* 527 */ 'A', 'S', 'R', '5', 0,
  /* 532 */ 'C', '1', '6', 0,
  /* 536 */ 'D', '1', '6', 0,
  /* 540 */ 'F', '1', '6', 0,
  /* 544 */ 'A', 'S', 'R', '1', '6', 0,
  /* 550 */ 'C', '2', '6', 0,
  /* 554 */ 'D', '2', '6', 0,
  /* 558 */ 'F', '2', '6', 0,
  /* 562 */ 'A', 'S', 'R', '2', '6', 0,
  /* 568 */ 'C', '6', 0,
  /* 571 */ 'D', '6', 0,
  /* 574 */ 'F', '6', 0,
  /* 577 */ 'G', '6', 0,
  /* 580 */ 'I', '6', 0,
  /* 583 */ 'L', '6', 0,
  /* 586 */ 'O', '6', 0,
  /* 589 */ 'Q', '6', 0,
  /* 592 */ 'A', 'S', 'R', '6', 0,
  /* 597 */ 'C', '1', '6', '_', 'C', '1', '7', 0,
  /* 605 */ 'D', '1', '7', 0,
  /* 609 */ 'F', '1', '7', 0,
  /* 613 */ 'A', 'S', 'R', '1', '7', 0,
  /* 619 */ 'C', '2', '6', '_', 'C', '2', '7', 0,
  /* 627 */ 'D', '2', '7', 0,
  /* 631 */ 'F', '2', '7', 0,
  /* 635 */ 'A', 'S', 'R', '2', '7', 0,
  /* 641 */ 'C', '6', '_', 'C', '7', 0,
  /* 647 */ 'D', '7', 0,
  /* 650 */ 'F', '7', 0,
  /* 653 */ 'G', '6', '_', 'G', '7', 0,
  /* 659 */ 'I', '6', '_', 'I', '7', 0,
  /* 665 */ 'L', '6', '_', 'L', '7', 0,
  /* 671 */ 'O', '6', '_', 'O', '7', 0,
  /* 677 */ 'Q', '7', 0,
  /* 680 */ 'A', 'S', 'R', '7', 0,
  /* 685 */ 'C', '1', '8', 0,
  /* 689 */ 'D', '1', '8', 0,
  /* 693 */ 'F', '1', '8', 0,
  /* 697 */ 'A', 'S', 'R', '1', '8', 0,
  /* 703 */ 'C', '2', '8', 0,
  /* 707 */ 'D', '2', '8', 0,
  /* 711 */ 'F', '2', '8', 0,
  /* 715 */ 'A', 'S', 'R', '2', '8', 0,
  /* 721 */ 'C', '8', 0,
  /* 724 */ 'D', '8', 0,
  /* 727 */ 'F', '8', 0,
  /* 730 */ 'Q', '8', 0,
  /* 733 */ 'A', 'S', 'R', '8', 0,
  /* 738 */ 'C', '1', '8', '_', 'C', '1', '9', 0,
  /* 746 */ 'D', '1', '9', 0,
  /* 750 */ 'F', '1', '9', 0,
  /* 754 */ 'A', 'S', 'R', '1', '9', 0,
  /* 760 */ 'C', '2', '8', '_', 'C', '2', '9', 0,
  /* 768 */ 'D', '2', '9', 0,
  /* 772 */ 'F', '2', '9', 0,
  /* 776 */ 'A', 'S', 'R', '2', '9', 0,
  /* 782 */ 'C', '8', '_', 'C', '9', 0,
  /* 788 */ 'D', '9', 0,
  /* 791 */ 'F', '9', 0,
  /* 794 */ 'Q', '9', 0,
  /* 797 */ 'A', 'S', 'R', '9', 0,
  /* 802 */ 'T', 'B', 'A', 0,
  /* 806 */ 'I', 'C', 'C', 0,
  /* 810 */ 'T', 'N', 'P', 'C', 0,
  /* 815 */ 'T', 'P', 'C', 0,
  /* 819 */ 'C', 'A', 'N', 'R', 'E', 'S', 'T', 'O', 'R', 'E', 0,
  /* 830 */ 'P', 'S', 'T', 'A', 'T', 'E', 0,
  /* 837 */ 'T', 'S', 'T', 'A', 'T', 'E', 0,
  /* 844 */ 'W', 'S', 'T', 'A', 'T', 'E', 0,
  /* 851 */ 'C', 'A', 'N', 'S', 'A', 'V', 'E', 0,
  /* 859 */ 'T', 'I', 'C', 'K', 0,
  /* 864 */ 'P', 'I', 'L', 0,
  /* 868 */ 'T', 'L', 0,
  /* 871 */ 'W', 'I', 'M', 0,
  /* 875 */ 'C', 'L', 'E', 'A', 'N', 'W', 'I', 'N', 0,
  /* 884 */ 'O', 'T', 'H', 'E', 'R', 'W', 'I', 'N', 0,
  /* 893 */ 'C', 'W', 'P', 0,
  /* 897 */ 'F', 'Q', 0,
  /* 900 */ 'C', 'P', 'Q', 0,
  /* 904 */ 'T', 'B', 'R', 0,
  /* 908 */ 'F', 'S', 'R', 0,
  /* 912 */ 'C', 'P', 'S', 'R', 0,
  /* 917 */ 'T', 'T', 0,
  /* 920 */ 'Y', 0,

};

static const MCRegisterDesc SparcRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0 },
  { 819, 4, 4, 2, 6065, 1 },
  { 851, 4, 4, 2, 6065, 114 },
  { 875, 4, 4, 2, 6065, 1 },
  { 900, 4, 4, 2, 6065, 1 },
  { 912, 4, 4, 2, 6065, 1 },
  { 893, 4, 4, 2, 6065, 1 },
  { 897, 4, 4, 2, 6065, 1 },
  { 908, 4, 4, 2, 6065, 1 },
  { 806, 4, 4, 2, 6065, 62 },
  { 884, 4, 4, 2, 6065, 296 },
  { 864, 4, 4, 2, 6065, 106 },
  { 913, 4, 4, 2, 6065, 92 },
  { 830, 4, 4, 2, 6065, 101 },
  { 802, 4, 4, 2, 6065, 318 },
  { 904, 4, 4, 2, 6065, 241 },
  { 859, 4, 4, 2, 6065, 1 },
  { 868, 4, 4, 2, 6065, 298 },
  { 810, 4, 4, 2, 6065, 1 },
  { 815, 4, 4, 2, 6065, 32 },
  { 837, 4, 4, 2, 6065, 57 },
  { 917, 4, 4, 2, 6065, 4 },
  { 871, 4, 4, 2, 6065, 1 },
  { 844, 4, 4, 2, 6065, 233 },
  { 920, 4, 4, 2, 6065, 1 },
  { 198, 4, 4, 2, 6065, 237 },
  { 269, 4, 4, 2, 6065, 239 },
  { 366, 4, 4, 2, 6065, 108 },
  { 435, 4, 4, 2, 6065, 110 },
  { 527, 4, 4, 2, 6065, 1 },
  { 592, 4, 4, 2, 6065, 1 },
  { 680, 4, 4, 2, 6065, 1 },
  { 733, 4, 4, 2, 6065, 292 },
  { 797, 4, 4, 2, 6065, 235 },
  { 16, 4, 4, 2, 6065, 4 },
  { 104, 4, 4, 2, 6065, 294 },
  { 219, 4, 4, 2, 6065, 62 },
  { 294, 4, 4, 2, 6065, 228 },
  { 387, 4, 4, 2, 6065, 57 },
  { 460, 4, 4, 2, 6065, 62 },
  { 544, 4, 4, 2, 6065, 226 },
  { 613, 4, 4, 2, 6065, 1 },
  { 697, 4, 4, 2, 6065, 224 },
  { 754, 4, 4, 2, 6065, 1 },
  { 34, 4, 4, 2, 6065, 1 },
  { 126, 4, 4, 2, 6065, 271 },
  { 237, 4, 4, 2, 6065, 32 },
  { 316, 4, 4, 2, 6065, 51 },
  { 405, 4, 4, 2, 6065, 1 },
  { 482, 4, 4, 2, 6065, 316 },
  { 562, 4, 4, 2, 6065, 273 },
  { 635, 4, 4, 2, 6065, 283 },
  { 715, 4, 4, 2, 6065, 32 },
  { 776, 4, 4, 2, 6065, 51 },
  { 52, 4, 4, 2, 6065, 222 },
  { 148, 4, 4, 2, 6065, 62 },
  { 60, 4, 373, 2, 6065, 55 },
  { 156, 4, 371, 2, 6065, 285 },
  { 245, 4, 371, 2, 6065, 1 },
  { 324, 4, 369, 2, 6065, 281 },
  { 411, 4, 369, 2, 6065, 290 },
  { 491, 4, 367, 2, 6065, 1 },
  { 568, 4, 367, 2, 6065, 316 },
  { 644, 4, 365, 2, 6065, 62 },
  { 721, 4, 365, 2, 6065, 45 },
  { 785, 4, 363, 2, 6065, 62 },
  { 0, 4, 363, 2, 6065, 1 },
  { 88, 4, 361, 2, 6065, 62 },
  { 203, 4, 361, 2, 6065, 1 },
  { 278, 4, 359, 2, 6065, 62 },
  { 371, 4, 359, 2, 6065, 245 },
  { 444, 4, 357, 2, 6065, 243 },
  { 532, 4, 357, 2, 6065, 32 },
  { 601, 4, 355, 2, 6065, 1 },
  { 685, 4, 355, 2, 6065, 62 },
  { 742, 4, 353, 2, 6065, 247 },
  { 22, 4, 353, 2, 6065, 59 },
  { 114, 4, 351, 2, 6065, 4 },
  { 225, 4, 351, 2, 6065, 1 },
  { 304, 4, 349, 2, 6065, 249 },
  { 393, 4, 349, 2, 6065, 62 },
  { 470, 4, 347, 2, 6065, 251 },
  { 550, 4, 347, 2, 6065, 53 },
  { 623, 4, 345, 2, 6065, 10 },
  { 703, 4, 345, 2, 6065, 62 },
  { 764, 4, 343, 2, 6065, 235 },
  { 40, 4, 343, 2, 6065, 62 },
  { 136, 4, 341, 2, 6065, 316 },
  { 63, 5, 336, 0, 2418, 256 },
  { 165, 12, 327, 0, 2418, 77 },
  { 248, 15, 327, 0, 2418, 34 },
  { 333, 22, 318, 0, 2418, 253 },
  { 414, 25, 318, 0, 2418, 83 },
  { 494, 32, 309, 0, 2418, 259 },
  { 571, 35, 309, 0, 2418, 265 },
  { 647, 42, 300, 0, 2418, 80 },
  { 724, 45, 300, 0, 2418, 268 },
  { 788, 52, 291, 0, 2418, 6 },
  { 4, 55, 291, 0, 2418, 275 },
  { 92, 62, 282, 0, 2418, 262 },
  { 207, 65, 282, 0, 2418, 278 },
  { 282, 72, 273, 0, 2418, 64 },
  { 375, 75, 273, 0, 2418, 64 },
  { 448, 82, 267, 0, 2418, 0 },
  { 536, 4, 267, 2, 3425, 120 },
  { 605, 4, 264, 2, 3425, 88 },
  { 689, 4, 264, 2, 3425, 94 },
  { 746, 4, 262, 2, 3425, 112 },
  { 26, 4, 262, 2, 3425, 124 },
  { 118, 4, 260, 2, 3425, 62 },
  { 229, 4, 260, 2, 3425, 1 },
  { 308, 4, 258, 2, 3425, 62 },
  { 397, 4, 258, 2, 3425, 126 },
  { 474, 4, 256, 2, 3425, 62 },
  { 554, 4, 256, 2, 3425, 10 },
  { 627, 4, 254, 2, 3425, 62 },
  { 707, 4, 254, 2, 3425, 131 },
  { 768, 4, 252, 2, 3425, 1 },
  { 44, 4, 252, 2, 3425, 133 },
  { 140, 4, 250, 2, 3425, 1 },
  { 66, 4, 338, 2, 6001, 137 },
  { 168, 4, 335, 2, 6001, 139 },
  { 251, 4, 332, 2, 6001, 1 },
  { 336, 4, 329, 2, 6001, 62 },
  { 417, 4, 329, 2, 6001, 1 },
  { 497, 4, 326, 2, 6001, 62 },
  { 574, 4, 323, 2, 6001, 1 },
  { 650, 4, 320, 2, 6001, 62 },
  { 727, 4, 320, 2, 6001, 144 },
  { 791, 4, 317, 2, 6001, 135 },
  { 8, 4, 314, 2, 6001, 32 },
  { 96, 4, 311, 2, 6001, 1 },
  { 211, 4, 311, 2, 6001, 51 },
  { 286, 4, 308, 2, 6001, 146 },
  { 379, 4, 305, 2, 6001, 4 },
  { 452, 4, 302, 2, 6001, 1 },
  { 540, 4, 302, 2, 6001, 62 },
  { 609, 4, 299, 2, 6001, 1 },
  { 693, 4, 296, 2, 6001, 62 },
  { 750, 4, 293, 2, 6001, 148 },
  { 30, 4, 293, 2, 6001, 62 },
  { 122, 4, 290, 2, 6001, 10 },
  { 233, 4, 287, 2, 6001, 62 },
  { 312, 4, 284, 2, 6001, 300 },
  { 401, 4, 284, 2, 6001, 62 },
  { 478, 4, 281, 2, 6001, 316 },
  { 558, 4, 278, 2, 6001, 118 },
  { 631, 4, 275, 2, 6001, 122 },
  { 711, 4, 275, 2, 6001, 4 },
  { 772, 4, 272, 2, 6001, 1 },
  { 48, 4, 269, 2, 6001, 150 },
  { 144, 4, 266, 2, 6001, 116 },
  { 58, 4, 4, 2, 6033, 316 },
  { 154, 4, 4, 2, 6033, 1 },
  { 243, 4, 4, 2, 6033, 152 },
  { 322, 4, 4, 2, 6033, 1 },
  { 69, 4, 248, 2, 6033, 4 },
  { 174, 4, 246, 2, 6033, 57 },
  { 254, 4, 246, 2, 6033, 118 },
  { 342, 4, 244, 2, 6033, 30 },
  { 420, 4, 244, 2, 6033, 43 },
  { 503, 4, 242, 2, 6033, 160 },
  { 577, 4, 242, 2, 6033, 158 },
  { 656, 4, 240, 2, 6033, 86 },
  { 72, 4, 240, 2, 6033, 90 },
  { 180, 4, 238, 2, 6033, 99 },
  { 257, 4, 238, 2, 6033, 1 },
  { 348, 4, 236, 2, 6033, 1 },
  { 423, 4, 236, 2, 6033, 1 },
  { 509, 4, 234, 2, 6033, 1 },
  { 580, 4, 234, 2, 6033, 12 },
  { 662, 4, 232, 2, 6033, 14 },
  { 75, 4, 232, 2, 6033, 1 },
  { 186, 4, 230, 2, 6033, 10 },
  { 260, 4, 230, 2, 6033, 162 },
  { 354, 4, 228, 2, 6033, 16 },
  { 426, 4, 228, 2, 6033, 154 },
  { 515, 4, 226, 2, 6033, 1 },
  { 583, 4, 226, 2, 6033, 156 },
  { 668, 4, 224, 2, 6033, 1 },
  { 78, 4, 224, 2, 6033, 166 },
  { 192, 4, 222, 2, 6033, 164 },
  { 263, 4, 222, 2, 6033, 47 },
  { 360, 4, 220, 2, 6033, 168 },
  { 429, 4, 220, 2, 6033, 7 },
  { 521, 4, 218, 2, 6033, 49 },
  { 586, 4, 218, 2, 6033, 1 },
  { 674, 4, 216, 2, 6033, 170 },
  { 81, 8, 4, 6, 4, 182 },
  { 195, 18, 4, 6, 4, 172 },
  { 266, 28, 4, 6, 4, 177 },
  { 363, 38, 4, 6, 4, 187 },
  { 432, 48, 4, 6, 4, 21 },
  { 524, 58, 4, 6, 4, 72 },
  { 589, 68, 4, 6, 4, 302 },
  { 677, 78, 4, 6, 4, 67 },
  { 730, 142, 4, 3, 1458, 287 },
  { 794, 145, 4, 3, 1458, 310 },
  { 12, 148, 4, 3, 1458, 128 },
  { 100, 151, 4, 3, 1458, 192 },
  { 215, 154, 4, 3, 1458, 195 },
  { 290, 157, 4, 3, 1458, 198 },
  { 383, 160, 4, 3, 1458, 23 },
  { 456, 163, 4, 3, 1458, 0 },
  { 159, 94, 4, 0, 1362, 201 },
  { 327, 97, 4, 0, 1362, 204 },
  { 488, 100, 4, 0, 1362, 0 },
  { 641, 103, 4, 0, 1362, 26 },
  { 782, 106, 4, 0, 1362, 207 },
  { 84, 109, 4, 0, 1362, 103 },
  { 274, 112, 4, 0, 1362, 18 },
  { 440, 115, 4, 0, 1362, 9 },
  { 597, 118, 4, 0, 1362, 64 },
  { 738, 121, 4, 0, 1362, 64 },
  { 110, 124, 4, 0, 1362, 96 },
  { 300, 127, 4, 0, 1362, 230 },
  { 466, 130, 4, 0, 1362, 141 },
  { 619, 133, 4, 0, 1362, 3 },
  { 760, 136, 4, 0, 1362, 0 },
  { 132, 139, 4, 0, 1362, 61 },
  { 171, 166, 4, 0, 1410, 313 },
  { 339, 169, 4, 0, 1410, 0 },
  { 500, 172, 4, 0, 1410, 40 },
  { 653, 175, 4, 0, 1410, 6 },
  { 177, 178, 4, 0, 1410, 29 },
  { 345, 181, 4, 0, 1410, 64 },
  { 506, 184, 4, 0, 1410, 210 },
  { 659, 187, 4, 0, 1410, 64 },
  { 183, 190, 4, 0, 1410, 213 },
  { 351, 193, 4, 0, 1410, 64 },
  { 512, 196, 4, 0, 1410, 216 },
  { 665, 199, 4, 0, 1410, 307 },
  { 189, 202, 4, 0, 1410, 18 },
  { 357, 205, 4, 0, 1410, 37 },
  { 518, 208, 4, 0, 1410, 3 },
  { 671, 211, 4, 0, 1410, 219 },
};

  // FCCRegs Register Class...
  static const MCPhysReg FCCRegs[] = {
    SP_FCC0, SP_FCC1, SP_FCC2, SP_FCC3, 
  };

  // FCCRegs Bit set.
  static const uint8_t FCCRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 
  };

  // ASRRegs Register Class...
  static const MCPhysReg ASRRegs[] = {
    SP_Y, SP_ASR1, SP_ASR2, SP_ASR3, SP_ASR4, SP_ASR5, SP_ASR6, SP_ASR7, SP_ASR8, SP_ASR9, SP_ASR10, SP_ASR11, SP_ASR12, SP_ASR13, SP_ASR14, SP_ASR15, SP_ASR16, SP_ASR17, SP_ASR18, SP_ASR19, SP_ASR20, SP_ASR21, SP_ASR22, SP_ASR23, SP_ASR24, SP_ASR25, SP_ASR26, SP_ASR27, SP_ASR28, SP_ASR29, SP_ASR30, SP_ASR31, 
  };

  // ASRRegs Bit set.
  static const uint8_t ASRRegsBits[] = {
    0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
  };

  // CoprocRegs Register Class...
  static const MCPhysReg CoprocRegs[] = {
    SP_C0, SP_C1, SP_C2, SP_C3, SP_C4, SP_C5, SP_C6, SP_C7, SP_C8, SP_C9, SP_C10, SP_C11, SP_C12, SP_C13, SP_C14, SP_C15, SP_C16, SP_C17, SP_C18, SP_C19, SP_C20, SP_C21, SP_C22, SP_C23, SP_C24, SP_C25, SP_C26, SP_C27, SP_C28, SP_C29, SP_C30, SP_C31, 
  };

  // CoprocRegs Bit set.
  static const uint8_t CoprocRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
  };

  // FPRegs Register Class...
  static const MCPhysReg FPRegs[] = {
    SP_F0, SP_F1, SP_F2, SP_F3, SP_F4, SP_F5, SP_F6, SP_F7, SP_F8, SP_F9, SP_F10, SP_F11, SP_F12, SP_F13, SP_F14, SP_F15, SP_F16, SP_F17, SP_F18, SP_F19, SP_F20, SP_F21, SP_F22, SP_F23, SP_F24, SP_F25, SP_F26, SP_F27, SP_F28, SP_F29, SP_F30, SP_F31, 
  };

  // FPRegs Bit set.
  static const uint8_t FPRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
  };

  // IntRegs Register Class...
  static const MCPhysReg IntRegs[] = {
    SP_I0, SP_I1, SP_I2, SP_I3, SP_I4, SP_I5, SP_I6, SP_I7, SP_G0, SP_G1, SP_G2, SP_G3, SP_G4, SP_G5, SP_G6, SP_G7, SP_L0, SP_L1, SP_L2, SP_L3, SP_L4, SP_L5, SP_L6, SP_L7, SP_O0, SP_O1, SP_O2, SP_O3, SP_O4, SP_O5, SP_O6, SP_O7, 
  };

  // IntRegs Bit set.
  static const uint8_t IntRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // DFPRegs Register Class...
  static const MCPhysReg DFPRegs[] = {
    SP_D0, SP_D1, SP_D2, SP_D3, SP_D4, SP_D5, SP_D6, SP_D7, SP_D8, SP_D9, SP_D10, SP_D11, SP_D12, SP_D13, SP_D14, SP_D15, SP_D16, SP_D17, SP_D18, SP_D19, SP_D20, SP_D21, SP_D22, SP_D23, SP_D24, SP_D25, SP_D26, SP_D27, SP_D28, SP_D29, SP_D30, SP_D31, 
  };

  // DFPRegs Bit set.
  static const uint8_t DFPRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
  };

  // I64Regs Register Class...
  static const MCPhysReg I64Regs[] = {
    SP_I0, SP_I1, SP_I2, SP_I3, SP_I4, SP_I5, SP_I6, SP_I7, SP_G0, SP_G1, SP_G2, SP_G3, SP_G4, SP_G5, SP_G6, SP_G7, SP_L0, SP_L1, SP_L2, SP_L3, SP_L4, SP_L5, SP_L6, SP_L7, SP_O0, SP_O1, SP_O2, SP_O3, SP_O4, SP_O5, SP_O6, SP_O7, 
  };

  // I64Regs Bit set.
  static const uint8_t I64RegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // CoprocPair Register Class...
  static const MCPhysReg CoprocPair[] = {
    SP_C0_C1, SP_C2_C3, SP_C4_C5, SP_C6_C7, SP_C8_C9, SP_C10_C11, SP_C12_C13, SP_C14_C15, SP_C16_C17, SP_C18_C19, SP_C20_C21, SP_C22_C23, SP_C24_C25, SP_C26_C27, SP_C28_C29, SP_C30_C31, 
  };

  // CoprocPair Bit set.
  static const uint8_t CoprocPairBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // IntPair Register Class...
  static const MCPhysReg IntPair[] = {
    SP_I0_I1, SP_I2_I3, SP_I4_I5, SP_I6_I7, SP_G0_G1, SP_G2_G3, SP_G4_G5, SP_G6_G7, SP_L0_L1, SP_L2_L3, SP_L4_L5, SP_L6_L7, SP_O0_O1, SP_O2_O3, SP_O4_O5, SP_O6_O7, 
  };

  // IntPair Bit set.
  static const uint8_t IntPairBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // LowDFPRegs Register Class...
  static const MCPhysReg LowDFPRegs[] = {
    SP_D0, SP_D1, SP_D2, SP_D3, SP_D4, SP_D5, SP_D6, SP_D7, SP_D8, SP_D9, SP_D10, SP_D11, SP_D12, SP_D13, SP_D14, SP_D15, 
  };

  // LowDFPRegs Bit set.
  static const uint8_t LowDFPRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 
  };

  // PRRegs Register Class...
  static const MCPhysReg PRRegs[] = {
    SP_TPC, SP_TNPC, SP_TSTATE, SP_TT, SP_TICK, SP_TBA, SP_PSTATE, SP_TL, SP_PIL, SP_CWP, SP_CANSAVE, SP_CANRESTORE, SP_CLEANWIN, SP_OTHERWIN, SP_WSTATE, 
  };

  // PRRegs Bit set.
  static const uint8_t PRRegsBits[] = {
    0x4e, 0x6c, 0xbf, 
  };

  // QFPRegs Register Class...
  static const MCPhysReg QFPRegs[] = {
    SP_Q0, SP_Q1, SP_Q2, SP_Q3, SP_Q4, SP_Q5, SP_Q6, SP_Q7, SP_Q8, SP_Q9, SP_Q10, SP_Q11, SP_Q12, SP_Q13, SP_Q14, SP_Q15, 
  };

  // QFPRegs Bit set.
  static const uint8_t QFPRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // LowQFPRegs Register Class...
  static const MCPhysReg LowQFPRegs[] = {
    SP_Q0, SP_Q1, SP_Q2, SP_Q3, SP_Q4, SP_Q5, SP_Q6, SP_Q7, 
  };

  // LowQFPRegs Bit set.
  static const uint8_t LowQFPRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

// end of register classes misc

static const char SparcRegClassStrings[] = {
  /* 0 */ 'C', 'o', 'p', 'r', 'o', 'c', 'P', 'a', 'i', 'r', 0,
  /* 11 */ 'I', 'n', 't', 'P', 'a', 'i', 'r', 0,
  /* 19 */ 'I', '6', '4', 'R', 'e', 'g', 's', 0,
  /* 27 */ 'F', 'C', 'C', 'R', 'e', 'g', 's', 0,
  /* 35 */ 'L', 'o', 'w', 'D', 'F', 'P', 'R', 'e', 'g', 's', 0,
  /* 46 */ 'L', 'o', 'w', 'Q', 'F', 'P', 'R', 'e', 'g', 's', 0,
  /* 57 */ 'P', 'R', 'R', 'e', 'g', 's', 0,
  /* 64 */ 'A', 'S', 'R', 'R', 'e', 'g', 's', 0,
  /* 72 */ 'C', 'o', 'p', 'r', 'o', 'c', 'R', 'e', 'g', 's', 0,
  /* 83 */ 'I', 'n', 't', 'R', 'e', 'g', 's', 0,

};

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
  static const char AsmStrs[] = {
  /* 0 */ 'r', 'd', 32, '%', 'w', 'i', 'm', ',', 32, 0,
  /* 10 */ 'r', 'd', 32, '%', 't', 'b', 'r', ',', 32, 0,
  /* 20 */ 'r', 'd', 32, '%', 'p', 's', 'r', ',', 32, 0,
  /* 30 */ 'f', 's', 'r', 'c', '1', 32, 0,
  /* 37 */ 'f', 'a', 'n', 'd', 'n', 'o', 't', '1', 32, 0,
  /* 47 */ 'f', 'n', 'o', 't', '1', 32, 0,
  /* 54 */ 'f', 'o', 'r', 'n', 'o', 't', '1', 32, 0,
  /* 63 */ 'f', 's', 'r', 'a', '3', '2', 32, 0,
  /* 71 */ 'f', 'p', 's', 'u', 'b', '3', '2', 32, 0,
  /* 80 */ 'f', 'p', 'a', 'd', 'd', '3', '2', 32, 0,
  /* 89 */ 'e', 'd', 'g', 'e', '3', '2', 32, 0,
  /* 97 */ 'f', 'c', 'm', 'p', 'l', 'e', '3', '2', 32, 0,
  /* 107 */ 'f', 'c', 'm', 'p', 'n', 'e', '3', '2', 32, 0,
  /* 117 */ 'f', 'p', 'a', 'c', 'k', '3', '2', 32, 0,
  /* 126 */ 'c', 'm', 'a', 's', 'k', '3', '2', 32, 0,
  /* 135 */ 'f', 's', 'l', 'l', '3', '2', 32, 0,
  /* 143 */ 'f', 's', 'r', 'l', '3', '2', 32, 0,
  /* 151 */ 'f', 'c', 'm', 'p', 'e', 'q', '3', '2', 32, 0,
  /* 161 */ 'f', 's', 'l', 'a', 's', '3', '2', 32, 0,
  /* 170 */ 'f', 'c', 'm', 'p', 'g', 't', '3', '2', 32, 0,
  /* 180 */ 'a', 'r', 'r', 'a', 'y', '3', '2', 32, 0,
  /* 189 */ 'f', 's', 'r', 'c', '2', 32, 0,
  /* 196 */ 'f', 'a', 'n', 'd', 'n', 'o', 't', '2', 32, 0,
  /* 206 */ 'f', 'n', 'o', 't', '2', 32, 0,
  /* 213 */ 'f', 'o', 'r', 'n', 'o', 't', '2', 32, 0,
  /* 222 */ 'f', 'p', 'a', 'd', 'd', '6', '4', 32, 0,
  /* 231 */ 'f', 's', 'r', 'a', '1', '6', 32, 0,
  /* 239 */ 'f', 'p', 's', 'u', 'b', '1', '6', 32, 0,
  /* 248 */ 'f', 'p', 'a', 'd', 'd', '1', '6', 32, 0,
  /* 257 */ 'e', 'd', 'g', 'e', '1', '6', 32, 0,
  /* 265 */ 'f', 'c', 'm', 'p', 'l', 'e', '1', '6', 32, 0,
  /* 275 */ 'f', 'c', 'm', 'p', 'n', 'e', '1', '6', 32, 0,
  /* 285 */ 'f', 'p', 'a', 'c', 'k', '1', '6', 32, 0,
  /* 294 */ 'c', 'm', 'a', 's', 'k', '1', '6', 32, 0,
  /* 303 */ 'f', 's', 'l', 'l', '1', '6', 32, 0,
  /* 311 */ 'f', 's', 'r', 'l', '1', '6', 32, 0,
  /* 319 */ 'f', 'c', 'h', 'k', 's', 'm', '1', '6', 32, 0,
  /* 329 */ 'f', 'm', 'e', 'a', 'n', '1', '6', 32, 0,
  /* 338 */ 'f', 'c', 'm', 'p', 'e', 'q', '1', '6', 32, 0,
  /* 348 */ 'f', 's', 'l', 'a', 's', '1', '6', 32, 0,
  /* 357 */ 'f', 'c', 'm', 'p', 'g', 't', '1', '6', 32, 0,
  /* 367 */ 'f', 'm', 'u', 'l', '8', 'x', '1', '6', 32, 0,
  /* 377 */ 'f', 'm', 'u', 'l', 'd', '8', 'u', 'l', 'x', '1', '6', 32, 0,
  /* 390 */ 'f', 'm', 'u', 'l', '8', 'u', 'l', 'x', '1', '6', 32, 0,
  /* 402 */ 'f', 'm', 'u', 'l', 'd', '8', 's', 'u', 'x', '1', '6', 32, 0,
  /* 415 */ 'f', 'm', 'u', 'l', '8', 's', 'u', 'x', '1', '6', 32, 0,
  /* 427 */ 'a', 'r', 'r', 'a', 'y', '1', '6', 32, 0,
  /* 436 */ 'e', 'd', 'g', 'e', '8', 32, 0,
  /* 443 */ 'c', 'm', 'a', 's', 'k', '8', 32, 0,
  /* 451 */ 'a', 'r', 'r', 'a', 'y', '8', 32, 0,
  /* 459 */ '!', 'A', 'D', 'J', 'C', 'A', 'L', 'L', 'S', 'T', 'A', 'C', 'K', 'D', 'O', 'W', 'N', 32, 0,
  /* 478 */ '!', 'A', 'D', 'J', 'C', 'A', 'L', 'L', 'S', 'T', 'A', 'C', 'K', 'U', 'P', 32, 0,
  /* 495 */ 'f', 'p', 's', 'u', 'b', '3', '2', 'S', 32, 0,
  /* 505 */ 'f', 'p', 's', 'u', 'b', '1', '6', 'S', 32, 0,
  /* 515 */ 'b', 'r', 'g', 'e', 'z', ',', 'a', 32, 0,
  /* 524 */ 'b', 'r', 'l', 'e', 'z', ',', 'a', 32, 0,
  /* 533 */ 'b', 'r', 'g', 'z', ',', 'a', 32, 0,
  /* 541 */ 'b', 'r', 'l', 'z', ',', 'a', 32, 0,
  /* 549 */ 'b', 'r', 'n', 'z', ',', 'a', 32, 0,
  /* 557 */ 'b', 'r', 'z', ',', 'a', 32, 0,
  /* 564 */ 's', 't', 'b', 'a', 32, 0,
  /* 570 */ 's', 't', 'd', 'a', 32, 0,
  /* 576 */ 's', 't', 'h', 'a', 32, 0,
  /* 582 */ 's', 't', 'q', 'a', 32, 0,
  /* 588 */ 's', 'r', 'a', 32, 0,
  /* 593 */ 'f', 'a', 'l', 'i', 'g', 'n', 'd', 'a', 't', 'a', 32, 0,
  /* 605 */ 's', 't', 'a', 32, 0,
  /* 610 */ 's', 't', 'b', 32, 0,
  /* 615 */ 's', 'u', 'b', 32, 0,
  /* 620 */ 's', 'm', 'a', 'c', 32, 0,
  /* 626 */ 'u', 'm', 'a', 'c', 32, 0,
  /* 632 */ 't', 's', 'u', 'b', 'c', 'c', 32, 0,
  /* 640 */ 'a', 'd', 'd', 'x', 'c', 'c', 'c', 32, 0,
  /* 649 */ 't', 'a', 'd', 'd', 'c', 'c', 32, 0,
  /* 657 */ 'a', 'n', 'd', 'c', 'c', 32, 0,
  /* 664 */ 's', 'm', 'u', 'l', 'c', 'c', 32, 0,
  /* 672 */ 'u', 'm', 'u', 'l', 'c', 'c', 32, 0,
  /* 680 */ 'a', 'n', 'd', 'n', 'c', 'c', 32, 0,
  /* 688 */ 'o', 'r', 'n', 'c', 'c', 32, 0,
  /* 695 */ 'x', 'n', 'o', 'r', 'c', 'c', 32, 0,
  /* 703 */ 'x', 'o', 'r', 'c', 'c', 32, 0,
  /* 710 */ 'm', 'u', 'l', 's', 'c', 'c', 32, 0,
  /* 718 */ 's', 'd', 'i', 'v', 'c', 'c', 32, 0,
  /* 726 */ 'u', 'd', 'i', 'v', 'c', 'c', 32, 0,
  /* 734 */ 's', 'u', 'b', 'x', 'c', 'c', 32, 0,
  /* 742 */ 'a', 'd', 'd', 'x', 'c', 'c', 32, 0,
  /* 750 */ 'p', 'o', 'p', 'c', 32, 0,
  /* 756 */ 'a', 'd', 'd', 'x', 'c', 32, 0,
  /* 763 */ 'f', 's', 'u', 'b', 'd', 32, 0,
  /* 770 */ 'f', 'h', 's', 'u', 'b', 'd', 32, 0,
  /* 778 */ 'a', 'd', 'd', 32, 0,
  /* 783 */ 'f', 'a', 'd', 'd', 'd', 32, 0,
  /* 790 */ 'f', 'h', 'a', 'd', 'd', 'd', 32, 0,
  /* 798 */ 'f', 'n', 'h', 'a', 'd', 'd', 'd', 32, 0,
  /* 807 */ 'f', 'n', 'a', 'd', 'd', 'd', 32, 0,
  /* 815 */ 'f', 'c', 'm', 'p', 'e', 'd', 32, 0,
  /* 823 */ 'f', 'n', 'e', 'g', 'd', 32, 0,
  /* 830 */ 'f', 'm', 'u', 'l', 'd', 32, 0,
  /* 837 */ 'f', 's', 'm', 'u', 'l', 'd', 32, 0,
  /* 845 */ 'f', 'a', 'n', 'd', 32, 0,
  /* 851 */ 'f', 'n', 'a', 'n', 'd', 32, 0,
  /* 858 */ 'f', 'e', 'x', 'p', 'a', 'n', 'd', 32, 0,
  /* 867 */ 'f', 'i', 't', 'o', 'd', 32, 0,
  /* 874 */ 'f', 'q', 't', 'o', 'd', 32, 0,
  /* 881 */ 'f', 's', 't', 'o', 'd', 32, 0,
  /* 888 */ 'f', 'x', 't', 'o', 'd', 32, 0,
  /* 895 */ 'f', 'c', 'm', 'p', 'd', 32, 0,
  /* 902 */ 'f', 'l', 'c', 'm', 'p', 'd', 32, 0,
  /* 910 */ 'r', 'd', 32, 0,
  /* 914 */ 'f', 'a', 'b', 's', 'd', 32, 0,
  /* 921 */ 'f', 's', 'q', 'r', 't', 'd', 32, 0,
  /* 929 */ 's', 't', 'd', 32, 0,
  /* 934 */ 'f', 'd', 'i', 'v', 'd', 32, 0,
  /* 941 */ 'f', 'm', 'o', 'v', 'd', 32, 0,
  /* 948 */ 'f', 'p', 'm', 'e', 'r', 'g', 'e', 32, 0,
  /* 957 */ 'b', 's', 'h', 'u', 'f', 'f', 'l', 'e', 32, 0,
  /* 967 */ 'f', 'o', 'n', 'e', 32, 0,
  /* 973 */ 'r', 'e', 's', 't', 'o', 'r', 'e', 32, 0,
  /* 982 */ 's', 'a', 'v', 'e', 32, 0,
  /* 988 */ 'f', 'l', 'u', 's', 'h', 32, 0,
  /* 995 */ 's', 't', 'h', 32, 0,
  /* 1000 */ 's', 'e', 't', 'h', 'i', 32, 0,
  /* 1007 */ 'u', 'm', 'u', 'l', 'x', 'h', 'i', 32, 0,
  /* 1016 */ 'x', 'm', 'u', 'l', 'x', 'h', 'i', 32, 0,
  /* 1025 */ 'f', 'd', 't', 'o', 'i', 32, 0,
  /* 1032 */ 'f', 'q', 't', 'o', 'i', 32, 0,
  /* 1039 */ 'f', 's', 't', 'o', 'i', 32, 0,
  /* 1046 */ 'b', 'm', 'a', 's', 'k', 32, 0,
  /* 1053 */ 'e', 'd', 'g', 'e', '3', '2', 'l', 32, 0,
  /* 1062 */ 'e', 'd', 'g', 'e', '1', '6', 'l', 32, 0,
  /* 1071 */ 'e', 'd', 'g', 'e', '8', 'l', 32, 0,
  /* 1079 */ 'f', 'm', 'u', 'l', '8', 'x', '1', '6', 'a', 'l', 32, 0,
  /* 1091 */ 'c', 'a', 'l', 'l', 32, 0,
  /* 1097 */ 's', 'l', 'l', 32, 0,
  /* 1102 */ 'j', 'm', 'p', 'l', 32, 0,
  /* 1108 */ 'a', 'l', 'i', 'g', 'n', 'a', 'd', 'd', 'r', 'l', 32, 0,
  /* 1120 */ 's', 'r', 'l', 32, 0,
  /* 1125 */ 's', 'm', 'u', 'l', 32, 0,
  /* 1131 */ 'u', 'm', 'u', 'l', 32, 0,
  /* 1137 */ 'e', 'd', 'g', 'e', '3', '2', 'n', 32, 0,
  /* 1146 */ 'e', 'd', 'g', 'e', '1', '6', 'n', 32, 0,
  /* 1155 */ 'e', 'd', 'g', 'e', '8', 'n', 32, 0,
  /* 1163 */ 'a', 'n', 'd', 'n', 32, 0,
  /* 1169 */ 'e', 'd', 'g', 'e', '3', '2', 'l', 'n', 32, 0,
  /* 1179 */ 'e', 'd', 'g', 'e', '1', '6', 'l', 'n', 32, 0,
  /* 1189 */ 'e', 'd', 'g', 'e', '8', 'l', 'n', 32, 0,
  /* 1198 */ 'b', 'r', 'g', 'e', 'z', ',', 'a', ',', 'p', 'n', 32, 0,
  /* 1210 */ 'b', 'r', 'l', 'e', 'z', ',', 'a', ',', 'p', 'n', 32, 0,
  /* 1222 */ 'b', 'r', 'g', 'z', ',', 'a', ',', 'p', 'n', 32, 0,
  /* 1233 */ 'b', 'r', 'l', 'z', ',', 'a', ',', 'p', 'n', 32, 0,
  /* 1244 */ 'b', 'r', 'n', 'z', ',', 'a', ',', 'p', 'n', 32, 0,
  /* 1255 */ 'b', 'r', 'z', ',', 'a', ',', 'p', 'n', 32, 0,
  /* 1265 */ 'b', 'r', 'g', 'e', 'z', ',', 'p', 'n', 32, 0,
  /* 1275 */ 'b', 'r', 'l', 'e', 'z', ',', 'p', 'n', 32, 0,
  /* 1285 */ 'b', 'r', 'g', 'z', ',', 'p', 'n', 32, 0,
  /* 1294 */ 'b', 'r', 'l', 'z', ',', 'p', 'n', 32, 0,
  /* 1303 */ 'b', 'r', 'n', 'z', ',', 'p', 'n', 32, 0,
  /* 1312 */ 'b', 'r', 'z', ',', 'p', 'n', 32, 0,
  /* 1320 */ 'o', 'r', 'n', 32, 0,
  /* 1325 */ 'p', 'd', 'i', 's', 't', 'n', 32, 0,
  /* 1333 */ 'f', 'z', 'e', 'r', 'o', 32, 0,
  /* 1340 */ 'c', 'm', 'p', 32, 0,
  /* 1345 */ 'u', 'n', 'i', 'm', 'p', 32, 0,
  /* 1352 */ 'j', 'm', 'p', 32, 0,
  /* 1357 */ 'f', 's', 'u', 'b', 'q', 32, 0,
  /* 1364 */ 'f', 'a', 'd', 'd', 'q', 32, 0,
  /* 1371 */ 'f', 'c', 'm', 'p', 'e', 'q', 32, 0,
  /* 1379 */ 'f', 'n', 'e', 'g', 'q', 32, 0,
  /* 1386 */ 'f', 'd', 'm', 'u', 'l', 'q', 32, 0,
  /* 1394 */ 'f', 'm', 'u', 'l', 'q', 32, 0,
  /* 1401 */ 'f', 'd', 't', 'o', 'q', 32, 0,
  /* 1408 */ 'f', 'i', 't', 'o', 'q', 32, 0,
  /* 1415 */ 'f', 's', 't', 'o', 'q', 32, 0,
  /* 1422 */ 'f', 'x', 't', 'o', 'q', 32, 0,
  /* 1429 */ 'f', 'c', 'm', 'p', 'q', 32, 0,
  /* 1436 */ 'f', 'a', 'b', 's', 'q', 32, 0,
  /* 1443 */ 'f', 's', 'q', 'r', 't', 'q', 32, 0,
  /* 1451 */ 's', 't', 'q', 32, 0,
  /* 1456 */ 'f', 'd', 'i', 'v', 'q', 32, 0,
  /* 1463 */ 'f', 'm', 'o', 'v', 'q', 32, 0,
  /* 1470 */ 'm', 'e', 'm', 'b', 'a', 'r', 32, 0,
  /* 1478 */ 'a', 'l', 'i', 'g', 'n', 'a', 'd', 'd', 'r', 32, 0,
  /* 1489 */ 's', 'i', 'r', 32, 0,
  /* 1494 */ 'f', 'o', 'r', 32, 0,
  /* 1499 */ 'f', 'n', 'o', 'r', 32, 0,
  /* 1505 */ 'f', 'x', 'n', 'o', 'r', 32, 0,
  /* 1512 */ 'f', 'x', 'o', 'r', 32, 0,
  /* 1518 */ 'r', 'd', 'p', 'r', 32, 0,
  /* 1524 */ 'w', 'r', 'p', 'r', 32, 0,
  /* 1530 */ 'p', 'w', 'r', 32, 0,
  /* 1535 */ 'f', 's', 'r', 'c', '1', 's', 32, 0,
  /* 1543 */ 'f', 'a', 'n', 'd', 'n', 'o', 't', '1', 's', 32, 0,
  /* 1554 */ 'f', 'n', 'o', 't', '1', 's', 32, 0,
  /* 1562 */ 'f', 'o', 'r', 'n', 'o', 't', '1', 's', 32, 0,
  /* 1572 */ 'f', 'p', 'a', 'd', 'd', '3', '2', 's', 32, 0,
  /* 1582 */ 'f', 's', 'r', 'c', '2', 's', 32, 0,
  /* 1590 */ 'f', 'a', 'n', 'd', 'n', 'o', 't', '2', 's', 32, 0,
  /* 1601 */ 'f', 'n', 'o', 't', '2', 's', 32, 0,
  /* 1609 */ 'f', 'o', 'r', 'n', 'o', 't', '2', 's', 32, 0,
  /* 1619 */ 'f', 'p', 'a', 'd', 'd', '1', '6', 's', 32, 0,
  /* 1629 */ 'f', 's', 'u', 'b', 's', 32, 0,
  /* 1636 */ 'f', 'h', 's', 'u', 'b', 's', 32, 0,
  /* 1644 */ 'f', 'a', 'd', 'd', 's', 32, 0,
  /* 1651 */ 'f', 'h', 'a', 'd', 'd', 's', 32, 0,
  /* 1659 */ 'f', 'n', 'h', 'a', 'd', 'd', 's', 32, 0,
  /* 1668 */ 'f', 'n', 'a', 'd', 'd', 's', 32, 0,
  /* 1676 */ 'f', 'a', 'n', 'd', 's', 32, 0,
  /* 1683 */ 'f', 'n', 'a', 'n', 'd', 's', 32, 0,
  /* 1691 */ 'f', 'o', 'n', 'e', 's', 32, 0,
  /* 1698 */ 'f', 'c', 'm', 'p', 'e', 's', 32, 0,
  /* 1706 */ 'f', 'n', 'e', 'g', 's', 32, 0,
  /* 1713 */ 'f', 'm', 'u', 'l', 's', 32, 0,
  /* 1720 */ 'f', 'z', 'e', 'r', 'o', 's', 32, 0,
  /* 1728 */ 'f', 'd', 't', 'o', 's', 32, 0,
  /* 1735 */ 'f', 'i', 't', 'o', 's', 32, 0,
  /* 1742 */ 'f', 'q', 't', 'o', 's', 32, 0,
  /* 1749 */ 'f', 'x', 't', 'o', 's', 32, 0,
  /* 1756 */ 'f', 'c', 'm', 'p', 's', 32, 0,
  /* 1763 */ 'f', 'l', 'c', 'm', 'p', 's', 32, 0,
  /* 1771 */ 'f', 'o', 'r', 's', 32, 0,
  /* 1777 */ 'f', 'n', 'o', 'r', 's', 32, 0,
  /* 1784 */ 'f', 'x', 'n', 'o', 'r', 's', 32, 0,
  /* 1792 */ 'f', 'x', 'o', 'r', 's', 32, 0,
  /* 1799 */ 'f', 'a', 'b', 's', 's', 32, 0,
  /* 1806 */ 'f', 's', 'q', 'r', 't', 's', 32, 0,
  /* 1814 */ 'f', 'd', 'i', 'v', 's', 32, 0,
  /* 1821 */ 'f', 'm', 'o', 'v', 's', 32, 0,
  /* 1828 */ 's', 'e', 't', 32, 0,
  /* 1833 */ 'l', 'z', 'c', 'n', 't', 32, 0,
  /* 1840 */ 'p', 'd', 'i', 's', 't', 32, 0,
  /* 1847 */ 'r', 'e', 't', 't', 32, 0,
  /* 1853 */ 'f', 'm', 'u', 'l', '8', 'x', '1', '6', 'a', 'u', 32, 0,
  /* 1865 */ 's', 'd', 'i', 'v', 32, 0,
  /* 1871 */ 'u', 'd', 'i', 'v', 32, 0,
  /* 1877 */ 't', 's', 'u', 'b', 'c', 'c', 't', 'v', 32, 0,
  /* 1887 */ 't', 'a', 'd', 'd', 'c', 'c', 't', 'v', 32, 0,
  /* 1897 */ 'm', 'o', 'v', 's', 't', 'o', 's', 'w', 32, 0,
  /* 1907 */ 'm', 'o', 'v', 's', 't', 'o', 'u', 'w', 32, 0,
  /* 1917 */ 's', 'r', 'a', 'x', 32, 0,
  /* 1923 */ 's', 'u', 'b', 'x', 32, 0,
  /* 1929 */ 'a', 'd', 'd', 'x', 32, 0,
  /* 1935 */ 'f', 'p', 'a', 'c', 'k', 'f', 'i', 'x', 32, 0,
  /* 1945 */ 's', 'l', 'l', 'x', 32, 0,
  /* 1951 */ 's', 'r', 'l', 'x', 32, 0,
  /* 1957 */ 'x', 'm', 'u', 'l', 'x', 32, 0,
  /* 1964 */ 'f', 'd', 't', 'o', 'x', 32, 0,
  /* 1971 */ 'm', 'o', 'v', 'd', 't', 'o', 'x', 32, 0,
  /* 1980 */ 'f', 'q', 't', 'o', 'x', 32, 0,
  /* 1987 */ 'f', 's', 't', 'o', 'x', 32, 0,
  /* 1994 */ 's', 't', 'x', 32, 0,
  /* 1999 */ 's', 'd', 'i', 'v', 'x', 32, 0,
  /* 2006 */ 'u', 'd', 'i', 'v', 'x', 32, 0,
  /* 2013 */ 'f', 'm', 'o', 'v', 'r', 'd', 'z', 32, 0,
  /* 2022 */ 'f', 'm', 'o', 'v', 'r', 'd', 'g', 'e', 'z', 32, 0,
  /* 2033 */ 'f', 'm', 'o', 'v', 'r', 'q', 'g', 'e', 'z', 32, 0,
  /* 2044 */ 'b', 'r', 'g', 'e', 'z', 32, 0,
  /* 2051 */ 'm', 'o', 'v', 'r', 'g', 'e', 'z', 32, 0,
  /* 2060 */ 'f', 'm', 'o', 'v', 'r', 's', 'g', 'e', 'z', 32, 0,
  /* 2071 */ 'f', 'm', 'o', 'v', 'r', 'd', 'l', 'e', 'z', 32, 0,
  /* 2082 */ 'f', 'm', 'o', 'v', 'r', 'q', 'l', 'e', 'z', 32, 0,
  /* 2093 */ 'b', 'r', 'l', 'e', 'z', 32, 0,
  /* 2100 */ 'm', 'o', 'v', 'r', 'l', 'e', 'z', 32, 0,
  /* 2109 */ 'f', 'm', 'o', 'v', 'r', 's', 'l', 'e', 'z', 32, 0,
  /* 2120 */ 'f', 'm', 'o', 'v', 'r', 'd', 'g', 'z', 32, 0,
  /* 2130 */ 'f', 'm', 'o', 'v', 'r', 'q', 'g', 'z', 32, 0,
  /* 2140 */ 'b', 'r', 'g', 'z', 32, 0,
  /* 2146 */ 'm', 'o', 'v', 'r', 'g', 'z', 32, 0,
  /* 2154 */ 'f', 'm', 'o', 'v', 'r', 's', 'g', 'z', 32, 0,
  /* 2164 */ 'f', 'm', 'o', 'v', 'r', 'd', 'l', 'z', 32, 0,
  /* 2174 */ 'f', 'm', 'o', 'v', 'r', 'q', 'l', 'z', 32, 0,
  /* 2184 */ 'b', 'r', 'l', 'z', 32, 0,
  /* 2190 */ 'm', 'o', 'v', 'r', 'l', 'z', 32, 0,
  /* 2198 */ 'f', 'm', 'o', 'v', 'r', 's', 'l', 'z', 32, 0,
  /* 2208 */ 'f', 'm', 'o', 'v', 'r', 'd', 'n', 'z', 32, 0,
  /* 2218 */ 'f', 'm', 'o', 'v', 'r', 'q', 'n', 'z', 32, 0,
  /* 2228 */ 'b', 'r', 'n', 'z', 32, 0,
  /* 2234 */ 'm', 'o', 'v', 'r', 'n', 'z', 32, 0,
  /* 2242 */ 'f', 'm', 'o', 'v', 'r', 's', 'n', 'z', 32, 0,
  /* 2252 */ 'f', 'm', 'o', 'v', 'r', 'q', 'z', 32, 0,
  /* 2261 */ 'b', 'r', 'z', 32, 0,
  /* 2266 */ 'm', 'o', 'v', 'r', 'z', 32, 0,
  /* 2273 */ 'f', 'm', 'o', 'v', 'r', 's', 'z', 32, 0,
  /* 2282 */ ';', 32, 'S', 'E', 'L', 'E', 'C', 'T', '_', 'C', 'C', '_', 'D', 'F', 'P', '_', 'F', 'C', 'C', 32, 'P', 'S', 'E', 'U', 'D', 'O', '!', 0,
  /* 2310 */ ';', 32, 'S', 'E', 'L', 'E', 'C', 'T', '_', 'C', 'C', '_', 'Q', 'F', 'P', '_', 'F', 'C', 'C', 32, 'P', 'S', 'E', 'U', 'D', 'O', '!', 0,
  /* 2338 */ ';', 32, 'S', 'E', 'L', 'E', 'C', 'T', '_', 'C', 'C', '_', 'F', 'P', '_', 'F', 'C', 'C', 32, 'P', 'S', 'E', 'U', 'D', 'O', '!', 0,
  /* 2365 */ ';', 32, 'S', 'E', 'L', 'E', 'C', 'T', '_', 'C', 'C', '_', 'I', 'n', 't', '_', 'F', 'C', 'C', 32, 'P', 'S', 'E', 'U', 'D', 'O', '!', 0,
  /* 2393 */ ';', 32, 'S', 'E', 'L', 'E', 'C', 'T', '_', 'C', 'C', '_', 'D', 'F', 'P', '_', 'I', 'C', 'C', 32, 'P', 'S', 'E', 'U', 'D', 'O', '!', 0,
  /* 2421 */ ';', 32, 'S', 'E', 'L', 'E', 'C', 'T', '_', 'C', 'C', '_', 'Q', 'F', 'P', '_', 'I', 'C', 'C', 32, 'P', 'S', 'E', 'U', 'D', 'O', '!', 0,
  /* 2449 */ ';', 32, 'S', 'E', 'L', 'E', 'C', 'T', '_', 'C', 'C', '_', 'F', 'P', '_', 'I', 'C', 'C', 32, 'P', 'S', 'E', 'U', 'D', 'O', '!', 0,
  /* 2476 */ ';', 32, 'S', 'E', 'L', 'E', 'C', 'T', '_', 'C', 'C', '_', 'I', 'n', 't', '_', 'I', 'C', 'C', 32, 'P', 'S', 'E', 'U', 'D', 'O', '!', 0,
  /* 2504 */ 'j', 'm', 'p', 32, '%', 'i', '7', '+', 0,
  /* 2513 */ 'j', 'm', 'p', 32, '%', 'o', '7', '+', 0,
  /* 2522 */ '#', 32, 'X', 'R', 'a', 'y', 32, 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', 32, 'P', 'a', 't', 'c', 'h', 'a', 'b', 'l', 'e', 32, 'R', 'E', 'T', '.', 0,
  /* 2553 */ '#', 32, 'X', 'R', 'a', 'y', 32, 'T', 'y', 'p', 'e', 'd', 32, 'E', 'v', 'e', 'n', 't', 32, 'L', 'o', 'g', '.', 0,
  /* 2577 */ '#', 32, 'X', 'R', 'a', 'y', 32, 'C', 'u', 's', 't', 'o', 'm', 32, 'E', 'v', 'e', 'n', 't', 32, 'L', 'o', 'g', '.', 0,
  /* 2602 */ '#', 32, 'X', 'R', 'a', 'y', 32, 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', 32, 'E', 'n', 't', 'e', 'r', '.', 0,
  /* 2625 */ '#', 32, 'X', 'R', 'a', 'y', 32, 'T', 'a', 'i', 'l', 32, 'C', 'a', 'l', 'l', 32, 'E', 'x', 'i', 't', '.', 0,
  /* 2648 */ '#', 32, 'X', 'R', 'a', 'y', 32, 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', 32, 'E', 'x', 'i', 't', '.', 0,
  /* 2670 */ 'f', 'l', 'u', 's', 'h', 32, '%', 'g', '0', 0,
  /* 2680 */ 't', 'a', 32, '1', 0,
  /* 2685 */ 't', 'a', 32, '3', 0,
  /* 2690 */ 't', 'a', 32, '5', 0,
  /* 2695 */ 'L', 'I', 'F', 'E', 'T', 'I', 'M', 'E', '_', 'E', 'N', 'D', 0,
  /* 2708 */ 'P', 'S', 'E', 'U', 'D', 'O', '_', 'P', 'R', 'O', 'B', 'E', 0,
  /* 2721 */ 'B', 'U', 'N', 'D', 'L', 'E', 0,
  /* 2728 */ 'D', 'B', 'G', '_', 'V', 'A', 'L', 'U', 'E', 0,
  /* 2738 */ 'D', 'B', 'G', '_', 'I', 'N', 'S', 'T', 'R', '_', 'R', 'E', 'F', 0,
  /* 2752 */ 'D', 'B', 'G', '_', 'L', 'A', 'B', 'E', 'L', 0,
  /* 2762 */ 'L', 'I', 'F', 'E', 'T', 'I', 'M', 'E', '_', 'S', 'T', 'A', 'R', 'T', 0,
  /* 2777 */ 'D', 'B', 'G', '_', 'V', 'A', 'L', 'U', 'E', '_', 'L', 'I', 'S', 'T', 0,
  /* 2792 */ 's', 't', 'd', 32, '%', 'c', 'q', ',', 32, '[', 0,
  /* 2803 */ 's', 't', 'd', 32, '%', 'f', 'q', ',', 32, '[', 0,
  /* 2814 */ 's', 't', 32, '%', 'c', 's', 'r', ',', 32, '[', 0,
  /* 2825 */ 's', 't', 32, '%', 'f', 's', 'r', ',', 32, '[', 0,
  /* 2836 */ 's', 't', 'x', 32, '%', 'f', 's', 'r', ',', 32, '[', 0,
  /* 2848 */ 'l', 'd', 's', 'b', 'a', 32, '[', 0,
  /* 2856 */ 'l', 'd', 'u', 'b', 'a', 32, '[', 0,
  /* 2864 */ 'l', 'd', 's', 't', 'u', 'b', 'a', 32, '[', 0,
  /* 2874 */ 'l', 'd', 'd', 'a', 32, '[', 0,
  /* 2881 */ 'l', 'd', 'a', 32, '[', 0,
  /* 2887 */ 'l', 'd', 's', 'h', 'a', 32, '[', 0,
  /* 2895 */ 'l', 'd', 'u', 'h', 'a', 32, '[', 0,
  /* 2903 */ 's', 'w', 'a', 'p', 'a', 32, '[', 0,
  /* 2911 */ 'l', 'd', 'q', 'a', 32, '[', 0,
  /* 2918 */ 'c', 'a', 's', 'a', 32, '[', 0,
  /* 2925 */ 'l', 'd', 's', 'b', 32, '[', 0,
  /* 2932 */ 'l', 'd', 'u', 'b', 32, '[', 0,
  /* 2939 */ 'l', 'd', 's', 't', 'u', 'b', 32, '[', 0,
  /* 2948 */ 'l', 'd', 'd', 32, '[', 0,
  /* 2954 */ 'l', 'd', 32, '[', 0,
  /* 2959 */ 'l', 'd', 's', 'h', 32, '[', 0,
  /* 2966 */ 'l', 'd', 'u', 'h', 32, '[', 0,
  /* 2973 */ 's', 'w', 'a', 'p', 32, '[', 0,
  /* 2980 */ 'l', 'd', 'q', 32, '[', 0,
  /* 2986 */ 'c', 'a', 's', 32, '[', 0,
  /* 2992 */ 'l', 'd', 's', 'w', 32, '[', 0,
  /* 2999 */ 'l', 'd', 'x', 32, '[', 0,
  /* 3005 */ 'c', 'a', 's', 'x', 32, '[', 0,
  /* 3012 */ 'c', 'b', 0,
  /* 3015 */ 'f', 'b', 0,
  /* 3018 */ 'f', 'm', 'o', 'v', 'd', 0,
  /* 3024 */ '#', 32, 'F', 'E', 'n', 't', 'r', 'y', 32, 'c', 'a', 'l', 'l', 0,
  /* 3038 */ 's', 'i', 'a', 'm', 0,
  /* 3043 */ 's', 'h', 'u', 't', 'd', 'o', 'w', 'n', 0,
  /* 3052 */ 'n', 'o', 'p', 0,
  /* 3056 */ 'f', 'm', 'o', 'v', 'q', 0,
  /* 3062 */ 's', 't', 'b', 'a', 'r', 0,
  /* 3068 */ 'f', 'm', 'o', 'v', 's', 0,
  /* 3074 */ 't', 0,
  /* 3076 */ 'm', 'o', 'v', 0,
  /* 3080 */ 'f', 'l', 'u', 's', 'h', 'w', 0,

};

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
    2729U,	// DBG_VALUE
    2778U,	// DBG_VALUE_LIST
    2739U,	// DBG_INSTR_REF
    2753U,	// DBG_LABEL
    0U,	// REG_SEQUENCE
    0U,	// COPY
    2722U,	// BUNDLE
    2763U,	// LIFETIME_START
    2696U,	// LIFETIME_END
    2709U,	// PSEUDO_PROBE
    0U,	// STACKMAP
    3025U,	// FENTRY_CALL
    0U,	// PATCHPOINT
    0U,	// LOAD_STACK_GUARD
    0U,	// PREALLOCATED_SETUP
    0U,	// PREALLOCATED_ARG
    0U,	// STATEPOINT
    0U,	// LOCAL_ESCAPE
    0U,	// FAULTING_OP
    0U,	// PATCHABLE_OP
    2603U,	// PATCHABLE_FUNCTION_ENTER
    2523U,	// PATCHABLE_RET
    2649U,	// PATCHABLE_FUNCTION_EXIT
    2626U,	// PATCHABLE_TAIL_CALL
    2578U,	// PATCHABLE_EVENT_CALL
    2554U,	// PATCHABLE_TYPED_EVENT_CALL
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
    4556U,	// ADJCALLSTACKDOWN
    70111U,	// ADJCALLSTACKUP
    8202U,	// GETPCX
    2283U,	// SELECT_CC_DFP_FCC
    2394U,	// SELECT_CC_DFP_ICC
    2339U,	// SELECT_CC_FP_FCC
    2450U,	// SELECT_CC_FP_ICC
    2366U,	// SELECT_CC_Int_FCC
    2477U,	// SELECT_CC_Int_ICC
    2311U,	// SELECT_CC_QFP_FCC
    2422U,	// SELECT_CC_QFP_ICC
    2111269U,	// SET
    4207243U,	// ADDCCri
    4207243U,	// ADDCCrr
    4208522U,	// ADDCri
    4208522U,	// ADDCrr
    4207335U,	// ADDEri
    4207335U,	// ADDErr
    4207349U,	// ADDXC
    4207233U,	// ADDXCCC
    4207371U,	// ADDXri
    4207371U,	// ADDXrr
    4207371U,	// ADDri
    4207371U,	// ADDrr
    4208071U,	// ALIGNADDR
    4207701U,	// ALIGNADDRL
    4207250U,	// ANDCCri
    4207250U,	// ANDCCrr
    4207273U,	// ANDNCCri
    4207273U,	// ANDNCCrr
    4207756U,	// ANDNri
    4207756U,	// ANDNrr
    4207756U,	// ANDXNrr
    4207439U,	// ANDXri
    4207439U,	// ANDXrr
    4207439U,	// ANDri
    4207439U,	// ANDrr
    4207020U,	// ARRAY16
    4206773U,	// ARRAY32
    4207044U,	// ARRAY8
    70199U,	// BA
    2247622U,	// BCOND
    2313158U,	// BCONDA
    87369U,	// BINDri
    87369U,	// BINDrr
    4207639U,	// BMASK
    4344776U,	// BPFCC
    4410312U,	// BPFCCA
    281544U,	// BPFCCANT
    347080U,	// BPFCCNT
    5295U,	// BPGEZapn
    4612U,	// BPGEZapt
    5362U,	// BPGEZnapn
    6141U,	// BPGEZnapt
    5319U,	// BPGZapn
    4630U,	// BPGZapt
    5382U,	// BPGZnapn
    6237U,	// BPGZnapt
    2509766U,	// BPICC
    478150U,	// BPICCA
    543686U,	// BPICCANT
    609222U,	// BPICCNT
    5307U,	// BPLEZapn
    4621U,	// BPLEZapt
    5372U,	// BPLEZnapn
    6190U,	// BPLEZnapt
    5330U,	// BPLZapn
    4638U,	// BPLZapt
    5391U,	// BPLZnapn
    6281U,	// BPLZnapt
    5341U,	// BPNZapn
    4646U,	// BPNZapt
    5400U,	// BPNZnapn
    6325U,	// BPNZnapt
    2771910U,	// BPXCC
    740294U,	// BPXCCA
    805830U,	// BPXCCANT
    871366U,	// BPXCCNT
    5352U,	// BPZapn
    4654U,	// BPZapt
    5409U,	// BPZnapn
    6358U,	// BPZnapt
    4207550U,	// BSHUFFLE
    70724U,	// CALL
    87108U,	// CALLri
    87108U,	// CALLrr
    932711U,	// CASAasi10
    7289703U,	// CASArr
    5258174U,	// CASXrr
    5258155U,	// CASrr
    2247621U,	// CBCOND
    2313157U,	// CBCONDA
    69927U,	// CMASK16
    69759U,	// CMASK32
    70076U,	// CMASK8
    5437U,	// CMPri
    5437U,	// CMPrr
    4206850U,	// EDGE16
    4207655U,	// EDGE16L
    4207772U,	// EDGE16LN
    4207739U,	// EDGE16N
    4206682U,	// EDGE32
    4207646U,	// EDGE32L
    4207762U,	// EDGE32LN
    4207730U,	// EDGE32N
    4207029U,	// EDGE8
    4207664U,	// EDGE8L
    4207782U,	// EDGE8LN
    4207748U,	// EDGE8N
    2110355U,	// FABSD
    2110877U,	// FABSQ
    2111240U,	// FABSS
    4207376U,	// FADDD
    4207957U,	// FADDQ
    4208237U,	// FADDS
    4207186U,	// FALIGNADATA
    4207438U,	// FAND
    4206630U,	// FANDNOT1
    4208136U,	// FANDNOT1S
    4206789U,	// FANDNOT2
    4208183U,	// FANDNOT2S
    4208269U,	// FANDS
    2247624U,	// FBCOND
    2313160U,	// FBCONDA
    4206912U,	// FCHKSM16
    4992U,	// FCMPD
    4206931U,	// FCMPEQ16
    4206744U,	// FCMPEQ32
    4206950U,	// FCMPGT16
    4206763U,	// FCMPGT32
    4206858U,	// FCMPLE16
    4206690U,	// FCMPLE32
    4206868U,	// FCMPNE16
    4206700U,	// FCMPNE32
    5526U,	// FCMPQ
    5853U,	// FCMPS
    4207527U,	// FDIVD
    4208049U,	// FDIVQ
    4208407U,	// FDIVS
    4207979U,	// FDMULQ
    2110466U,	// FDTOI
    2110842U,	// FDTOQ
    2111169U,	// FDTOS
    2111405U,	// FDTOX
    2110299U,	// FEXPAND
    4207383U,	// FHADDD
    4208244U,	// FHADDS
    4207363U,	// FHSUBD
    4208229U,	// FHSUBS
    2110308U,	// FITOD
    2110849U,	// FITOQ
    2111176U,	// FITOS
    16782215U,	// FLCMPD
    16783076U,	// FLCMPS
    2671U,	// FLUSH
    3081U,	// FLUSHW
    87005U,	// FLUSHri
    87005U,	// FLUSHrr
    4206922U,	// FMEAN16
    2110382U,	// FMOVD
    1141707U,	// FMOVD_FCC
    151415755U,	// FMOVD_ICC
    151677899U,	// FMOVD_XCC
    2110904U,	// FMOVQ
    1141745U,	// FMOVQ_FCC
    151415793U,	// FMOVQ_ICC
    151677937U,	// FMOVQ_XCC
    4208615U,	// FMOVRGEZD
    4208626U,	// FMOVRGEZQ
    4208653U,	// FMOVRGEZS
    4208713U,	// FMOVRGZD
    4208723U,	// FMOVRGZQ
    4208747U,	// FMOVRGZS
    4208664U,	// FMOVRLEZD
    4208675U,	// FMOVRLEZQ
    4208702U,	// FMOVRLEZS
    4208757U,	// FMOVRLZD
    4208767U,	// FMOVRLZQ
    4208791U,	// FMOVRLZS
    4208801U,	// FMOVRNZD
    4208811U,	// FMOVRNZQ
    4208835U,	// FMOVRNZS
    4208606U,	// FMOVRZD
    4208845U,	// FMOVRZQ
    4208866U,	// FMOVRZS
    2111262U,	// FMOVS
    1141757U,	// FMOVS_FCC
    151415805U,	// FMOVS_ICC
    151677949U,	// FMOVS_XCC
    4207008U,	// FMUL8SUX16
    4206983U,	// FMUL8ULX16
    4206960U,	// FMUL8X16
    4207672U,	// FMUL8X16AL
    4208446U,	// FMUL8X16AU
    4207423U,	// FMULD
    4206995U,	// FMULD8SUX16
    4206970U,	// FMULD8ULX16
    4207987U,	// FMULQ
    4208306U,	// FMULS
    4207400U,	// FNADDD
    4208261U,	// FNADDS
    4207444U,	// FNAND
    4208276U,	// FNANDS
    2110264U,	// FNEGD
    2110820U,	// FNEGQ
    2111147U,	// FNEGS
    4207391U,	// FNHADDD
    4208252U,	// FNHADDS
    4207391U,	// FNMULD
    4208252U,	// FNMULS
    4208092U,	// FNOR
    4208370U,	// FNORS
    2109488U,	// FNOT1
    2110995U,	// FNOT1S
    2109647U,	// FNOT2
    2111042U,	// FNOT2S
    4208252U,	// FNSMULD
    70600U,	// FONE
    71324U,	// FONES
    4208087U,	// FOR
    4206647U,	// FORNOT1
    4208155U,	// FORNOT1S
    4206806U,	// FORNOT2
    4208202U,	// FORNOT2S
    4208364U,	// FORS
    2109726U,	// FPACK16
    4206710U,	// FPACK32
    2111376U,	// FPACKFIX
    4206841U,	// FPADD16
    4208212U,	// FPADD16S
    4206673U,	// FPADD32
    4208165U,	// FPADD32S
    4206815U,	// FPADD64
    4207541U,	// FPMERGE
    4206832U,	// FPSUB16
    4207098U,	// FPSUB16S
    4206664U,	// FPSUB32
    4207088U,	// FPSUB32S
    2110315U,	// FQTOD
    2110473U,	// FQTOI
    2111183U,	// FQTOS
    2111421U,	// FQTOX
    4206941U,	// FSLAS16
    4206754U,	// FSLAS32
    4206896U,	// FSLL16
    4206728U,	// FSLL32
    4207430U,	// FSMULD
    2110362U,	// FSQRTD
    2110884U,	// FSQRTQ
    2111247U,	// FSQRTS
    4206824U,	// FSRA16
    4206656U,	// FSRA32
    2109471U,	// FSRC1
    2110976U,	// FSRC1S
    2109630U,	// FSRC2
    2111023U,	// FSRC2S
    4206904U,	// FSRL16
    4206736U,	// FSRL32
    2110322U,	// FSTOD
    2110480U,	// FSTOI
    2110856U,	// FSTOQ
    2111428U,	// FSTOX
    4207356U,	// FSUBD
    4207950U,	// FSUBQ
    4208222U,	// FSUBS
    4208098U,	// FXNOR
    4208377U,	// FXNORS
    4208105U,	// FXOR
    4208385U,	// FXORS
    2110329U,	// FXTOD
    2110863U,	// FXTOQ
    2111190U,	// FXTOS
    70966U,	// FZERO
    71353U,	// FZEROS
    2126927U,	// JMPLri
    2126927U,	// JMPLrr
    160398146U,	// LDArr
    1203083U,	// LDCSRri
    1203083U,	// LDCSRrr
    3177355U,	// LDCri
    3177355U,	// LDCrr
    160398139U,	// LDDArr
    3177349U,	// LDDCri
    3177349U,	// LDDCrr
    160398139U,	// LDDFArr
    3177349U,	// LDDFri
    3177349U,	// LDDFrr
    3177349U,	// LDDri
    3177349U,	// LDDrr
    160398146U,	// LDFArr
    1268619U,	// LDFSRri
    1268619U,	// LDFSRrr
    3177355U,	// LDFri
    3177355U,	// LDFrr
    160398176U,	// LDQFArr
    3177381U,	// LDQFri
    3177381U,	// LDQFrr
    160398113U,	// LDSBArr
    3177326U,	// LDSBri
    3177326U,	// LDSBrr
    160398152U,	// LDSHArr
    3177360U,	// LDSHri
    3177360U,	// LDSHrr
    160398129U,	// LDSTUBArr
    3177340U,	// LDSTUBri
    3177340U,	// LDSTUBrr
    3177393U,	// LDSWri
    3177393U,	// LDSWrr
    160398121U,	// LDUBArr
    3177333U,	// LDUBri
    3177333U,	// LDUBrr
    160398160U,	// LDUHArr
    3177367U,	// LDUHri
    3177367U,	// LDUHrr
    1268664U,	// LDXFSRri
    1268664U,	// LDXFSRrr
    3177400U,	// LDXri
    3177400U,	// LDXrr
    3177355U,	// LDri
    3177355U,	// LDrr
    33547U,	// LEAX_ADDri
    33547U,	// LEA_ADDri
    2111274U,	// LZCNT
    38335U,	// MEMBARi
    2111412U,	// MOVDTOX
    1141765U,	// MOVFCCri
    1141765U,	// MOVFCCrr
    151415813U,	// MOVICCri
    151415813U,	// MOVICCrr
    4208644U,	// MOVRGEZri
    4208644U,	// MOVRGEZrr
    4208739U,	// MOVRGZri
    4208739U,	// MOVRGZrr
    4208693U,	// MOVRLEZri
    4208693U,	// MOVRLEZrr
    4208783U,	// MOVRLZri
    4208783U,	// MOVRLZrr
    4208827U,	// MOVRNZri
    4208827U,	// MOVRNZrr
    4208859U,	// MOVRRZri
    4208859U,	// MOVRRZrr
    2111338U,	// MOVSTOSW
    2111348U,	// MOVSTOUW
    2111412U,	// MOVWTOS
    151677957U,	// MOVXCCri
    151677957U,	// MOVXCCrr
    2111412U,	// MOVXTOD
    4207303U,	// MULSCCri
    4207303U,	// MULSCCrr
    4208551U,	// MULXri
    4208551U,	// MULXrr
    3053U,	// NOP
    4207290U,	// ORCCri
    4207290U,	// ORCCrr
    4207281U,	// ORNCCri
    4207281U,	// ORNCCrr
    4207913U,	// ORNri
    4207913U,	// ORNrr
    4207913U,	// ORXNrr
    4208088U,	// ORXri
    4208088U,	// ORXrr
    4208088U,	// ORri
    4208088U,	// ORrr
    4208433U,	// PDIST
    4207918U,	// PDISTN
    2110191U,	// POPCrr
    33560059U,	// PWRPSRri
    33560059U,	// PWRPSRrr
    2110351U,	// RDASR
    2110959U,	// RDPR
    69653U,	// RDPSR
    69643U,	// RDTBR
    69633U,	// RDWIM
    4207566U,	// RESTOREri
    4207566U,	// RESTORErr
    72137U,	// RET
    72146U,	// RETL
    87864U,	// RETTri
    87864U,	// RETTrr
    4207575U,	// SAVEri
    4207575U,	// SAVErr
    4207311U,	// SDIVCCri
    4207311U,	// SDIVCCrr
    4208592U,	// SDIVXri
    4208592U,	// SDIVXrr
    4208458U,	// SDIVri
    4208458U,	// SDIVrr
    2110441U,	// SETHIXi
    2110441U,	// SETHIi
    3044U,	// SHUTDOWN
    3039U,	// SIAM
    71122U,	// SIR
    4208538U,	// SLLXri
    4208538U,	// SLLXrr
    4207690U,	// SLLri
    4207690U,	// SLLrr
    4207213U,	// SMACri
    4207213U,	// SMACrr
    4207257U,	// SMULCCri
    4207257U,	// SMULCCrr
    4207718U,	// SMULri
    4207718U,	// SMULrr
    4208510U,	// SRAXri
    4208510U,	// SRAXrr
    4207181U,	// SRAri
    4207181U,	// SRArr
    4208544U,	// SRLXri
    4208544U,	// SRLXrr
    4207713U,	// SRLri
    4207713U,	// SRLrr
    9413214U,	// STArr
    3063U,	// STBAR
    9413173U,	// STBArr
    1352291U,	// STBri
    1352291U,	// STBrr
    1334015U,	// STCSRri
    1334015U,	// STCSRrr
    1353524U,	// STCri
    1353524U,	// STCrr
    9413179U,	// STDArr
    1333993U,	// STDCQri
    1333993U,	// STDCQrr
    1352610U,	// STDCri
    1352610U,	// STDCrr
    9413179U,	// STDFArr
    1334004U,	// STDFQri
    1334004U,	// STDFQrr
    1352610U,	// STDFri
    1352610U,	// STDFrr
    1352610U,	// STDri
    1352610U,	// STDrr
    9413214U,	// STFArr
    1334026U,	// STFSRri
    1334026U,	// STFSRrr
    1353524U,	// STFri
    1353524U,	// STFrr
    9413185U,	// STHArr
    1352676U,	// STHri
    1352676U,	// STHrr
    9413191U,	// STQFArr
    1353132U,	// STQFri
    1353132U,	// STQFrr
    1334037U,	// STXFSRri
    1334037U,	// STXFSRrr
    1353675U,	// STXri
    1353675U,	// STXrr
    1353524U,	// STri
    1353524U,	// STrr
    4207226U,	// SUBCCri
    4207226U,	// SUBCCrr
    4208516U,	// SUBCri
    4208516U,	// SUBCrr
    4207327U,	// SUBEri
    4207327U,	// SUBErr
    4207208U,	// SUBXri
    4207208U,	// SUBXrr
    4207208U,	// SUBri
    4207208U,	// SUBrr
    160398168U,	// SWAPArr
    3177374U,	// SWAPri
    3177374U,	// SWAPrr
    2681U,	// TA1
    2686U,	// TA3
    2691U,	// TA5
    4208480U,	// TADDCCTVri
    4208480U,	// TADDCCTVrr
    4207242U,	// TADDCCri
    4207242U,	// TADDCCrr
    52870147U,	// TICCri
    52870147U,	// TICCrr
    289420043U,	// TLS_ADDXrr
    289420043U,	// TLS_ADDrr
    5188U,	// TLS_CALL
    288390072U,	// TLS_LDXrr
    288390027U,	// TLS_LDrr
    52608003U,	// TRAPri
    52608003U,	// TRAPrr
    4208470U,	// TSUBCCTVri
    4208470U,	// TSUBCCTVrr
    4207225U,	// TSUBCCri
    4207225U,	// TSUBCCrr
    53132291U,	// TXCCri
    53132291U,	// TXCCrr
    4207319U,	// UDIVCCri
    4207319U,	// UDIVCCrr
    4208599U,	// UDIVXri
    4208599U,	// UDIVXrr
    4208464U,	// UDIVri
    4208464U,	// UDIVrr
    4207219U,	// UMACri
    4207219U,	// UMACrr
    4207265U,	// UMULCCri
    4207265U,	// UMULCCrr
    4207600U,	// UMULXHI
    4207724U,	// UMULri
    4207724U,	// UMULrr
    70978U,	// UNIMP
    16782208U,	// V9FCMPD
    16782128U,	// V9FCMPED
    16782684U,	// V9FCMPEQ
    16783011U,	// V9FCMPES
    16782742U,	// V9FCMPQ
    16783069U,	// V9FCMPS
    52171U,	// V9FMOVD_FCC
    52209U,	// V9FMOVQ_FCC
    52221U,	// V9FMOVS_FCC
    52229U,	// V9MOVFCCri
    52229U,	// V9MOVFCCrr
    4208124U,	// WRASRri
    4208124U,	// WRASRrr
    4208117U,	// WRPRri
    4208117U,	// WRPRrr
    33560060U,	// WRPSRri
    33560060U,	// WRPSRrr
    67114492U,	// WRTBRri
    67114492U,	// WRTBRrr
    83891708U,	// WRWIMri
    83891708U,	// WRWIMrr
    4208550U,	// XMULX
    4207609U,	// XMULXHI
    4207288U,	// XNORCCri
    4207288U,	// XNORCCrr
    4208099U,	// XNORXrr
    4208099U,	// XNORri
    4208099U,	// XNORrr
    4207296U,	// XORCCri
    4207296U,	// XORCCrr
    4208106U,	// XORXri
    4208106U,	// XORXrr
    4208106U,	// XORri
    4208106U,	// XORrr
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
    // DBG_VALUE, DBG_VALUE_LIST, DBG_INSTR_REF, DBG_LABEL, BUNDLE, LIFETIME_...
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
    SStream_concat0(O, ", ");
    printOperand/* printOperand (+ ) */(MI, 0, O);
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
    // ADJCALLSTACKDOWN, SET, ADDCCri, ADDCCrr, ADDCri, ADDCrr, ADDEri, ADDEr...
    return;
    break;
  case 1:
    // FLCMPD, FLCMPS, FMOVD_ICC, FMOVD_XCC, FMOVQ_ICC, FMOVQ_XCC, FMOVS_ICC,...
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
    // FLCMPD, FLCMPS, V9FCMPD, V9FCMPED, V9FCMPEQ, V9FCMPES, V9FCMPQ, V9FCMP...
    printOperand/* printOperand (+ ) */(MI, 2, O);
    return;
    break;
  case 1:
    // FMOVD_ICC, FMOVD_XCC, FMOVQ_ICC, FMOVQ_XCC, FMOVS_ICC, FMOVS_XCC, LDAr...
    printOperand/* printOperand (+ ) */(MI, 0, O);
    return;
    break;
  case 2:
    // TLS_ADDXrr, TLS_ADDrr, TLS_LDXrr, TLS_LDrr
    printOperand/* printOperand (+ ) */(MI, 3, O);
    return;
    break;
  }

}


/// getRegisterName - This method is automatically generated by tblgen
/// from the register set description.  This returns the assembler name
/// for the specified register.
const char *getRegisterName(unsigned RegNo) {
  assert(RegNo && RegNo < 236 && "Invalid register number!");

  static const char AsmStrs[] = {
  /* 0 */ 'C', '1', '0', 0,
  /* 4 */ 'F', '1', '0', 0,
  /* 8 */ 'A', 'S', 'R', '1', '0', 0,
  /* 14 */ 'C', '2', '0', 0,
  /* 18 */ 'F', '2', '0', 0,
  /* 22 */ 'A', 'S', 'R', '2', '0', 0,
  /* 28 */ 'C', '3', '0', 0,
  /* 32 */ 'F', '3', '0', 0,
  /* 36 */ 'A', 'S', 'R', '3', '0', 0,
  /* 42 */ 'F', '4', '0', 0,
  /* 46 */ 'F', '5', '0', 0,
  /* 50 */ 'F', '6', '0', 0,
  /* 54 */ 'F', 'C', 'C', '0', 0,
  /* 59 */ 'F', '0', 0,
  /* 62 */ 'G', '0', 0,
  /* 65 */ 'I', '0', 0,
  /* 68 */ 'L', '0', 0,
  /* 71 */ 'O', '0', 0,
  /* 74 */ 'C', '1', '1', 0,
  /* 78 */ 'F', '1', '1', 0,
  /* 82 */ 'A', 'S', 'R', '1', '1', 0,
  /* 88 */ 'C', '2', '1', 0,
  /* 92 */ 'F', '2', '1', 0,
  /* 96 */ 'A', 'S', 'R', '2', '1', 0,
  /* 102 */ 'C', '3', '1', 0,
  /* 106 */ 'F', '3', '1', 0,
  /* 110 */ 'A', 'S', 'R', '3', '1', 0,
  /* 116 */ 'F', 'C', 'C', '1', 0,
  /* 121 */ 'F', '1', 0,
  /* 124 */ 'G', '1', 0,
  /* 127 */ 'I', '1', 0,
  /* 130 */ 'L', '1', 0,
  /* 133 */ 'O', '1', 0,
  /* 136 */ 'A', 'S', 'R', '1', 0,
  /* 141 */ 'C', '1', '2', 0,
  /* 145 */ 'F', '1', '2', 0,
  /* 149 */ 'A', 'S', 'R', '1', '2', 0,
  /* 155 */ 'C', '2', '2', 0,
  /* 159 */ 'F', '2', '2', 0,
  /* 163 */ 'A', 'S', 'R', '2', '2', 0,
  /* 169 */ 'F', '3', '2', 0,
  /* 173 */ 'F', '4', '2', 0,
  /* 177 */ 'F', '5', '2', 0,
  /* 181 */ 'F', '6', '2', 0,
  /* 185 */ 'F', 'C', 'C', '2', 0,
  /* 190 */ 'F', '2', 0,
  /* 193 */ 'G', '2', 0,
  /* 196 */ 'I', '2', 0,
  /* 199 */ 'L', '2', 0,
  /* 202 */ 'O', '2', 0,
  /* 205 */ 'A', 'S', 'R', '2', 0,
  /* 210 */ 'C', '1', '3', 0,
  /* 214 */ 'F', '1', '3', 0,
  /* 218 */ 'A', 'S', 'R', '1', '3', 0,
  /* 224 */ 'C', '2', '3', 0,
  /* 228 */ 'F', '2', '3', 0,
  /* 232 */ 'A', 'S', 'R', '2', '3', 0,
  /* 238 */ 'F', 'C', 'C', '3', 0,
  /* 243 */ 'F', '3', 0,
  /* 246 */ 'G', '3', 0,
  /* 249 */ 'I', '3', 0,
  /* 252 */ 'L', '3', 0,
  /* 255 */ 'O', '3', 0,
  /* 258 */ 'A', 'S', 'R', '3', 0,
  /* 263 */ 'C', '1', '4', 0,
  /* 267 */ 'F', '1', '4', 0,
  /* 271 */ 'A', 'S', 'R', '1', '4', 0,
  /* 277 */ 'C', '2', '4', 0,
  /* 281 */ 'F', '2', '4', 0,
  /* 285 */ 'A', 'S', 'R', '2', '4', 0,
  /* 291 */ 'F', '3', '4', 0,
  /* 295 */ 'F', '4', '4', 0,
  /* 299 */ 'F', '5', '4', 0,
  /* 303 */ 'C', '4', 0,
  /* 306 */ 'F', '4', 0,
  /* 309 */ 'G', '4', 0,
  /* 312 */ 'I', '4', 0,
  /* 315 */ 'L', '4', 0,
  /* 318 */ 'O', '4', 0,
  /* 321 */ 'A', 'S', 'R', '4', 0,
  /* 326 */ 'C', '1', '5', 0,
  /* 330 */ 'F', '1', '5', 0,
  /* 334 */ 'A', 'S', 'R', '1', '5', 0,
  /* 340 */ 'C', '2', '5', 0,
  /* 344 */ 'F', '2', '5', 0,
  /* 348 */ 'A', 'S', 'R', '2', '5', 0,
  /* 354 */ 'C', '5', 0,
  /* 357 */ 'F', '5', 0,
  /* 360 */ 'G', '5', 0,
  /* 363 */ 'I', '5', 0,
  /* 366 */ 'L', '5', 0,
  /* 369 */ 'O', '5', 0,
  /* 372 */ 'A', 'S', 'R', '5', 0,
  /* 377 */ 'C', '1', '6', 0,
  /* 381 */ 'F', '1', '6', 0,
  /* 385 */ 'A', 'S', 'R', '1', '6', 0,
  /* 391 */ 'C', '2', '6', 0,
  /* 395 */ 'F', '2', '6', 0,
  /* 399 */ 'A', 'S', 'R', '2', '6', 0,
  /* 405 */ 'F', '3', '6', 0,
  /* 409 */ 'F', '4', '6', 0,
  /* 413 */ 'F', '5', '6', 0,
  /* 417 */ 'C', '6', 0,
  /* 420 */ 'F', '6', 0,
  /* 423 */ 'G', '6', 0,
  /* 426 */ 'I', '6', 0,
  /* 429 */ 'L', '6', 0,
  /* 432 */ 'O', '6', 0,
  /* 435 */ 'A', 'S', 'R', '6', 0,
  /* 440 */ 'C', '1', '7', 0,
  /* 444 */ 'F', '1', '7', 0,
  /* 448 */ 'A', 'S', 'R', '1', '7', 0,
  /* 454 */ 'C', '2', '7', 0,
  /* 458 */ 'F', '2', '7', 0,
  /* 462 */ 'A', 'S', 'R', '2', '7', 0,
  /* 468 */ 'C', '7', 0,
  /* 471 */ 'F', '7', 0,
  /* 474 */ 'G', '7', 0,
  /* 477 */ 'I', '7', 0,
  /* 480 */ 'L', '7', 0,
  /* 483 */ 'O', '7', 0,
  /* 486 */ 'A', 'S', 'R', '7', 0,
  /* 491 */ 'C', '1', '8', 0,
  /* 495 */ 'F', '1', '8', 0,
  /* 499 */ 'A', 'S', 'R', '1', '8', 0,
  /* 505 */ 'C', '2', '8', 0,
  /* 509 */ 'F', '2', '8', 0,
  /* 513 */ 'A', 'S', 'R', '2', '8', 0,
  /* 519 */ 'F', '3', '8', 0,
  /* 523 */ 'F', '4', '8', 0,
  /* 527 */ 'F', '5', '8', 0,
  /* 531 */ 'C', '8', 0,
  /* 534 */ 'F', '8', 0,
  /* 537 */ 'A', 'S', 'R', '8', 0,
  /* 542 */ 'C', '1', '9', 0,
  /* 546 */ 'F', '1', '9', 0,
  /* 550 */ 'A', 'S', 'R', '1', '9', 0,
  /* 556 */ 'C', '2', '9', 0,
  /* 560 */ 'F', '2', '9', 0,
  /* 564 */ 'A', 'S', 'R', '2', '9', 0,
  /* 570 */ 'C', '9', 0,
  /* 573 */ 'F', '9', 0,
  /* 576 */ 'A', 'S', 'R', '9', 0,
  /* 581 */ 'T', 'B', 'A', 0,
  /* 585 */ 'I', 'C', 'C', 0,
  /* 589 */ 'T', 'N', 'P', 'C', 0,
  /* 594 */ 'T', 'P', 'C', 0,
  /* 598 */ 'C', 'A', 'N', 'R', 'E', 'S', 'T', 'O', 'R', 'E', 0,
  /* 609 */ 'P', 'S', 'T', 'A', 'T', 'E', 0,
  /* 616 */ 'T', 'S', 'T', 'A', 'T', 'E', 0,
  /* 623 */ 'W', 'S', 'T', 'A', 'T', 'E', 0,
  /* 630 */ 'C', 'A', 'N', 'S', 'A', 'V', 'E', 0,
  /* 638 */ 'T', 'I', 'C', 'K', 0,
  /* 643 */ 'P', 'I', 'L', 0,
  /* 647 */ 'T', 'L', 0,
  /* 650 */ 'W', 'I', 'M', 0,
  /* 654 */ 'C', 'L', 'E', 'A', 'N', 'W', 'I', 'N', 0,
  /* 663 */ 'O', 'T', 'H', 'E', 'R', 'W', 'I', 'N', 0,
  /* 672 */ 'F', 'P', 0,
  /* 675 */ 'S', 'P', 0,
  /* 678 */ 'C', 'W', 'P', 0,
  /* 682 */ 'F', 'Q', 0,
  /* 685 */ 'C', 'P', 'Q', 0,
  /* 689 */ 'T', 'B', 'R', 0,
  /* 693 */ 'F', 'S', 'R', 0,
  /* 697 */ 'C', 'P', 'S', 'R', 0,
  /* 702 */ 'T', 'T', 0,
  /* 705 */ 'Y', 0,

};

  static const uint16_t RegAsmOffset[] = {
    598, 630, 654, 685, 697, 678, 682, 693, 585, 663, 643, 698, 609, 581, 
    689, 638, 647, 589, 594, 616, 702, 650, 623, 705, 136, 205, 258, 321, 
    372, 435, 486, 537, 576, 8, 82, 149, 218, 271, 334, 385, 448, 499, 
    550, 22, 96, 163, 232, 285, 348, 399, 462, 513, 564, 36, 110, 56, 
    118, 187, 240, 303, 354, 417, 468, 531, 570, 0, 74, 141, 210, 263, 
    326, 377, 440, 491, 542, 14, 88, 155, 224, 277, 340, 391, 454, 505, 
    556, 28, 102, 59, 190, 306, 420, 534, 4, 145, 267, 381, 495, 18, 
    159, 281, 395, 509, 32, 169, 291, 405, 519, 42, 173, 295, 409, 523, 
    46, 177, 299, 413, 527, 50, 181, 59, 121, 190, 243, 306, 357, 420, 
    471, 534, 573, 4, 78, 145, 214, 267, 330, 381, 444, 495, 546, 18, 
    92, 159, 228, 281, 344, 395, 458, 509, 560, 32, 106, 54, 116, 185, 
    238, 62, 124, 193, 246, 309, 360, 423, 474, 65, 127, 196, 249, 312, 
    363, 672, 477, 68, 130, 199, 252, 315, 366, 429, 480, 71, 133, 202, 
    255, 318, 369, 675, 483, 59, 306, 534, 145, 381, 18, 281, 509, 169, 
    405, 42, 295, 523, 177, 413, 50, 56, 187, 303, 417, 531, 0, 141, 
    263, 377, 491, 14, 155, 277, 391, 505, 28, 62, 193, 309, 423, 65, 
    196, 312, 426, 68, 199, 315, 429, 71, 202, 318, 432, 
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
  SStream_concat0(OS, AsmString + I);
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
        SStream_concat0(OS, AsmString + (I++));
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
