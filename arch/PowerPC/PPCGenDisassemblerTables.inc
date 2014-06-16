/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* * PPC Disassembler                                                         *|
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
static InsnType fname(InsnType insn, unsigned startBit, \
                                     unsigned numBits) \
{ \
    InsnType fieldMask; \
    if (numBits == sizeof(InsnType)*8) \
      fieldMask = (InsnType)(-1LL); \
    else \
      fieldMask = (((InsnType)1 << numBits) - 1) << startBit; \
    return (insn & fieldMask) >> startBit; \
}

// FieldFromInstruction(fieldFromInstruction_2, uint16_t)
FieldFromInstruction(fieldFromInstruction_4, uint32_t)

static uint8_t DecoderTable32[] = {
/* 0 */       MCD_OPC_ExtractField, 26, 6,  // Inst{31-26} ...
/* 3 */       MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 11
/* 7 */       MCD_OPC_Decode, 183, 5, 0, // Opcode: TDI
/* 11 */      MCD_OPC_FilterValue, 3, 4, 0, // Skip to: 19
/* 15 */      MCD_OPC_Decode, 189, 5, 1, // Opcode: TWI
/* 19 */      MCD_OPC_FilterValue, 4, 155, 5, // Skip to: 1458
/* 23 */      MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 26 */      MCD_OPC_FilterValue, 0, 163, 0, // Skip to: 193
/* 30 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 33 */      MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 41
/* 37 */      MCD_OPC_Decode, 196, 5, 2, // Opcode: VADDUBM
/* 41 */      MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 49
/* 45 */      MCD_OPC_Decode, 198, 5, 2, // Opcode: VADDUHM
/* 49 */      MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 57
/* 53 */      MCD_OPC_Decode, 200, 5, 2, // Opcode: VADDUWM
/* 57 */      MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 65
/* 61 */      MCD_OPC_Decode, 191, 5, 2, // Opcode: VADDCUW
/* 65 */      MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 73
/* 69 */      MCD_OPC_Decode, 197, 5, 2, // Opcode: VADDUBS
/* 73 */      MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 81
/* 77 */      MCD_OPC_Decode, 199, 5, 2, // Opcode: VADDUHS
/* 81 */      MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 89
/* 85 */      MCD_OPC_Decode, 201, 5, 2, // Opcode: VADDUWS
/* 89 */      MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 97
/* 93 */      MCD_OPC_Decode, 193, 5, 2, // Opcode: VADDSBS
/* 97 */      MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 105
/* 101 */     MCD_OPC_Decode, 194, 5, 2, // Opcode: VADDSHS
/* 105 */     MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 113
/* 109 */     MCD_OPC_Decode, 195, 5, 2, // Opcode: VADDSWS
/* 113 */     MCD_OPC_FilterValue, 16, 4, 0, // Skip to: 121
/* 117 */     MCD_OPC_Decode, 204, 6, 2, // Opcode: VSUBUBM
/* 121 */     MCD_OPC_FilterValue, 17, 4, 0, // Skip to: 129
/* 125 */     MCD_OPC_Decode, 206, 6, 2, // Opcode: VSUBUHM
/* 129 */     MCD_OPC_FilterValue, 18, 4, 0, // Skip to: 137
/* 133 */     MCD_OPC_Decode, 208, 6, 2, // Opcode: VSUBUWM
/* 137 */     MCD_OPC_FilterValue, 22, 4, 0, // Skip to: 145
/* 141 */     MCD_OPC_Decode, 199, 6, 2, // Opcode: VSUBCUW
/* 145 */     MCD_OPC_FilterValue, 24, 4, 0, // Skip to: 153
/* 149 */     MCD_OPC_Decode, 205, 6, 2, // Opcode: VSUBUBS
/* 153 */     MCD_OPC_FilterValue, 25, 4, 0, // Skip to: 161
/* 157 */     MCD_OPC_Decode, 207, 6, 2, // Opcode: VSUBUHS
/* 161 */     MCD_OPC_FilterValue, 26, 4, 0, // Skip to: 169
/* 165 */     MCD_OPC_Decode, 209, 6, 2, // Opcode: VSUBUWS
/* 169 */     MCD_OPC_FilterValue, 28, 4, 0, // Skip to: 177
/* 173 */     MCD_OPC_Decode, 201, 6, 2, // Opcode: VSUBSBS
/* 177 */     MCD_OPC_FilterValue, 29, 4, 0, // Skip to: 185
/* 181 */     MCD_OPC_Decode, 202, 6, 2, // Opcode: VSUBSHS
/* 185 */     MCD_OPC_FilterValue, 30, 108, 25, // Skip to: 6697
/* 189 */     MCD_OPC_Decode, 203, 6, 2, // Opcode: VSUBSWS
/* 193 */     MCD_OPC_FilterValue, 2, 147, 0, // Skip to: 344
/* 197 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 200 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 208
/* 204 */     MCD_OPC_Decode, 251, 5, 2, // Opcode: VMAXUB
/* 208 */     MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 216
/* 212 */     MCD_OPC_Decode, 252, 5, 2, // Opcode: VMAXUH
/* 216 */     MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 224
/* 220 */     MCD_OPC_Decode, 253, 5, 2, // Opcode: VMAXUW
/* 224 */     MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 232
/* 228 */     MCD_OPC_Decode, 248, 5, 2, // Opcode: VMAXSB
/* 232 */     MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 240
/* 236 */     MCD_OPC_Decode, 249, 5, 2, // Opcode: VMAXSH
/* 240 */     MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 248
/* 244 */     MCD_OPC_Decode, 250, 5, 2, // Opcode: VMAXSW
/* 248 */     MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 256
/* 252 */     MCD_OPC_Decode, 132, 6, 2, // Opcode: VMINUB
/* 256 */     MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 264
/* 260 */     MCD_OPC_Decode, 133, 6, 2, // Opcode: VMINUH
/* 264 */     MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 272
/* 268 */     MCD_OPC_Decode, 134, 6, 2, // Opcode: VMINUW
/* 272 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 280
/* 276 */     MCD_OPC_Decode, 129, 6, 2, // Opcode: VMINSB
/* 280 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 288
/* 284 */     MCD_OPC_Decode, 130, 6, 2, // Opcode: VMINSH
/* 288 */     MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 296
/* 292 */     MCD_OPC_Decode, 131, 6, 2, // Opcode: VMINSW
/* 296 */     MCD_OPC_FilterValue, 16, 4, 0, // Skip to: 304
/* 300 */     MCD_OPC_Decode, 207, 5, 2, // Opcode: VAVGUB
/* 304 */     MCD_OPC_FilterValue, 17, 4, 0, // Skip to: 312
/* 308 */     MCD_OPC_Decode, 208, 5, 2, // Opcode: VAVGUH
/* 312 */     MCD_OPC_FilterValue, 18, 4, 0, // Skip to: 320
/* 316 */     MCD_OPC_Decode, 209, 5, 2, // Opcode: VAVGUW
/* 320 */     MCD_OPC_FilterValue, 20, 4, 0, // Skip to: 328
/* 324 */     MCD_OPC_Decode, 204, 5, 2, // Opcode: VAVGSB
/* 328 */     MCD_OPC_FilterValue, 21, 4, 0, // Skip to: 336
/* 332 */     MCD_OPC_Decode, 205, 5, 2, // Opcode: VAVGSH
/* 336 */     MCD_OPC_FilterValue, 22, 213, 24, // Skip to: 6697
/* 340 */     MCD_OPC_Decode, 206, 5, 2, // Opcode: VAVGSW
/* 344 */     MCD_OPC_FilterValue, 4, 183, 0, // Skip to: 531
/* 348 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 351 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 359
/* 355 */     MCD_OPC_Decode, 174, 6, 2, // Opcode: VRLB
/* 359 */     MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 367
/* 363 */     MCD_OPC_Decode, 175, 6, 2, // Opcode: VRLH
/* 367 */     MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 375
/* 371 */     MCD_OPC_Decode, 176, 6, 2, // Opcode: VRLW
/* 375 */     MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 383
/* 379 */     MCD_OPC_Decode, 180, 6, 2, // Opcode: VSLB
/* 383 */     MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 391
/* 387 */     MCD_OPC_Decode, 182, 6, 2, // Opcode: VSLH
/* 391 */     MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 399
/* 395 */     MCD_OPC_Decode, 184, 6, 2, // Opcode: VSLW
/* 399 */     MCD_OPC_FilterValue, 7, 4, 0, // Skip to: 407
/* 403 */     MCD_OPC_Decode, 179, 6, 2, // Opcode: VSL
/* 407 */     MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 415
/* 411 */     MCD_OPC_Decode, 195, 6, 2, // Opcode: VSRB
/* 415 */     MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 423
/* 419 */     MCD_OPC_Decode, 196, 6, 2, // Opcode: VSRH
/* 423 */     MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 431
/* 427 */     MCD_OPC_Decode, 198, 6, 2, // Opcode: VSRW
/* 431 */     MCD_OPC_FilterValue, 11, 4, 0, // Skip to: 439
/* 435 */     MCD_OPC_Decode, 191, 6, 2, // Opcode: VSR
/* 439 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 447
/* 443 */     MCD_OPC_Decode, 192, 6, 2, // Opcode: VSRAB
/* 447 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 455
/* 451 */     MCD_OPC_Decode, 193, 6, 2, // Opcode: VSRAH
/* 455 */     MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 463
/* 459 */     MCD_OPC_Decode, 194, 6, 2, // Opcode: VSRAW
/* 463 */     MCD_OPC_FilterValue, 16, 4, 0, // Skip to: 471
/* 467 */     MCD_OPC_Decode, 202, 5, 2, // Opcode: VAND
/* 471 */     MCD_OPC_FilterValue, 17, 4, 0, // Skip to: 479
/* 475 */     MCD_OPC_Decode, 203, 5, 2, // Opcode: VANDC
/* 479 */     MCD_OPC_FilterValue, 18, 4, 0, // Skip to: 487
/* 483 */     MCD_OPC_Decode, 158, 6, 2, // Opcode: VOR
/* 487 */     MCD_OPC_FilterValue, 19, 4, 0, // Skip to: 495
/* 491 */     MCD_OPC_Decode, 221, 6, 2, // Opcode: VXOR
/* 495 */     MCD_OPC_FilterValue, 20, 4, 0, // Skip to: 503
/* 499 */     MCD_OPC_Decode, 157, 6, 2, // Opcode: VNOR
/* 503 */     MCD_OPC_FilterValue, 24, 10, 0, // Skip to: 517
/* 507 */     MCD_OPC_CheckField, 11, 10, 0, 40, 24, // Skip to: 6697
/* 513 */     MCD_OPC_Decode, 221, 3, 3, // Opcode: MFVSCR
/* 517 */     MCD_OPC_FilterValue, 25, 32, 24, // Skip to: 6697
/* 521 */     MCD_OPC_CheckField, 16, 10, 0, 26, 24, // Skip to: 6697
/* 527 */     MCD_OPC_Decode, 241, 3, 4, // Opcode: MTVSCR
/* 531 */     MCD_OPC_FilterValue, 6, 211, 0, // Skip to: 746
/* 535 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 538 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 546
/* 542 */     MCD_OPC_Decode, 218, 5, 2, // Opcode: VCMPEQUB
/* 546 */     MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 554
/* 550 */     MCD_OPC_Decode, 220, 5, 2, // Opcode: VCMPEQUH
/* 554 */     MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 562
/* 558 */     MCD_OPC_Decode, 222, 5, 2, // Opcode: VCMPEQUW
/* 562 */     MCD_OPC_FilterValue, 3, 4, 0, // Skip to: 570
/* 566 */     MCD_OPC_Decode, 216, 5, 2, // Opcode: VCMPEQFP
/* 570 */     MCD_OPC_FilterValue, 7, 4, 0, // Skip to: 578
/* 574 */     MCD_OPC_Decode, 224, 5, 2, // Opcode: VCMPGEFP
/* 578 */     MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 586
/* 582 */     MCD_OPC_Decode, 234, 5, 2, // Opcode: VCMPGTUB
/* 586 */     MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 594
/* 590 */     MCD_OPC_Decode, 236, 5, 2, // Opcode: VCMPGTUH
/* 594 */     MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 602
/* 598 */     MCD_OPC_Decode, 238, 5, 2, // Opcode: VCMPGTUW
/* 602 */     MCD_OPC_FilterValue, 11, 4, 0, // Skip to: 610
/* 606 */     MCD_OPC_Decode, 226, 5, 2, // Opcode: VCMPGTFP
/* 610 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 618
/* 614 */     MCD_OPC_Decode, 228, 5, 2, // Opcode: VCMPGTSB
/* 618 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 626
/* 622 */     MCD_OPC_Decode, 230, 5, 2, // Opcode: VCMPGTSH
/* 626 */     MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 634
/* 630 */     MCD_OPC_Decode, 232, 5, 2, // Opcode: VCMPGTSW
/* 634 */     MCD_OPC_FilterValue, 15, 4, 0, // Skip to: 642
/* 638 */     MCD_OPC_Decode, 214, 5, 2, // Opcode: VCMPBFP
/* 642 */     MCD_OPC_FilterValue, 16, 4, 0, // Skip to: 650
/* 646 */     MCD_OPC_Decode, 219, 5, 2, // Opcode: VCMPEQUBo
/* 650 */     MCD_OPC_FilterValue, 17, 4, 0, // Skip to: 658
/* 654 */     MCD_OPC_Decode, 221, 5, 2, // Opcode: VCMPEQUHo
/* 658 */     MCD_OPC_FilterValue, 18, 4, 0, // Skip to: 666
/* 662 */     MCD_OPC_Decode, 223, 5, 2, // Opcode: VCMPEQUWo
/* 666 */     MCD_OPC_FilterValue, 19, 4, 0, // Skip to: 674
/* 670 */     MCD_OPC_Decode, 217, 5, 2, // Opcode: VCMPEQFPo
/* 674 */     MCD_OPC_FilterValue, 23, 4, 0, // Skip to: 682
/* 678 */     MCD_OPC_Decode, 225, 5, 2, // Opcode: VCMPGEFPo
/* 682 */     MCD_OPC_FilterValue, 24, 4, 0, // Skip to: 690
/* 686 */     MCD_OPC_Decode, 235, 5, 2, // Opcode: VCMPGTUBo
/* 690 */     MCD_OPC_FilterValue, 25, 4, 0, // Skip to: 698
/* 694 */     MCD_OPC_Decode, 237, 5, 2, // Opcode: VCMPGTUHo
/* 698 */     MCD_OPC_FilterValue, 26, 4, 0, // Skip to: 706
/* 702 */     MCD_OPC_Decode, 239, 5, 2, // Opcode: VCMPGTUWo
/* 706 */     MCD_OPC_FilterValue, 27, 4, 0, // Skip to: 714
/* 710 */     MCD_OPC_Decode, 227, 5, 2, // Opcode: VCMPGTFPo
/* 714 */     MCD_OPC_FilterValue, 28, 4, 0, // Skip to: 722
/* 718 */     MCD_OPC_Decode, 229, 5, 2, // Opcode: VCMPGTSBo
/* 722 */     MCD_OPC_FilterValue, 29, 4, 0, // Skip to: 730
/* 726 */     MCD_OPC_Decode, 231, 5, 2, // Opcode: VCMPGTSHo
/* 730 */     MCD_OPC_FilterValue, 30, 4, 0, // Skip to: 738
/* 734 */     MCD_OPC_Decode, 233, 5, 2, // Opcode: VCMPGTSWo
/* 738 */     MCD_OPC_FilterValue, 31, 67, 23, // Skip to: 6697
/* 742 */     MCD_OPC_Decode, 215, 5, 2, // Opcode: VCMPBFPo
/* 746 */     MCD_OPC_FilterValue, 8, 107, 0, // Skip to: 857
/* 750 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 753 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 761
/* 757 */     MCD_OPC_Decode, 154, 6, 2, // Opcode: VMULOUB
/* 761 */     MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 769
/* 765 */     MCD_OPC_Decode, 155, 6, 2, // Opcode: VMULOUH
/* 769 */     MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 777
/* 773 */     MCD_OPC_Decode, 152, 6, 2, // Opcode: VMULOSB
/* 777 */     MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 785
/* 781 */     MCD_OPC_Decode, 153, 6, 2, // Opcode: VMULOSH
/* 785 */     MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 793
/* 789 */     MCD_OPC_Decode, 150, 6, 2, // Opcode: VMULEUB
/* 793 */     MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 801
/* 797 */     MCD_OPC_Decode, 151, 6, 2, // Opcode: VMULEUH
/* 801 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 809
/* 805 */     MCD_OPC_Decode, 148, 6, 2, // Opcode: VMULESB
/* 809 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 817
/* 813 */     MCD_OPC_Decode, 149, 6, 2, // Opcode: VMULESH
/* 817 */     MCD_OPC_FilterValue, 24, 4, 0, // Skip to: 825
/* 821 */     MCD_OPC_Decode, 213, 6, 2, // Opcode: VSUM4UBS
/* 825 */     MCD_OPC_FilterValue, 25, 4, 0, // Skip to: 833
/* 829 */     MCD_OPC_Decode, 212, 6, 2, // Opcode: VSUM4SHS
/* 833 */     MCD_OPC_FilterValue, 26, 4, 0, // Skip to: 841
/* 837 */     MCD_OPC_Decode, 210, 6, 2, // Opcode: VSUM2SWS
/* 841 */     MCD_OPC_FilterValue, 28, 4, 0, // Skip to: 849
/* 845 */     MCD_OPC_Decode, 211, 6, 2, // Opcode: VSUM4SBS
/* 849 */     MCD_OPC_FilterValue, 30, 212, 22, // Skip to: 6697
/* 853 */     MCD_OPC_Decode, 214, 6, 2, // Opcode: VSUMSWS
/* 857 */     MCD_OPC_FilterValue, 10, 179, 0, // Skip to: 1040
/* 861 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 864 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 872
/* 868 */     MCD_OPC_Decode, 192, 5, 2, // Opcode: VADDFP
/* 872 */     MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 880
/* 876 */     MCD_OPC_Decode, 200, 6, 2, // Opcode: VSUBFP
/* 880 */     MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 894
/* 884 */     MCD_OPC_CheckField, 16, 5, 0, 175, 22, // Skip to: 6697
/* 890 */     MCD_OPC_Decode, 169, 6, 5, // Opcode: VREFP
/* 894 */     MCD_OPC_FilterValue, 5, 10, 0, // Skip to: 908
/* 898 */     MCD_OPC_CheckField, 16, 5, 0, 161, 22, // Skip to: 6697
/* 904 */     MCD_OPC_Decode, 177, 6, 5, // Opcode: VRSQRTEFP
/* 908 */     MCD_OPC_FilterValue, 6, 10, 0, // Skip to: 922
/* 912 */     MCD_OPC_CheckField, 16, 5, 0, 147, 22, // Skip to: 6697
/* 918 */     MCD_OPC_Decode, 244, 5, 5, // Opcode: VEXPTEFP
/* 922 */     MCD_OPC_FilterValue, 7, 10, 0, // Skip to: 936
/* 926 */     MCD_OPC_CheckField, 16, 5, 0, 133, 22, // Skip to: 6697
/* 932 */     MCD_OPC_Decode, 245, 5, 5, // Opcode: VLOGEFP
/* 936 */     MCD_OPC_FilterValue, 8, 10, 0, // Skip to: 950
/* 940 */     MCD_OPC_CheckField, 16, 5, 0, 119, 22, // Skip to: 6697
/* 946 */     MCD_OPC_Decode, 171, 6, 5, // Opcode: VRFIN
/* 950 */     MCD_OPC_FilterValue, 9, 10, 0, // Skip to: 964
/* 954 */     MCD_OPC_CheckField, 16, 5, 0, 105, 22, // Skip to: 6697
/* 960 */     MCD_OPC_Decode, 173, 6, 5, // Opcode: VRFIZ
/* 964 */     MCD_OPC_FilterValue, 10, 10, 0, // Skip to: 978
/* 968 */     MCD_OPC_CheckField, 16, 5, 0, 91, 22, // Skip to: 6697
/* 974 */     MCD_OPC_Decode, 172, 6, 5, // Opcode: VRFIP
/* 978 */     MCD_OPC_FilterValue, 11, 10, 0, // Skip to: 992
/* 982 */     MCD_OPC_CheckField, 16, 5, 0, 77, 22, // Skip to: 6697
/* 988 */     MCD_OPC_Decode, 170, 6, 5, // Opcode: VRFIM
/* 992 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 1000
/* 996 */     MCD_OPC_Decode, 212, 5, 6, // Opcode: VCFUX
/* 1000 */    MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 1008
/* 1004 */    MCD_OPC_Decode, 210, 5, 6, // Opcode: VCFSX
/* 1008 */    MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 1016
/* 1012 */    MCD_OPC_Decode, 242, 5, 6, // Opcode: VCTUXS
/* 1016 */    MCD_OPC_FilterValue, 15, 4, 0, // Skip to: 1024
/* 1020 */    MCD_OPC_Decode, 240, 5, 6, // Opcode: VCTSXS
/* 1024 */    MCD_OPC_FilterValue, 16, 4, 0, // Skip to: 1032
/* 1028 */    MCD_OPC_Decode, 247, 5, 2, // Opcode: VMAXFP
/* 1032 */    MCD_OPC_FilterValue, 17, 29, 22, // Skip to: 6697
/* 1036 */    MCD_OPC_Decode, 128, 6, 2, // Opcode: VMINFP
/* 1040 */    MCD_OPC_FilterValue, 12, 133, 0, // Skip to: 1177
/* 1044 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 1047 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 1055
/* 1051 */    MCD_OPC_Decode, 136, 6, 2, // Opcode: VMRGHB
/* 1055 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 1063
/* 1059 */    MCD_OPC_Decode, 137, 6, 2, // Opcode: VMRGHH
/* 1063 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 1071
/* 1067 */    MCD_OPC_Decode, 138, 6, 2, // Opcode: VMRGHW
/* 1071 */    MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 1079
/* 1075 */    MCD_OPC_Decode, 139, 6, 2, // Opcode: VMRGLB
/* 1079 */    MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 1087
/* 1083 */    MCD_OPC_Decode, 140, 6, 2, // Opcode: VMRGLH
/* 1087 */    MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 1095
/* 1091 */    MCD_OPC_Decode, 141, 6, 2, // Opcode: VMRGLW
/* 1095 */    MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 1103
/* 1099 */    MCD_OPC_Decode, 185, 6, 6, // Opcode: VSPLTB
/* 1103 */    MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 1111
/* 1107 */    MCD_OPC_Decode, 186, 6, 6, // Opcode: VSPLTH
/* 1111 */    MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 1119
/* 1115 */    MCD_OPC_Decode, 190, 6, 6, // Opcode: VSPLTW
/* 1119 */    MCD_OPC_FilterValue, 12, 10, 0, // Skip to: 1133
/* 1123 */    MCD_OPC_CheckField, 11, 5, 0, 192, 21, // Skip to: 6697
/* 1129 */    MCD_OPC_Decode, 187, 6, 7, // Opcode: VSPLTISB
/* 1133 */    MCD_OPC_FilterValue, 13, 10, 0, // Skip to: 1147
/* 1137 */    MCD_OPC_CheckField, 11, 5, 0, 178, 21, // Skip to: 6697
/* 1143 */    MCD_OPC_Decode, 188, 6, 7, // Opcode: VSPLTISH
/* 1147 */    MCD_OPC_FilterValue, 14, 10, 0, // Skip to: 1161
/* 1151 */    MCD_OPC_CheckField, 11, 5, 0, 164, 21, // Skip to: 6697
/* 1157 */    MCD_OPC_Decode, 189, 6, 7, // Opcode: VSPLTISW
/* 1161 */    MCD_OPC_FilterValue, 16, 4, 0, // Skip to: 1169
/* 1165 */    MCD_OPC_Decode, 183, 6, 2, // Opcode: VSLO
/* 1169 */    MCD_OPC_FilterValue, 17, 148, 21, // Skip to: 6697
/* 1173 */    MCD_OPC_Decode, 197, 6, 2, // Opcode: VSRO
/* 1177 */    MCD_OPC_FilterValue, 14, 159, 0, // Skip to: 1340
/* 1181 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 1184 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 1192
/* 1188 */    MCD_OPC_Decode, 165, 6, 2, // Opcode: VPKUHUM
/* 1192 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 1200
/* 1196 */    MCD_OPC_Decode, 167, 6, 2, // Opcode: VPKUWUM
/* 1200 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 1208
/* 1204 */    MCD_OPC_Decode, 166, 6, 2, // Opcode: VPKUHUS
/* 1208 */    MCD_OPC_FilterValue, 3, 4, 0, // Skip to: 1216
/* 1212 */    MCD_OPC_Decode, 168, 6, 2, // Opcode: VPKUWUS
/* 1216 */    MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 1224
/* 1220 */    MCD_OPC_Decode, 162, 6, 2, // Opcode: VPKSHUS
/* 1224 */    MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 1232
/* 1228 */    MCD_OPC_Decode, 164, 6, 2, // Opcode: VPKSWUS
/* 1232 */    MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 1240
/* 1236 */    MCD_OPC_Decode, 161, 6, 2, // Opcode: VPKSHSS
/* 1240 */    MCD_OPC_FilterValue, 7, 4, 0, // Skip to: 1248
/* 1244 */    MCD_OPC_Decode, 163, 6, 2, // Opcode: VPKSWSS
/* 1248 */    MCD_OPC_FilterValue, 8, 10, 0, // Skip to: 1262
/* 1252 */    MCD_OPC_CheckField, 16, 5, 0, 63, 21, // Skip to: 6697
/* 1258 */    MCD_OPC_Decode, 216, 6, 5, // Opcode: VUPKHSB
/* 1262 */    MCD_OPC_FilterValue, 9, 10, 0, // Skip to: 1276
/* 1266 */    MCD_OPC_CheckField, 16, 5, 0, 49, 21, // Skip to: 6697
/* 1272 */    MCD_OPC_Decode, 217, 6, 5, // Opcode: VUPKHSH
/* 1276 */    MCD_OPC_FilterValue, 10, 10, 0, // Skip to: 1290
/* 1280 */    MCD_OPC_CheckField, 16, 5, 0, 35, 21, // Skip to: 6697
/* 1286 */    MCD_OPC_Decode, 219, 6, 5, // Opcode: VUPKLSB
/* 1290 */    MCD_OPC_FilterValue, 11, 10, 0, // Skip to: 1304
/* 1294 */    MCD_OPC_CheckField, 16, 5, 0, 21, 21, // Skip to: 6697
/* 1300 */    MCD_OPC_Decode, 220, 6, 5, // Opcode: VUPKLSH
/* 1304 */    MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 1312
/* 1308 */    MCD_OPC_Decode, 160, 6, 2, // Opcode: VPKPX
/* 1312 */    MCD_OPC_FilterValue, 13, 10, 0, // Skip to: 1326
/* 1316 */    MCD_OPC_CheckField, 16, 5, 0, 255, 20, // Skip to: 6697
/* 1322 */    MCD_OPC_Decode, 215, 6, 5, // Opcode: VUPKHPX
/* 1326 */    MCD_OPC_FilterValue, 15, 247, 20, // Skip to: 6697
/* 1330 */    MCD_OPC_CheckField, 16, 5, 0, 241, 20, // Skip to: 6697
/* 1336 */    MCD_OPC_Decode, 218, 6, 5, // Opcode: VUPKLPX
/* 1340 */    MCD_OPC_FilterValue, 32, 4, 0, // Skip to: 1348
/* 1344 */    MCD_OPC_Decode, 254, 5, 8, // Opcode: VMHADDSHS
/* 1348 */    MCD_OPC_FilterValue, 33, 4, 0, // Skip to: 1356
/* 1352 */    MCD_OPC_Decode, 255, 5, 8, // Opcode: VMHRADDSHS
/* 1356 */    MCD_OPC_FilterValue, 34, 4, 0, // Skip to: 1364
/* 1360 */    MCD_OPC_Decode, 135, 6, 8, // Opcode: VMLADDUHM
/* 1364 */    MCD_OPC_FilterValue, 36, 4, 0, // Skip to: 1372
/* 1368 */    MCD_OPC_Decode, 145, 6, 8, // Opcode: VMSUMUBM
/* 1372 */    MCD_OPC_FilterValue, 37, 4, 0, // Skip to: 1380
/* 1376 */    MCD_OPC_Decode, 142, 6, 8, // Opcode: VMSUMMBM
/* 1380 */    MCD_OPC_FilterValue, 38, 4, 0, // Skip to: 1388
/* 1384 */    MCD_OPC_Decode, 146, 6, 8, // Opcode: VMSUMUHM
/* 1388 */    MCD_OPC_FilterValue, 39, 4, 0, // Skip to: 1396
/* 1392 */    MCD_OPC_Decode, 147, 6, 8, // Opcode: VMSUMUHS
/* 1396 */    MCD_OPC_FilterValue, 40, 4, 0, // Skip to: 1404
/* 1400 */    MCD_OPC_Decode, 143, 6, 8, // Opcode: VMSUMSHM
/* 1404 */    MCD_OPC_FilterValue, 41, 4, 0, // Skip to: 1412
/* 1408 */    MCD_OPC_Decode, 144, 6, 8, // Opcode: VMSUMSHS
/* 1412 */    MCD_OPC_FilterValue, 42, 4, 0, // Skip to: 1420
/* 1416 */    MCD_OPC_Decode, 178, 6, 8, // Opcode: VSEL
/* 1420 */    MCD_OPC_FilterValue, 43, 4, 0, // Skip to: 1428
/* 1424 */    MCD_OPC_Decode, 159, 6, 8, // Opcode: VPERM
/* 1428 */    MCD_OPC_FilterValue, 44, 10, 0, // Skip to: 1442
/* 1432 */    MCD_OPC_CheckField, 10, 1, 0, 139, 20, // Skip to: 6697
/* 1438 */    MCD_OPC_Decode, 181, 6, 9, // Opcode: VSLDOI
/* 1442 */    MCD_OPC_FilterValue, 46, 4, 0, // Skip to: 1450
/* 1446 */    MCD_OPC_Decode, 246, 5, 10, // Opcode: VMADDFP
/* 1450 */    MCD_OPC_FilterValue, 47, 123, 20, // Skip to: 6697
/* 1454 */    MCD_OPC_Decode, 156, 6, 10, // Opcode: VNMSUBFP
/* 1458 */    MCD_OPC_FilterValue, 7, 4, 0, // Skip to: 1466
/* 1462 */    MCD_OPC_Decode, 252, 3, 11, // Opcode: MULLI
/* 1466 */    MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 1474
/* 1470 */    MCD_OPC_Decode, 154, 5, 11, // Opcode: SUBFIC
/* 1474 */    MCD_OPC_FilterValue, 10, 19, 0, // Skip to: 1497
/* 1478 */    MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 1481 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 1489
/* 1485 */    MCD_OPC_Decode, 185, 1, 12, // Opcode: CMPLWI
/* 1489 */    MCD_OPC_FilterValue, 1, 84, 20, // Skip to: 6697
/* 1493 */    MCD_OPC_Decode, 183, 1, 13, // Opcode: CMPLDI
/* 1497 */    MCD_OPC_FilterValue, 11, 19, 0, // Skip to: 1520
/* 1501 */    MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 1504 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 1512
/* 1508 */    MCD_OPC_Decode, 187, 1, 14, // Opcode: CMPWI
/* 1512 */    MCD_OPC_FilterValue, 1, 61, 20, // Skip to: 6697
/* 1516 */    MCD_OPC_Decode, 181, 1, 15, // Opcode: CMPDI
/* 1520 */    MCD_OPC_FilterValue, 12, 3, 0, // Skip to: 1527
/* 1524 */    MCD_OPC_Decode, 36, 11, // Opcode: ADDIC
/* 1527 */    MCD_OPC_FilterValue, 13, 3, 0, // Skip to: 1534
/* 1531 */    MCD_OPC_Decode, 38, 11, // Opcode: ADDICo
/* 1534 */    MCD_OPC_FilterValue, 14, 13, 0, // Skip to: 1551
/* 1538 */    MCD_OPC_CheckField, 16, 5, 0, 4, 0, // Skip to: 1548
/* 1544 */    MCD_OPC_Decode, 178, 3, 16, // Opcode: LI
/* 1548 */    MCD_OPC_Decode, 34, 17, // Opcode: ADDI
/* 1551 */    MCD_OPC_FilterValue, 15, 13, 0, // Skip to: 1568
/* 1555 */    MCD_OPC_CheckField, 16, 5, 0, 4, 0, // Skip to: 1565
/* 1561 */    MCD_OPC_Decode, 180, 3, 16, // Opcode: LIS
/* 1565 */    MCD_OPC_Decode, 39, 17, // Opcode: ADDIS
/* 1568 */    MCD_OPC_FilterValue, 16, 1, 1, // Skip to: 1829
/* 1572 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 1575 */    MCD_OPC_FilterValue, 0, 60, 0, // Skip to: 1639
/* 1579 */    MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 1582 */    MCD_OPC_FilterValue, 128, 4, 3, 0, // Skip to: 1590
/* 1587 */    MCD_OPC_Decode, 121, 18, // Opcode: BDNZ
/* 1590 */    MCD_OPC_FilterValue, 192, 4, 4, 0, // Skip to: 1599
/* 1595 */    MCD_OPC_Decode, 141, 1, 18, // Opcode: BDZ
/* 1599 */    MCD_OPC_FilterValue, 128, 6, 4, 0, // Skip to: 1608
/* 1604 */    MCD_OPC_Decode, 139, 1, 18, // Opcode: BDNZm
/* 1608 */    MCD_OPC_FilterValue, 160, 6, 4, 0, // Skip to: 1617
/* 1613 */    MCD_OPC_Decode, 140, 1, 18, // Opcode: BDNZp
/* 1617 */    MCD_OPC_FilterValue, 192, 6, 4, 0, // Skip to: 1626
/* 1622 */    MCD_OPC_Decode, 159, 1, 18, // Opcode: BDZm
/* 1626 */    MCD_OPC_FilterValue, 224, 6, 4, 0, // Skip to: 1635
/* 1631 */    MCD_OPC_Decode, 160, 1, 18, // Opcode: BDZp
/* 1635 */    MCD_OPC_Decode, 237, 6, 19, // Opcode: gBC
/* 1639 */    MCD_OPC_FilterValue, 1, 60, 0, // Skip to: 1703
/* 1643 */    MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 1646 */    MCD_OPC_FilterValue, 128, 4, 3, 0, // Skip to: 1654
/* 1651 */    MCD_OPC_Decode, 126, 18, // Opcode: BDNZL
/* 1654 */    MCD_OPC_FilterValue, 192, 4, 4, 0, // Skip to: 1663
/* 1659 */    MCD_OPC_Decode, 146, 1, 18, // Opcode: BDZL
/* 1663 */    MCD_OPC_FilterValue, 128, 6, 4, 0, // Skip to: 1672
/* 1668 */    MCD_OPC_Decode, 137, 1, 18, // Opcode: BDNZLm
/* 1672 */    MCD_OPC_FilterValue, 160, 6, 4, 0, // Skip to: 1681
/* 1677 */    MCD_OPC_Decode, 138, 1, 18, // Opcode: BDNZLp
/* 1681 */    MCD_OPC_FilterValue, 192, 6, 4, 0, // Skip to: 1690
/* 1686 */    MCD_OPC_Decode, 157, 1, 18, // Opcode: BDZLm
/* 1690 */    MCD_OPC_FilterValue, 224, 6, 4, 0, // Skip to: 1699
/* 1695 */    MCD_OPC_Decode, 158, 1, 18, // Opcode: BDZLp
/* 1699 */    MCD_OPC_Decode, 241, 6, 19, // Opcode: gBCL
/* 1703 */    MCD_OPC_FilterValue, 2, 58, 0, // Skip to: 1765
/* 1707 */    MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 1710 */    MCD_OPC_FilterValue, 128, 4, 3, 0, // Skip to: 1718
/* 1715 */    MCD_OPC_Decode, 123, 18, // Opcode: BDNZA
/* 1718 */    MCD_OPC_FilterValue, 192, 4, 4, 0, // Skip to: 1727
/* 1723 */    MCD_OPC_Decode, 143, 1, 18, // Opcode: BDZA
/* 1727 */    MCD_OPC_FilterValue, 128, 6, 3, 0, // Skip to: 1735
/* 1732 */    MCD_OPC_Decode, 124, 18, // Opcode: BDNZAm
/* 1735 */    MCD_OPC_FilterValue, 160, 6, 3, 0, // Skip to: 1743
/* 1740 */    MCD_OPC_Decode, 125, 18, // Opcode: BDNZAp
/* 1743 */    MCD_OPC_FilterValue, 192, 6, 4, 0, // Skip to: 1752
/* 1748 */    MCD_OPC_Decode, 144, 1, 18, // Opcode: BDZAm
/* 1752 */    MCD_OPC_FilterValue, 224, 6, 4, 0, // Skip to: 1761
/* 1757 */    MCD_OPC_Decode, 145, 1, 18, // Opcode: BDZAp
/* 1761 */    MCD_OPC_Decode, 238, 6, 19, // Opcode: gBCA
/* 1765 */    MCD_OPC_FilterValue, 3, 64, 19, // Skip to: 6697
/* 1769 */    MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 1772 */    MCD_OPC_FilterValue, 128, 4, 3, 0, // Skip to: 1780
/* 1777 */    MCD_OPC_Decode, 127, 18, // Opcode: BDNZLA
/* 1780 */    MCD_OPC_FilterValue, 192, 4, 4, 0, // Skip to: 1789
/* 1785 */    MCD_OPC_Decode, 147, 1, 18, // Opcode: BDZLA
/* 1789 */    MCD_OPC_FilterValue, 128, 6, 4, 0, // Skip to: 1798
/* 1794 */    MCD_OPC_Decode, 128, 1, 18, // Opcode: BDNZLAm
/* 1798 */    MCD_OPC_FilterValue, 160, 6, 4, 0, // Skip to: 1807
/* 1803 */    MCD_OPC_Decode, 129, 1, 18, // Opcode: BDNZLAp
/* 1807 */    MCD_OPC_FilterValue, 192, 6, 4, 0, // Skip to: 1816
/* 1812 */    MCD_OPC_Decode, 148, 1, 18, // Opcode: BDZLAm
/* 1816 */    MCD_OPC_FilterValue, 224, 6, 4, 0, // Skip to: 1825
/* 1821 */    MCD_OPC_Decode, 149, 1, 18, // Opcode: BDZLAp
/* 1825 */    MCD_OPC_Decode, 242, 6, 19, // Opcode: gBCLA
/* 1829 */    MCD_OPC_FilterValue, 17, 10, 0, // Skip to: 1843
/* 1833 */    MCD_OPC_CheckField, 1, 1, 1, 250, 18, // Skip to: 6697
/* 1839 */    MCD_OPC_Decode, 187, 4, 20, // Opcode: SC
/* 1843 */    MCD_OPC_FilterValue, 18, 33, 0, // Skip to: 1880
/* 1847 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 1850 */    MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 1857
/* 1854 */    MCD_OPC_Decode, 104, 21, // Opcode: B
/* 1857 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 1865
/* 1861 */    MCD_OPC_Decode, 161, 1, 21, // Opcode: BL
/* 1865 */    MCD_OPC_FilterValue, 2, 3, 0, // Skip to: 1872
/* 1869 */    MCD_OPC_Decode, 105, 21, // Opcode: BA
/* 1872 */    MCD_OPC_FilterValue, 3, 213, 18, // Skip to: 6697
/* 1876 */    MCD_OPC_Decode, 167, 1, 21, // Opcode: BLA
/* 1880 */    MCD_OPC_FilterValue, 19, 163, 1, // Skip to: 2303
/* 1884 */    MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 1887 */    MCD_OPC_FilterValue, 0, 16, 0, // Skip to: 1907
/* 1891 */    MCD_OPC_CheckField, 21, 2, 0, 192, 18, // Skip to: 6697
/* 1897 */    MCD_OPC_CheckField, 11, 7, 0, 186, 18, // Skip to: 6697
/* 1903 */    MCD_OPC_Decode, 205, 3, 22, // Opcode: MCRF
/* 1907 */    MCD_OPC_FilterValue, 32, 119, 0, // Skip to: 2030
/* 1911 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 1914 */    MCD_OPC_FilterValue, 0, 171, 18, // Skip to: 6697
/* 1918 */    MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 1921 */    MCD_OPC_FilterValue, 128, 4, 10, 0, // Skip to: 1936
/* 1926 */    MCD_OPC_CheckField, 11, 2, 0, 94, 0, // Skip to: 2026
/* 1932 */    MCD_OPC_Decode, 130, 1, 23, // Opcode: BDNZLR
/* 1936 */    MCD_OPC_FilterValue, 192, 4, 10, 0, // Skip to: 1951
/* 1941 */    MCD_OPC_CheckField, 11, 2, 0, 79, 0, // Skip to: 2026
/* 1947 */    MCD_OPC_Decode, 150, 1, 23, // Opcode: BDZLR
/* 1951 */    MCD_OPC_FilterValue, 128, 5, 10, 0, // Skip to: 1966
/* 1956 */    MCD_OPC_CheckField, 11, 2, 0, 64, 0, // Skip to: 2026
/* 1962 */    MCD_OPC_Decode, 170, 1, 23, // Opcode: BLR
/* 1966 */    MCD_OPC_FilterValue, 128, 6, 10, 0, // Skip to: 1981
/* 1971 */    MCD_OPC_CheckField, 11, 2, 0, 49, 0, // Skip to: 2026
/* 1977 */    MCD_OPC_Decode, 135, 1, 23, // Opcode: BDNZLRm
/* 1981 */    MCD_OPC_FilterValue, 160, 6, 10, 0, // Skip to: 1996
/* 1986 */    MCD_OPC_CheckField, 11, 2, 0, 34, 0, // Skip to: 2026
/* 1992 */    MCD_OPC_Decode, 136, 1, 23, // Opcode: BDNZLRp
/* 1996 */    MCD_OPC_FilterValue, 192, 6, 10, 0, // Skip to: 2011
/* 2001 */    MCD_OPC_CheckField, 11, 2, 0, 19, 0, // Skip to: 2026
/* 2007 */    MCD_OPC_Decode, 155, 1, 23, // Opcode: BDZLRm
/* 2011 */    MCD_OPC_FilterValue, 224, 6, 10, 0, // Skip to: 2026
/* 2016 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 2026
/* 2022 */    MCD_OPC_Decode, 156, 1, 23, // Opcode: BDZLRp
/* 2026 */    MCD_OPC_Decode, 243, 6, 24, // Opcode: gBCLR
/* 2030 */    MCD_OPC_FilterValue, 33, 119, 0, // Skip to: 2153
/* 2034 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 2037 */    MCD_OPC_FilterValue, 0, 48, 18, // Skip to: 6697
/* 2041 */    MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 2044 */    MCD_OPC_FilterValue, 128, 4, 10, 0, // Skip to: 2059
/* 2049 */    MCD_OPC_CheckField, 11, 2, 0, 94, 0, // Skip to: 2149
/* 2055 */    MCD_OPC_Decode, 132, 1, 23, // Opcode: BDNZLRL
/* 2059 */    MCD_OPC_FilterValue, 192, 4, 10, 0, // Skip to: 2074
/* 2064 */    MCD_OPC_CheckField, 11, 2, 0, 79, 0, // Skip to: 2149
/* 2070 */    MCD_OPC_Decode, 152, 1, 23, // Opcode: BDZLRL
/* 2074 */    MCD_OPC_FilterValue, 128, 5, 10, 0, // Skip to: 2089
/* 2079 */    MCD_OPC_CheckField, 11, 2, 0, 64, 0, // Skip to: 2149
/* 2085 */    MCD_OPC_Decode, 171, 1, 23, // Opcode: BLRL
/* 2089 */    MCD_OPC_FilterValue, 128, 6, 10, 0, // Skip to: 2104
/* 2094 */    MCD_OPC_CheckField, 11, 2, 0, 49, 0, // Skip to: 2149
/* 2100 */    MCD_OPC_Decode, 133, 1, 23, // Opcode: BDNZLRLm
/* 2104 */    MCD_OPC_FilterValue, 160, 6, 10, 0, // Skip to: 2119
/* 2109 */    MCD_OPC_CheckField, 11, 2, 0, 34, 0, // Skip to: 2149
/* 2115 */    MCD_OPC_Decode, 134, 1, 23, // Opcode: BDNZLRLp
/* 2119 */    MCD_OPC_FilterValue, 192, 6, 10, 0, // Skip to: 2134
/* 2124 */    MCD_OPC_CheckField, 11, 2, 0, 19, 0, // Skip to: 2149
/* 2130 */    MCD_OPC_Decode, 153, 1, 23, // Opcode: BDZLRLm
/* 2134 */    MCD_OPC_FilterValue, 224, 6, 10, 0, // Skip to: 2149
/* 2139 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 2149
/* 2145 */    MCD_OPC_Decode, 154, 1, 23, // Opcode: BDZLRLp
/* 2149 */    MCD_OPC_Decode, 244, 6, 24, // Opcode: gBCLRL
/* 2153 */    MCD_OPC_FilterValue, 66, 4, 0, // Skip to: 2161
/* 2157 */    MCD_OPC_Decode, 198, 1, 25, // Opcode: CRNOR
/* 2161 */    MCD_OPC_FilterValue, 130, 2, 4, 0, // Skip to: 2170
/* 2166 */    MCD_OPC_Decode, 195, 1, 25, // Opcode: CRANDC
/* 2170 */    MCD_OPC_FilterValue, 172, 2, 10, 0, // Skip to: 2185
/* 2175 */    MCD_OPC_CheckField, 11, 15, 0, 164, 17, // Skip to: 6697
/* 2181 */    MCD_OPC_Decode, 254, 2, 23, // Opcode: ISYNC
/* 2185 */    MCD_OPC_FilterValue, 130, 3, 4, 0, // Skip to: 2194
/* 2190 */    MCD_OPC_Decode, 203, 1, 25, // Opcode: CRXOR
/* 2194 */    MCD_OPC_FilterValue, 194, 3, 4, 0, // Skip to: 2203
/* 2199 */    MCD_OPC_Decode, 197, 1, 25, // Opcode: CRNAND
/* 2203 */    MCD_OPC_FilterValue, 130, 4, 4, 0, // Skip to: 2212
/* 2208 */    MCD_OPC_Decode, 194, 1, 25, // Opcode: CRAND
/* 2212 */    MCD_OPC_FilterValue, 194, 4, 4, 0, // Skip to: 2221
/* 2217 */    MCD_OPC_Decode, 196, 1, 25, // Opcode: CREQV
/* 2221 */    MCD_OPC_FilterValue, 194, 6, 4, 0, // Skip to: 2230
/* 2226 */    MCD_OPC_Decode, 200, 1, 25, // Opcode: CRORC
/* 2230 */    MCD_OPC_FilterValue, 130, 7, 4, 0, // Skip to: 2239
/* 2235 */    MCD_OPC_Decode, 199, 1, 25, // Opcode: CROR
/* 2239 */    MCD_OPC_FilterValue, 160, 8, 27, 0, // Skip to: 2271
/* 2244 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 2247 */    MCD_OPC_FilterValue, 0, 94, 17, // Skip to: 6697
/* 2251 */    MCD_OPC_CheckField, 16, 10, 128, 5, 9, 0, // Skip to: 2267
/* 2258 */    MCD_OPC_CheckField, 11, 2, 0, 3, 0, // Skip to: 2267
/* 2264 */    MCD_OPC_Decode, 117, 23, // Opcode: BCTR
/* 2267 */    MCD_OPC_Decode, 239, 6, 24, // Opcode: gBCCTR
/* 2271 */    MCD_OPC_FilterValue, 161, 8, 69, 17, // Skip to: 6697
/* 2276 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 2279 */    MCD_OPC_FilterValue, 0, 62, 17, // Skip to: 6697
/* 2283 */    MCD_OPC_CheckField, 16, 10, 128, 5, 9, 0, // Skip to: 2299
/* 2290 */    MCD_OPC_CheckField, 11, 2, 0, 3, 0, // Skip to: 2299
/* 2296 */    MCD_OPC_Decode, 119, 23, // Opcode: BCTRL
/* 2299 */    MCD_OPC_Decode, 240, 6, 24, // Opcode: gBCCTRL
/* 2303 */    MCD_OPC_FilterValue, 20, 19, 0, // Skip to: 2326
/* 2307 */    MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 2310 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2318
/* 2314 */    MCD_OPC_Decode, 175, 4, 26, // Opcode: RLWIMI
/* 2318 */    MCD_OPC_FilterValue, 1, 23, 17, // Skip to: 6697
/* 2322 */    MCD_OPC_Decode, 176, 4, 26, // Opcode: RLWIMIo
/* 2326 */    MCD_OPC_FilterValue, 21, 19, 0, // Skip to: 2349
/* 2330 */    MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 2333 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2341
/* 2337 */    MCD_OPC_Decode, 177, 4, 27, // Opcode: RLWINM
/* 2341 */    MCD_OPC_FilterValue, 1, 0, 17, // Skip to: 6697
/* 2345 */    MCD_OPC_Decode, 180, 4, 27, // Opcode: RLWINMo
/* 2349 */    MCD_OPC_FilterValue, 23, 19, 0, // Skip to: 2372
/* 2353 */    MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 2356 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2364
/* 2360 */    MCD_OPC_Decode, 181, 4, 28, // Opcode: RLWNM
/* 2364 */    MCD_OPC_FilterValue, 1, 233, 16, // Skip to: 6697
/* 2368 */    MCD_OPC_Decode, 182, 4, 28, // Opcode: RLWNMo
/* 2372 */    MCD_OPC_FilterValue, 24, 14, 0, // Skip to: 2390
/* 2376 */    MCD_OPC_CheckField, 0, 26, 0, 4, 0, // Skip to: 2386
/* 2382 */    MCD_OPC_Decode, 138, 4, 23, // Opcode: NOP
/* 2386 */    MCD_OPC_Decode, 152, 4, 29, // Opcode: ORI
/* 2390 */    MCD_OPC_FilterValue, 25, 4, 0, // Skip to: 2398
/* 2394 */    MCD_OPC_Decode, 154, 4, 29, // Opcode: ORIS
/* 2398 */    MCD_OPC_FilterValue, 26, 4, 0, // Skip to: 2406
/* 2402 */    MCD_OPC_Decode, 232, 6, 29, // Opcode: XORI
/* 2406 */    MCD_OPC_FilterValue, 27, 4, 0, // Skip to: 2414
/* 2410 */    MCD_OPC_Decode, 234, 6, 29, // Opcode: XORIS
/* 2414 */    MCD_OPC_FilterValue, 28, 3, 0, // Skip to: 2421
/* 2418 */    MCD_OPC_Decode, 69, 29, // Opcode: ANDIo
/* 2421 */    MCD_OPC_FilterValue, 29, 3, 0, // Skip to: 2428
/* 2425 */    MCD_OPC_Decode, 67, 29, // Opcode: ANDISo
/* 2428 */    MCD_OPC_FilterValue, 30, 134, 0, // Skip to: 2566
/* 2432 */    MCD_OPC_ExtractField, 2, 3,  // Inst{4-2} ...
/* 2435 */    MCD_OPC_FilterValue, 0, 19, 0, // Skip to: 2458
/* 2439 */    MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 2442 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2450
/* 2446 */    MCD_OPC_Decode, 167, 4, 30, // Opcode: RLDICL
/* 2450 */    MCD_OPC_FilterValue, 1, 147, 16, // Skip to: 6697
/* 2454 */    MCD_OPC_Decode, 169, 4, 30, // Opcode: RLDICLo
/* 2458 */    MCD_OPC_FilterValue, 1, 19, 0, // Skip to: 2481
/* 2462 */    MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 2465 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2473
/* 2469 */    MCD_OPC_Decode, 170, 4, 30, // Opcode: RLDICR
/* 2473 */    MCD_OPC_FilterValue, 1, 124, 16, // Skip to: 6697
/* 2477 */    MCD_OPC_Decode, 171, 4, 30, // Opcode: RLDICRo
/* 2481 */    MCD_OPC_FilterValue, 2, 19, 0, // Skip to: 2504
/* 2485 */    MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 2488 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2496
/* 2492 */    MCD_OPC_Decode, 166, 4, 30, // Opcode: RLDIC
/* 2496 */    MCD_OPC_FilterValue, 1, 101, 16, // Skip to: 6697
/* 2500 */    MCD_OPC_Decode, 172, 4, 30, // Opcode: RLDICo
/* 2504 */    MCD_OPC_FilterValue, 3, 19, 0, // Skip to: 2527
/* 2508 */    MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 2511 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2519
/* 2515 */    MCD_OPC_Decode, 173, 4, 31, // Opcode: RLDIMI
/* 2519 */    MCD_OPC_FilterValue, 1, 78, 16, // Skip to: 6697
/* 2523 */    MCD_OPC_Decode, 174, 4, 31, // Opcode: RLDIMIo
/* 2527 */    MCD_OPC_FilterValue, 4, 70, 16, // Skip to: 6697
/* 2531 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 2534 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2542
/* 2538 */    MCD_OPC_Decode, 162, 4, 32, // Opcode: RLDCL
/* 2542 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 2550
/* 2546 */    MCD_OPC_Decode, 163, 4, 32, // Opcode: RLDCLo
/* 2550 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 2558
/* 2554 */    MCD_OPC_Decode, 164, 4, 32, // Opcode: RLDCR
/* 2558 */    MCD_OPC_FilterValue, 3, 39, 16, // Skip to: 6697
/* 2562 */    MCD_OPC_Decode, 165, 4, 32, // Opcode: RLDCRo
/* 2566 */    MCD_OPC_FilterValue, 31, 255, 9, // Skip to: 5129
/* 2570 */    MCD_OPC_ExtractField, 2, 4,  // Inst{5-2} ...
/* 2573 */    MCD_OPC_FilterValue, 0, 73, 0, // Skip to: 2650
/* 2577 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 2580 */    MCD_OPC_FilterValue, 0, 31, 0, // Skip to: 2615
/* 2584 */    MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 2587 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 2601
/* 2591 */    MCD_OPC_CheckField, 0, 2, 0, 4, 16, // Skip to: 6697
/* 2597 */    MCD_OPC_Decode, 186, 1, 33, // Opcode: CMPW
/* 2601 */    MCD_OPC_FilterValue, 1, 252, 15, // Skip to: 6697
/* 2605 */    MCD_OPC_CheckField, 0, 2, 0, 246, 15, // Skip to: 6697
/* 2611 */    MCD_OPC_Decode, 180, 1, 34, // Opcode: CMPD
/* 2615 */    MCD_OPC_FilterValue, 1, 238, 15, // Skip to: 6697
/* 2619 */    MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 2622 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 2636
/* 2626 */    MCD_OPC_CheckField, 0, 2, 0, 225, 15, // Skip to: 6697
/* 2632 */    MCD_OPC_Decode, 184, 1, 33, // Opcode: CMPLW
/* 2636 */    MCD_OPC_FilterValue, 1, 217, 15, // Skip to: 6697
/* 2640 */    MCD_OPC_CheckField, 0, 2, 0, 211, 15, // Skip to: 6697
/* 2646 */    MCD_OPC_Decode, 182, 1, 34, // Opcode: CMPLD
/* 2650 */    MCD_OPC_FilterValue, 2, 44, 0, // Skip to: 2698
/* 2654 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 2657 */    MCD_OPC_FilterValue, 0, 23, 0, // Skip to: 2684
/* 2661 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 2664 */    MCD_OPC_FilterValue, 0, 189, 15, // Skip to: 6697
/* 2668 */    MCD_OPC_CheckField, 11, 15, 128, 248, 1, 4, 0, // Skip to: 2680
/* 2676 */    MCD_OPC_Decode, 187, 5, 23, // Opcode: TRAP
/* 2680 */    MCD_OPC_Decode, 188, 5, 35, // Opcode: TW
/* 2684 */    MCD_OPC_FilterValue, 2, 169, 15, // Skip to: 6697
/* 2688 */    MCD_OPC_CheckField, 0, 2, 0, 163, 15, // Skip to: 6697
/* 2694 */    MCD_OPC_Decode, 182, 5, 36, // Opcode: TD
/* 2698 */    MCD_OPC_FilterValue, 3, 161, 0, // Skip to: 2863
/* 2702 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 2705 */    MCD_OPC_FilterValue, 0, 19, 0, // Skip to: 2728
/* 2709 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 2712 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2720
/* 2716 */    MCD_OPC_Decode, 186, 3, 37, // Opcode: LVSL
/* 2720 */    MCD_OPC_FilterValue, 2, 133, 15, // Skip to: 6697
/* 2724 */    MCD_OPC_Decode, 183, 3, 37, // Opcode: LVEBX
/* 2728 */    MCD_OPC_FilterValue, 1, 19, 0, // Skip to: 2751
/* 2732 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 2735 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2743
/* 2739 */    MCD_OPC_Decode, 187, 3, 37, // Opcode: LVSR
/* 2743 */    MCD_OPC_FilterValue, 2, 110, 15, // Skip to: 6697
/* 2747 */    MCD_OPC_Decode, 184, 3, 37, // Opcode: LVEHX
/* 2751 */    MCD_OPC_FilterValue, 2, 10, 0, // Skip to: 2765
/* 2755 */    MCD_OPC_CheckField, 0, 2, 2, 96, 15, // Skip to: 6697
/* 2761 */    MCD_OPC_Decode, 185, 3, 37, // Opcode: LVEWX
/* 2765 */    MCD_OPC_FilterValue, 3, 10, 0, // Skip to: 2779
/* 2769 */    MCD_OPC_CheckField, 0, 2, 2, 82, 15, // Skip to: 6697
/* 2775 */    MCD_OPC_Decode, 188, 3, 37, // Opcode: LVX
/* 2779 */    MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 2793
/* 2783 */    MCD_OPC_CheckField, 0, 2, 2, 68, 15, // Skip to: 6697
/* 2789 */    MCD_OPC_Decode, 128, 5, 37, // Opcode: STVEBX
/* 2793 */    MCD_OPC_FilterValue, 5, 10, 0, // Skip to: 2807
/* 2797 */    MCD_OPC_CheckField, 0, 2, 2, 54, 15, // Skip to: 6697
/* 2803 */    MCD_OPC_Decode, 129, 5, 37, // Opcode: STVEHX
/* 2807 */    MCD_OPC_FilterValue, 6, 10, 0, // Skip to: 2821
/* 2811 */    MCD_OPC_CheckField, 0, 2, 2, 40, 15, // Skip to: 6697
/* 2817 */    MCD_OPC_Decode, 130, 5, 37, // Opcode: STVEWX
/* 2821 */    MCD_OPC_FilterValue, 7, 10, 0, // Skip to: 2835
/* 2825 */    MCD_OPC_CheckField, 0, 2, 2, 26, 15, // Skip to: 6697
/* 2831 */    MCD_OPC_Decode, 131, 5, 37, // Opcode: STVX
/* 2835 */    MCD_OPC_FilterValue, 11, 10, 0, // Skip to: 2849
/* 2839 */    MCD_OPC_CheckField, 0, 2, 2, 12, 15, // Skip to: 6697
/* 2845 */    MCD_OPC_Decode, 189, 3, 37, // Opcode: LVXL
/* 2849 */    MCD_OPC_FilterValue, 15, 4, 15, // Skip to: 6697
/* 2853 */    MCD_OPC_CheckField, 0, 2, 2, 254, 14, // Skip to: 6697
/* 2859 */    MCD_OPC_Decode, 132, 5, 37, // Opcode: STVXL
/* 2863 */    MCD_OPC_FilterValue, 4, 22, 1, // Skip to: 3145
/* 2867 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 2870 */    MCD_OPC_FilterValue, 0, 35, 0, // Skip to: 2909
/* 2874 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 2877 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2885
/* 2881 */    MCD_OPC_Decode, 146, 5, 38, // Opcode: SUBFC
/* 2885 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 2893
/* 2889 */    MCD_OPC_Decode, 149, 5, 38, // Opcode: SUBFCo
/* 2893 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 2901
/* 2897 */    MCD_OPC_Decode, 243, 3, 39, // Opcode: MULHDU
/* 2901 */    MCD_OPC_FilterValue, 3, 208, 14, // Skip to: 6697
/* 2905 */    MCD_OPC_Decode, 244, 3, 39, // Opcode: MULHDUo
/* 2909 */    MCD_OPC_FilterValue, 1, 19, 0, // Skip to: 2932
/* 2913 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 2916 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2924
/* 2920 */    MCD_OPC_Decode, 143, 5, 38, // Opcode: SUBF
/* 2924 */    MCD_OPC_FilterValue, 1, 185, 14, // Skip to: 6697
/* 2928 */    MCD_OPC_Decode, 164, 5, 38, // Opcode: SUBFo
/* 2932 */    MCD_OPC_FilterValue, 2, 19, 0, // Skip to: 2955
/* 2936 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 2939 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 2947
/* 2943 */    MCD_OPC_Decode, 242, 3, 39, // Opcode: MULHD
/* 2947 */    MCD_OPC_FilterValue, 3, 162, 14, // Skip to: 6697
/* 2951 */    MCD_OPC_Decode, 245, 3, 39, // Opcode: MULHDo
/* 2955 */    MCD_OPC_FilterValue, 3, 31, 0, // Skip to: 2990
/* 2959 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 2962 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 2976
/* 2966 */    MCD_OPC_CheckField, 11, 5, 0, 141, 14, // Skip to: 6697
/* 2972 */    MCD_OPC_Decode, 134, 4, 40, // Opcode: NEG
/* 2976 */    MCD_OPC_FilterValue, 1, 133, 14, // Skip to: 6697
/* 2980 */    MCD_OPC_CheckField, 11, 5, 0, 127, 14, // Skip to: 6697
/* 2986 */    MCD_OPC_Decode, 137, 4, 40, // Opcode: NEGo
/* 2990 */    MCD_OPC_FilterValue, 4, 19, 0, // Skip to: 3013
/* 2994 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 2997 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 3005
/* 3001 */    MCD_OPC_Decode, 150, 5, 38, // Opcode: SUBFE
/* 3005 */    MCD_OPC_FilterValue, 1, 104, 14, // Skip to: 6697
/* 3009 */    MCD_OPC_Decode, 153, 5, 38, // Opcode: SUBFEo
/* 3013 */    MCD_OPC_FilterValue, 6, 31, 0, // Skip to: 3048
/* 3017 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3020 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 3034
/* 3024 */    MCD_OPC_CheckField, 11, 5, 0, 83, 14, // Skip to: 6697
/* 3030 */    MCD_OPC_Decode, 160, 5, 40, // Opcode: SUBFZE
/* 3034 */    MCD_OPC_FilterValue, 1, 75, 14, // Skip to: 6697
/* 3038 */    MCD_OPC_CheckField, 11, 5, 0, 69, 14, // Skip to: 6697
/* 3044 */    MCD_OPC_Decode, 163, 5, 40, // Opcode: SUBFZEo
/* 3048 */    MCD_OPC_FilterValue, 7, 47, 0, // Skip to: 3099
/* 3052 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3055 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 3069
/* 3059 */    MCD_OPC_CheckField, 11, 5, 0, 48, 14, // Skip to: 6697
/* 3065 */    MCD_OPC_Decode, 156, 5, 40, // Opcode: SUBFME
/* 3069 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 3083
/* 3073 */    MCD_OPC_CheckField, 11, 5, 0, 34, 14, // Skip to: 6697
/* 3079 */    MCD_OPC_Decode, 159, 5, 40, // Opcode: SUBFMEo
/* 3083 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 3091
/* 3087 */    MCD_OPC_Decode, 250, 3, 39, // Opcode: MULLD
/* 3091 */    MCD_OPC_FilterValue, 3, 18, 14, // Skip to: 6697
/* 3095 */    MCD_OPC_Decode, 251, 3, 39, // Opcode: MULLDo
/* 3099 */    MCD_OPC_FilterValue, 14, 19, 0, // Skip to: 3122
/* 3103 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3106 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 3114
/* 3110 */    MCD_OPC_Decode, 213, 1, 39, // Opcode: DIVDU
/* 3114 */    MCD_OPC_FilterValue, 3, 251, 13, // Skip to: 6697
/* 3118 */    MCD_OPC_Decode, 214, 1, 39, // Opcode: DIVDUo
/* 3122 */    MCD_OPC_FilterValue, 15, 243, 13, // Skip to: 6697
/* 3126 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3129 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 3137
/* 3133 */    MCD_OPC_Decode, 212, 1, 39, // Opcode: DIVD
/* 3137 */    MCD_OPC_FilterValue, 3, 228, 13, // Skip to: 6697
/* 3141 */    MCD_OPC_Decode, 215, 1, 39, // Opcode: DIVDo
/* 3145 */    MCD_OPC_FilterValue, 5, 233, 0, // Skip to: 3382
/* 3149 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 3152 */    MCD_OPC_FilterValue, 0, 33, 0, // Skip to: 3189
/* 3156 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3159 */    MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 3166
/* 3163 */    MCD_OPC_Decode, 26, 38, // Opcode: ADDC
/* 3166 */    MCD_OPC_FilterValue, 1, 3, 0, // Skip to: 3173
/* 3170 */    MCD_OPC_Decode, 29, 38, // Opcode: ADDCo
/* 3173 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 3181
/* 3177 */    MCD_OPC_Decode, 247, 3, 38, // Opcode: MULHWU
/* 3181 */    MCD_OPC_FilterValue, 3, 184, 13, // Skip to: 6697
/* 3185 */    MCD_OPC_Decode, 248, 3, 38, // Opcode: MULHWUo
/* 3189 */    MCD_OPC_FilterValue, 2, 19, 0, // Skip to: 3212
/* 3193 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3196 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 3204
/* 3200 */    MCD_OPC_Decode, 246, 3, 38, // Opcode: MULHW
/* 3204 */    MCD_OPC_FilterValue, 3, 161, 13, // Skip to: 6697
/* 3208 */    MCD_OPC_Decode, 249, 3, 38, // Opcode: MULHWo
/* 3212 */    MCD_OPC_FilterValue, 4, 17, 0, // Skip to: 3233
/* 3216 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3219 */    MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 3226
/* 3223 */    MCD_OPC_Decode, 30, 38, // Opcode: ADDE
/* 3226 */    MCD_OPC_FilterValue, 1, 139, 13, // Skip to: 6697
/* 3230 */    MCD_OPC_Decode, 33, 38, // Opcode: ADDEo
/* 3233 */    MCD_OPC_FilterValue, 6, 29, 0, // Skip to: 3266
/* 3237 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3240 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 3253
/* 3244 */    MCD_OPC_CheckField, 11, 5, 0, 119, 13, // Skip to: 6697
/* 3250 */    MCD_OPC_Decode, 54, 40, // Opcode: ADDZE
/* 3253 */    MCD_OPC_FilterValue, 1, 112, 13, // Skip to: 6697
/* 3257 */    MCD_OPC_CheckField, 11, 5, 0, 106, 13, // Skip to: 6697
/* 3263 */    MCD_OPC_Decode, 57, 40, // Opcode: ADDZEo
/* 3266 */    MCD_OPC_FilterValue, 7, 45, 0, // Skip to: 3315
/* 3270 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3273 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 3286
/* 3277 */    MCD_OPC_CheckField, 11, 5, 0, 86, 13, // Skip to: 6697
/* 3283 */    MCD_OPC_Decode, 50, 40, // Opcode: ADDME
/* 3286 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 3299
/* 3290 */    MCD_OPC_CheckField, 11, 5, 0, 73, 13, // Skip to: 6697
/* 3296 */    MCD_OPC_Decode, 53, 40, // Opcode: ADDMEo
/* 3299 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 3307
/* 3303 */    MCD_OPC_Decode, 254, 3, 38, // Opcode: MULLW
/* 3307 */    MCD_OPC_FilterValue, 3, 58, 13, // Skip to: 6697
/* 3311 */    MCD_OPC_Decode, 255, 3, 38, // Opcode: MULLWo
/* 3315 */    MCD_OPC_FilterValue, 8, 17, 0, // Skip to: 3336
/* 3319 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3322 */    MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 3329
/* 3326 */    MCD_OPC_Decode, 19, 38, // Opcode: ADD4
/* 3329 */    MCD_OPC_FilterValue, 1, 36, 13, // Skip to: 6697
/* 3333 */    MCD_OPC_Decode, 21, 38, // Opcode: ADD4o
/* 3336 */    MCD_OPC_FilterValue, 14, 19, 0, // Skip to: 3359
/* 3340 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3343 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 3351
/* 3347 */    MCD_OPC_Decode, 217, 1, 38, // Opcode: DIVWU
/* 3351 */    MCD_OPC_FilterValue, 3, 14, 13, // Skip to: 6697
/* 3355 */    MCD_OPC_Decode, 218, 1, 38, // Opcode: DIVWUo
/* 3359 */    MCD_OPC_FilterValue, 15, 6, 13, // Skip to: 6697
/* 3363 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3366 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 3374
/* 3370 */    MCD_OPC_Decode, 216, 1, 38, // Opcode: DIVW
/* 3374 */    MCD_OPC_FilterValue, 3, 247, 12, // Skip to: 6697
/* 3378 */    MCD_OPC_Decode, 219, 1, 38, // Opcode: DIVWo
/* 3382 */    MCD_OPC_FilterValue, 7, 10, 0, // Skip to: 3396
/* 3386 */    MCD_OPC_CheckField, 0, 2, 2, 233, 12, // Skip to: 6697
/* 3392 */    MCD_OPC_Decode, 252, 2, 41, // Opcode: ISEL
/* 3396 */    MCD_OPC_FilterValue, 8, 43, 0, // Skip to: 3443
/* 3400 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 3403 */    MCD_OPC_FilterValue, 0, 16, 0, // Skip to: 3423
/* 3407 */    MCD_OPC_CheckField, 6, 6, 4, 212, 12, // Skip to: 6697
/* 3413 */    MCD_OPC_CheckField, 0, 2, 0, 206, 12, // Skip to: 6697
/* 3419 */    MCD_OPC_Decode, 223, 3, 42, // Opcode: MTCRF
/* 3423 */    MCD_OPC_FilterValue, 1, 198, 12, // Skip to: 6697
/* 3427 */    MCD_OPC_CheckField, 6, 6, 4, 192, 12, // Skip to: 6697
/* 3433 */    MCD_OPC_CheckField, 0, 2, 0, 186, 12, // Skip to: 6697
/* 3439 */    MCD_OPC_Decode, 236, 3, 43, // Opcode: MTOCRF
/* 3443 */    MCD_OPC_FilterValue, 9, 48, 1, // Skip to: 3751
/* 3447 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 3450 */    MCD_OPC_FilterValue, 0, 43, 0, // Skip to: 3497
/* 3454 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 3457 */    MCD_OPC_FilterValue, 0, 16, 0, // Skip to: 3477
/* 3461 */    MCD_OPC_CheckField, 11, 9, 0, 158, 12, // Skip to: 6697
/* 3467 */    MCD_OPC_CheckField, 0, 2, 2, 152, 12, // Skip to: 6697
/* 3473 */    MCD_OPC_Decode, 206, 3, 44, // Opcode: MFCR
/* 3477 */    MCD_OPC_FilterValue, 1, 144, 12, // Skip to: 6697
/* 3481 */    MCD_OPC_CheckField, 11, 1, 0, 138, 12, // Skip to: 6697
/* 3487 */    MCD_OPC_CheckField, 0, 2, 2, 132, 12, // Skip to: 6697
/* 3493 */    MCD_OPC_Decode, 214, 3, 45, // Opcode: MFOCRF
/* 3497 */    MCD_OPC_FilterValue, 2, 16, 0, // Skip to: 3517
/* 3501 */    MCD_OPC_CheckField, 11, 10, 0, 118, 12, // Skip to: 6697
/* 3507 */    MCD_OPC_CheckField, 0, 2, 2, 112, 12, // Skip to: 6697
/* 3513 */    MCD_OPC_Decode, 213, 3, 44, // Opcode: MFMSR
/* 3517 */    MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 3531
/* 3521 */    MCD_OPC_CheckField, 1, 1, 0, 98, 12, // Skip to: 6697
/* 3527 */    MCD_OPC_Decode, 234, 3, 46, // Opcode: MTMSR
/* 3531 */    MCD_OPC_FilterValue, 5, 10, 0, // Skip to: 3545
/* 3535 */    MCD_OPC_CheckField, 1, 1, 0, 84, 12, // Skip to: 6697
/* 3541 */    MCD_OPC_Decode, 235, 3, 46, // Opcode: MTMSRD
/* 3545 */    MCD_OPC_FilterValue, 8, 16, 0, // Skip to: 3565
/* 3549 */    MCD_OPC_CheckField, 16, 10, 0, 70, 12, // Skip to: 6697
/* 3555 */    MCD_OPC_CheckField, 0, 2, 0, 64, 12, // Skip to: 6697
/* 3561 */    MCD_OPC_Decode, 185, 5, 47, // Opcode: TLBIEL
/* 3565 */    MCD_OPC_FilterValue, 9, 16, 0, // Skip to: 3585
/* 3569 */    MCD_OPC_CheckField, 16, 5, 0, 50, 12, // Skip to: 6697
/* 3575 */    MCD_OPC_CheckField, 0, 2, 0, 44, 12, // Skip to: 6697
/* 3581 */    MCD_OPC_Decode, 184, 5, 48, // Opcode: TLBIE
/* 3585 */    MCD_OPC_FilterValue, 10, 32, 0, // Skip to: 3621
/* 3589 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3592 */    MCD_OPC_FilterValue, 2, 29, 12, // Skip to: 6697
/* 3596 */    MCD_OPC_ExtractField, 11, 10,  // Inst{20-11} ...
/* 3599 */    MCD_OPC_FilterValue, 128, 2, 4, 0, // Skip to: 3608
/* 3604 */    MCD_OPC_Decode, 211, 3, 44, // Opcode: MFLR
/* 3608 */    MCD_OPC_FilterValue, 160, 2, 4, 0, // Skip to: 3617
/* 3613 */    MCD_OPC_Decode, 208, 3, 44, // Opcode: MFCTR
/* 3617 */    MCD_OPC_Decode, 216, 3, 49, // Opcode: MFSPR
/* 3621 */    MCD_OPC_FilterValue, 11, 10, 0, // Skip to: 3635
/* 3625 */    MCD_OPC_CheckField, 0, 2, 2, 250, 11, // Skip to: 6697
/* 3631 */    MCD_OPC_Decode, 217, 3, 49, // Opcode: MFTB
/* 3635 */    MCD_OPC_FilterValue, 12, 16, 0, // Skip to: 3655
/* 3639 */    MCD_OPC_CheckField, 16, 5, 0, 236, 11, // Skip to: 6697
/* 3645 */    MCD_OPC_CheckField, 0, 2, 0, 230, 11, // Skip to: 6697
/* 3651 */    MCD_OPC_Decode, 196, 4, 48, // Opcode: SLBMTE
/* 3655 */    MCD_OPC_FilterValue, 13, 16, 0, // Skip to: 3675
/* 3659 */    MCD_OPC_CheckField, 16, 10, 0, 216, 11, // Skip to: 6697
/* 3665 */    MCD_OPC_CheckField, 0, 2, 0, 210, 11, // Skip to: 6697
/* 3671 */    MCD_OPC_Decode, 194, 4, 47, // Opcode: SLBIE
/* 3675 */    MCD_OPC_FilterValue, 14, 32, 0, // Skip to: 3711
/* 3679 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3682 */    MCD_OPC_FilterValue, 2, 195, 11, // Skip to: 6697
/* 3686 */    MCD_OPC_ExtractField, 11, 10,  // Inst{20-11} ...
/* 3689 */    MCD_OPC_FilterValue, 128, 2, 4, 0, // Skip to: 3698
/* 3694 */    MCD_OPC_Decode, 232, 3, 44, // Opcode: MTLR
/* 3698 */    MCD_OPC_FilterValue, 160, 2, 4, 0, // Skip to: 3707
/* 3703 */    MCD_OPC_Decode, 225, 3, 44, // Opcode: MTCTR
/* 3707 */    MCD_OPC_Decode, 238, 3, 50, // Opcode: MTSPR
/* 3711 */    MCD_OPC_FilterValue, 15, 16, 0, // Skip to: 3731
/* 3715 */    MCD_OPC_CheckField, 11, 15, 0, 160, 11, // Skip to: 6697
/* 3721 */    MCD_OPC_CheckField, 0, 2, 0, 154, 11, // Skip to: 6697
/* 3727 */    MCD_OPC_Decode, 193, 4, 23, // Opcode: SLBIA
/* 3731 */    MCD_OPC_FilterValue, 28, 146, 11, // Skip to: 6697
/* 3735 */    MCD_OPC_CheckField, 16, 5, 0, 140, 11, // Skip to: 6697
/* 3741 */    MCD_OPC_CheckField, 0, 2, 2, 134, 11, // Skip to: 6697
/* 3747 */    MCD_OPC_Decode, 195, 4, 48, // Opcode: SLBMFEE
/* 3751 */    MCD_OPC_FilterValue, 10, 138, 0, // Skip to: 3893
/* 3755 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 3758 */    MCD_OPC_FilterValue, 0, 19, 0, // Skip to: 3781
/* 3762 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3765 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 3773
/* 3769 */    MCD_OPC_Decode, 191, 3, 51, // Opcode: LWARX
/* 3773 */    MCD_OPC_FilterValue, 2, 104, 11, // Skip to: 6697
/* 3777 */    MCD_OPC_Decode, 142, 3, 52, // Opcode: LDX
/* 3781 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 3795
/* 3785 */    MCD_OPC_CheckField, 0, 2, 2, 90, 11, // Skip to: 6697
/* 3791 */    MCD_OPC_Decode, 141, 3, 53, // Opcode: LDUX
/* 3795 */    MCD_OPC_FilterValue, 2, 10, 0, // Skip to: 3809
/* 3799 */    MCD_OPC_CheckField, 0, 2, 0, 76, 11, // Skip to: 6697
/* 3805 */    MCD_OPC_Decode, 138, 3, 52, // Opcode: LDARX
/* 3809 */    MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 3823
/* 3813 */    MCD_OPC_CheckField, 0, 2, 2, 62, 11, // Skip to: 6697
/* 3819 */    MCD_OPC_Decode, 236, 4, 52, // Opcode: STDX
/* 3823 */    MCD_OPC_FilterValue, 5, 10, 0, // Skip to: 3837
/* 3827 */    MCD_OPC_CheckField, 0, 2, 2, 48, 11, // Skip to: 6697
/* 3833 */    MCD_OPC_Decode, 235, 4, 54, // Opcode: STDUX
/* 3837 */    MCD_OPC_FilterValue, 10, 10, 0, // Skip to: 3851
/* 3841 */    MCD_OPC_CheckField, 0, 2, 2, 34, 11, // Skip to: 6697
/* 3847 */    MCD_OPC_Decode, 193, 3, 52, // Opcode: LWAX
/* 3851 */    MCD_OPC_FilterValue, 11, 10, 0, // Skip to: 3865
/* 3855 */    MCD_OPC_CheckField, 0, 2, 2, 20, 11, // Skip to: 6697
/* 3861 */    MCD_OPC_Decode, 192, 3, 53, // Opcode: LWAUX
/* 3865 */    MCD_OPC_FilterValue, 16, 10, 0, // Skip to: 3879
/* 3869 */    MCD_OPC_CheckField, 0, 2, 0, 6, 11, // Skip to: 6697
/* 3875 */    MCD_OPC_Decode, 139, 3, 52, // Opcode: LDBRX
/* 3879 */    MCD_OPC_FilterValue, 20, 254, 10, // Skip to: 6697
/* 3883 */    MCD_OPC_CheckField, 0, 2, 0, 248, 10, // Skip to: 6697
/* 3889 */    MCD_OPC_Decode, 232, 4, 52, // Opcode: STDBRX
/* 3893 */    MCD_OPC_FilterValue, 11, 101, 2, // Skip to: 4510
/* 3897 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 3900 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 3914
/* 3904 */    MCD_OPC_CheckField, 0, 2, 2, 227, 10, // Skip to: 6697
/* 3910 */    MCD_OPC_Decode, 203, 3, 51, // Opcode: LWZX
/* 3914 */    MCD_OPC_FilterValue, 1, 25, 0, // Skip to: 3943
/* 3918 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3921 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 3935
/* 3925 */    MCD_OPC_CheckField, 21, 5, 0, 206, 10, // Skip to: 6697
/* 3931 */    MCD_OPC_Decode, 207, 1, 55, // Opcode: DCBST
/* 3935 */    MCD_OPC_FilterValue, 2, 198, 10, // Skip to: 6697
/* 3939 */    MCD_OPC_Decode, 201, 3, 56, // Opcode: LWZUX
/* 3943 */    MCD_OPC_FilterValue, 2, 25, 0, // Skip to: 3972
/* 3947 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3950 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 3964
/* 3954 */    MCD_OPC_CheckField, 21, 5, 0, 177, 10, // Skip to: 6697
/* 3960 */    MCD_OPC_Decode, 205, 1, 55, // Opcode: DCBF
/* 3964 */    MCD_OPC_FilterValue, 2, 169, 10, // Skip to: 6697
/* 3968 */    MCD_OPC_Decode, 135, 3, 51, // Opcode: LBZX
/* 3972 */    MCD_OPC_FilterValue, 3, 10, 0, // Skip to: 3986
/* 3976 */    MCD_OPC_CheckField, 0, 2, 2, 155, 10, // Skip to: 6697
/* 3982 */    MCD_OPC_Decode, 133, 3, 56, // Opcode: LBZUX
/* 3986 */    MCD_OPC_FilterValue, 4, 19, 0, // Skip to: 4009
/* 3990 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3993 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 4001
/* 3997 */    MCD_OPC_Decode, 136, 5, 51, // Opcode: STWCX
/* 4001 */    MCD_OPC_FilterValue, 2, 132, 10, // Skip to: 6697
/* 4005 */    MCD_OPC_Decode, 141, 5, 51, // Opcode: STWX
/* 4009 */    MCD_OPC_FilterValue, 5, 10, 0, // Skip to: 4023
/* 4013 */    MCD_OPC_CheckField, 0, 2, 2, 118, 10, // Skip to: 6697
/* 4019 */    MCD_OPC_Decode, 139, 5, 57, // Opcode: STWUX
/* 4023 */    MCD_OPC_FilterValue, 6, 19, 0, // Skip to: 4046
/* 4027 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4030 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 4038
/* 4034 */    MCD_OPC_Decode, 233, 4, 52, // Opcode: STDCX
/* 4038 */    MCD_OPC_FilterValue, 2, 95, 10, // Skip to: 6697
/* 4042 */    MCD_OPC_Decode, 229, 4, 51, // Opcode: STBX
/* 4046 */    MCD_OPC_FilterValue, 7, 25, 0, // Skip to: 4075
/* 4050 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4053 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4067
/* 4057 */    MCD_OPC_CheckField, 21, 5, 0, 74, 10, // Skip to: 6697
/* 4063 */    MCD_OPC_Decode, 209, 1, 55, // Opcode: DCBTST
/* 4067 */    MCD_OPC_FilterValue, 2, 66, 10, // Skip to: 6697
/* 4071 */    MCD_OPC_Decode, 227, 4, 57, // Opcode: STBUX
/* 4075 */    MCD_OPC_FilterValue, 8, 25, 0, // Skip to: 4104
/* 4079 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4082 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4096
/* 4086 */    MCD_OPC_CheckField, 21, 5, 0, 45, 10, // Skip to: 6697
/* 4092 */    MCD_OPC_Decode, 208, 1, 55, // Opcode: DCBT
/* 4096 */    MCD_OPC_FilterValue, 2, 37, 10, // Skip to: 6697
/* 4100 */    MCD_OPC_Decode, 176, 3, 51, // Opcode: LHZX
/* 4104 */    MCD_OPC_FilterValue, 9, 10, 0, // Skip to: 4118
/* 4108 */    MCD_OPC_CheckField, 0, 2, 2, 23, 10, // Skip to: 6697
/* 4114 */    MCD_OPC_Decode, 174, 3, 56, // Opcode: LHZUX
/* 4118 */    MCD_OPC_FilterValue, 10, 10, 0, // Skip to: 4132
/* 4122 */    MCD_OPC_CheckField, 0, 2, 2, 9, 10, // Skip to: 6697
/* 4128 */    MCD_OPC_Decode, 167, 3, 51, // Opcode: LHAX
/* 4132 */    MCD_OPC_FilterValue, 11, 10, 0, // Skip to: 4146
/* 4136 */    MCD_OPC_CheckField, 0, 2, 2, 251, 9, // Skip to: 6697
/* 4142 */    MCD_OPC_Decode, 165, 3, 56, // Opcode: LHAUX
/* 4146 */    MCD_OPC_FilterValue, 12, 10, 0, // Skip to: 4160
/* 4150 */    MCD_OPC_CheckField, 0, 2, 2, 237, 9, // Skip to: 6697
/* 4156 */    MCD_OPC_Decode, 253, 4, 51, // Opcode: STHX
/* 4160 */    MCD_OPC_FilterValue, 13, 10, 0, // Skip to: 4174
/* 4164 */    MCD_OPC_CheckField, 0, 2, 2, 223, 9, // Skip to: 6697
/* 4170 */    MCD_OPC_Decode, 251, 4, 57, // Opcode: STHUX
/* 4174 */    MCD_OPC_FilterValue, 14, 16, 0, // Skip to: 4194
/* 4178 */    MCD_OPC_CheckField, 21, 5, 0, 209, 9, // Skip to: 6697
/* 4184 */    MCD_OPC_CheckField, 0, 2, 0, 203, 9, // Skip to: 6697
/* 4190 */    MCD_OPC_Decode, 206, 1, 55, // Opcode: DCBI
/* 4194 */    MCD_OPC_FilterValue, 16, 19, 0, // Skip to: 4217
/* 4198 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4201 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 4209
/* 4205 */    MCD_OPC_Decode, 196, 3, 51, // Opcode: LWBRX
/* 4209 */    MCD_OPC_FilterValue, 2, 180, 9, // Skip to: 6697
/* 4213 */    MCD_OPC_Decode, 160, 3, 58, // Opcode: LFSX
/* 4217 */    MCD_OPC_FilterValue, 17, 25, 0, // Skip to: 4246
/* 4221 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4224 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4238
/* 4228 */    MCD_OPC_CheckField, 11, 15, 0, 159, 9, // Skip to: 6697
/* 4234 */    MCD_OPC_Decode, 186, 5, 23, // Opcode: TLBSYNC
/* 4238 */    MCD_OPC_FilterValue, 2, 151, 9, // Skip to: 6697
/* 4242 */    MCD_OPC_Decode, 159, 3, 59, // Opcode: LFSUX
/* 4246 */    MCD_OPC_FilterValue, 18, 31, 0, // Skip to: 4281
/* 4250 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4253 */    MCD_OPC_FilterValue, 0, 16, 0, // Skip to: 4273
/* 4257 */    MCD_OPC_CheckField, 23, 3, 0, 130, 9, // Skip to: 6697
/* 4263 */    MCD_OPC_CheckField, 11, 10, 0, 124, 9, // Skip to: 6697
/* 4269 */    MCD_OPC_Decode, 169, 5, 60, // Opcode: SYNC
/* 4273 */    MCD_OPC_FilterValue, 2, 116, 9, // Skip to: 6697
/* 4277 */    MCD_OPC_Decode, 154, 3, 61, // Opcode: LFDX
/* 4281 */    MCD_OPC_FilterValue, 19, 10, 0, // Skip to: 4295
/* 4285 */    MCD_OPC_CheckField, 0, 2, 2, 102, 9, // Skip to: 6697
/* 4291 */    MCD_OPC_Decode, 153, 3, 62, // Opcode: LFDUX
/* 4295 */    MCD_OPC_FilterValue, 20, 19, 0, // Skip to: 4318
/* 4299 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4302 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 4310
/* 4306 */    MCD_OPC_Decode, 135, 5, 51, // Opcode: STWBRX
/* 4310 */    MCD_OPC_FilterValue, 2, 79, 9, // Skip to: 6697
/* 4314 */    MCD_OPC_Decode, 245, 4, 58, // Opcode: STFSX
/* 4318 */    MCD_OPC_FilterValue, 21, 10, 0, // Skip to: 4332
/* 4322 */    MCD_OPC_CheckField, 0, 2, 2, 65, 9, // Skip to: 6697
/* 4328 */    MCD_OPC_Decode, 244, 4, 63, // Opcode: STFSUX
/* 4332 */    MCD_OPC_FilterValue, 22, 10, 0, // Skip to: 4346
/* 4336 */    MCD_OPC_CheckField, 0, 2, 2, 51, 9, // Skip to: 6697
/* 4342 */    MCD_OPC_Decode, 240, 4, 61, // Opcode: STFDX
/* 4346 */    MCD_OPC_FilterValue, 23, 25, 0, // Skip to: 4375
/* 4350 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4353 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4367
/* 4357 */    MCD_OPC_CheckField, 21, 5, 0, 30, 9, // Skip to: 6697
/* 4363 */    MCD_OPC_Decode, 204, 1, 55, // Opcode: DCBA
/* 4367 */    MCD_OPC_FilterValue, 2, 22, 9, // Skip to: 6697
/* 4371 */    MCD_OPC_Decode, 239, 4, 64, // Opcode: STFDUX
/* 4375 */    MCD_OPC_FilterValue, 24, 10, 0, // Skip to: 4389
/* 4379 */    MCD_OPC_CheckField, 0, 2, 0, 8, 9, // Skip to: 6697
/* 4385 */    MCD_OPC_Decode, 169, 3, 51, // Opcode: LHBRX
/* 4389 */    MCD_OPC_FilterValue, 26, 25, 0, // Skip to: 4418
/* 4393 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4396 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4410
/* 4400 */    MCD_OPC_CheckField, 11, 15, 0, 243, 8, // Skip to: 6697
/* 4406 */    MCD_OPC_Decode, 237, 1, 23, // Opcode: EIEIO
/* 4410 */    MCD_OPC_FilterValue, 2, 235, 8, // Skip to: 6697
/* 4414 */    MCD_OPC_Decode, 155, 3, 61, // Opcode: LFIWAX
/* 4418 */    MCD_OPC_FilterValue, 27, 10, 0, // Skip to: 4432
/* 4422 */    MCD_OPC_CheckField, 0, 2, 2, 221, 8, // Skip to: 6697
/* 4428 */    MCD_OPC_Decode, 156, 3, 61, // Opcode: LFIWZX
/* 4432 */    MCD_OPC_FilterValue, 28, 10, 0, // Skip to: 4446
/* 4436 */    MCD_OPC_CheckField, 0, 2, 0, 207, 8, // Skip to: 6697
/* 4442 */    MCD_OPC_Decode, 248, 4, 51, // Opcode: STHBRX
/* 4446 */    MCD_OPC_FilterValue, 30, 25, 0, // Skip to: 4475
/* 4450 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4453 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4467
/* 4457 */    MCD_OPC_CheckField, 21, 5, 0, 186, 8, // Skip to: 6697
/* 4463 */    MCD_OPC_Decode, 245, 2, 55, // Opcode: ICBI
/* 4467 */    MCD_OPC_FilterValue, 2, 178, 8, // Skip to: 6697
/* 4471 */    MCD_OPC_Decode, 241, 4, 61, // Opcode: STFIWX
/* 4475 */    MCD_OPC_FilterValue, 31, 170, 8, // Skip to: 6697
/* 4479 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 4482 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4496
/* 4486 */    MCD_OPC_CheckField, 0, 2, 0, 157, 8, // Skip to: 6697
/* 4492 */    MCD_OPC_Decode, 210, 1, 55, // Opcode: DCBZ
/* 4496 */    MCD_OPC_FilterValue, 1, 149, 8, // Skip to: 6697
/* 4500 */    MCD_OPC_CheckField, 0, 2, 0, 143, 8, // Skip to: 6697
/* 4506 */    MCD_OPC_Decode, 211, 1, 55, // Opcode: DCBZL
/* 4510 */    MCD_OPC_FilterValue, 12, 95, 0, // Skip to: 4609
/* 4514 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 4517 */    MCD_OPC_FilterValue, 0, 19, 0, // Skip to: 4540
/* 4521 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4524 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 4532
/* 4528 */    MCD_OPC_Decode, 201, 4, 65, // Opcode: SLW
/* 4532 */    MCD_OPC_FilterValue, 1, 113, 8, // Skip to: 6697
/* 4536 */    MCD_OPC_Decode, 204, 4, 65, // Opcode: SLWo
/* 4540 */    MCD_OPC_FilterValue, 16, 19, 0, // Skip to: 4563
/* 4544 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4547 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 4555
/* 4551 */    MCD_OPC_Decode, 219, 4, 65, // Opcode: SRW
/* 4555 */    MCD_OPC_FilterValue, 1, 90, 8, // Skip to: 6697
/* 4559 */    MCD_OPC_Decode, 222, 4, 65, // Opcode: SRWo
/* 4563 */    MCD_OPC_FilterValue, 24, 19, 0, // Skip to: 4586
/* 4567 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4570 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 4578
/* 4574 */    MCD_OPC_Decode, 211, 4, 65, // Opcode: SRAW
/* 4578 */    MCD_OPC_FilterValue, 1, 67, 8, // Skip to: 6697
/* 4582 */    MCD_OPC_Decode, 214, 4, 65, // Opcode: SRAWo
/* 4586 */    MCD_OPC_FilterValue, 25, 59, 8, // Skip to: 6697
/* 4590 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4593 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 4601
/* 4597 */    MCD_OPC_Decode, 212, 4, 66, // Opcode: SRAWI
/* 4601 */    MCD_OPC_FilterValue, 1, 44, 8, // Skip to: 6697
/* 4605 */    MCD_OPC_Decode, 213, 4, 66, // Opcode: SRAWIo
/* 4609 */    MCD_OPC_FilterValue, 13, 47, 1, // Skip to: 4916
/* 4613 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 4616 */    MCD_OPC_FilterValue, 0, 47, 0, // Skip to: 4667
/* 4620 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4623 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4637
/* 4627 */    MCD_OPC_CheckField, 11, 5, 0, 16, 8, // Skip to: 6697
/* 4633 */    MCD_OPC_Decode, 190, 1, 67, // Opcode: CNTLZW
/* 4637 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 4651
/* 4641 */    MCD_OPC_CheckField, 11, 5, 0, 2, 8, // Skip to: 6697
/* 4647 */    MCD_OPC_Decode, 191, 1, 67, // Opcode: CNTLZWo
/* 4651 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 4659
/* 4655 */    MCD_OPC_Decode, 197, 4, 68, // Opcode: SLD
/* 4659 */    MCD_OPC_FilterValue, 3, 242, 7, // Skip to: 6697
/* 4663 */    MCD_OPC_Decode, 200, 4, 68, // Opcode: SLDo
/* 4667 */    MCD_OPC_FilterValue, 1, 31, 0, // Skip to: 4702
/* 4671 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4674 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4688
/* 4678 */    MCD_OPC_CheckField, 11, 5, 0, 221, 7, // Skip to: 6697
/* 4684 */    MCD_OPC_Decode, 188, 1, 69, // Opcode: CNTLZD
/* 4688 */    MCD_OPC_FilterValue, 1, 213, 7, // Skip to: 6697
/* 4692 */    MCD_OPC_CheckField, 11, 5, 0, 207, 7, // Skip to: 6697
/* 4698 */    MCD_OPC_Decode, 189, 1, 69, // Opcode: CNTLZDo
/* 4702 */    MCD_OPC_FilterValue, 11, 16, 0, // Skip to: 4722
/* 4706 */    MCD_OPC_CheckField, 11, 5, 0, 193, 7, // Skip to: 6697
/* 4712 */    MCD_OPC_CheckField, 0, 2, 0, 187, 7, // Skip to: 6697
/* 4718 */    MCD_OPC_Decode, 158, 4, 67, // Opcode: POPCNTW
/* 4722 */    MCD_OPC_FilterValue, 15, 16, 0, // Skip to: 4742
/* 4726 */    MCD_OPC_CheckField, 11, 5, 0, 173, 7, // Skip to: 6697
/* 4732 */    MCD_OPC_CheckField, 0, 2, 0, 167, 7, // Skip to: 6697
/* 4738 */    MCD_OPC_Decode, 157, 4, 69, // Opcode: POPCNTD
/* 4742 */    MCD_OPC_FilterValue, 16, 19, 0, // Skip to: 4765
/* 4746 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4749 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 4757
/* 4753 */    MCD_OPC_Decode, 215, 4, 68, // Opcode: SRD
/* 4757 */    MCD_OPC_FilterValue, 3, 144, 7, // Skip to: 6697
/* 4761 */    MCD_OPC_Decode, 218, 4, 68, // Opcode: SRDo
/* 4765 */    MCD_OPC_FilterValue, 24, 19, 0, // Skip to: 4788
/* 4769 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4772 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 4780
/* 4776 */    MCD_OPC_Decode, 207, 4, 68, // Opcode: SRAD
/* 4780 */    MCD_OPC_FilterValue, 1, 121, 7, // Skip to: 6697
/* 4784 */    MCD_OPC_Decode, 210, 4, 68, // Opcode: SRADo
/* 4788 */    MCD_OPC_FilterValue, 25, 19, 0, // Skip to: 4811
/* 4792 */    MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 4795 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 4803
/* 4799 */    MCD_OPC_Decode, 208, 4, 70, // Opcode: SRADI
/* 4803 */    MCD_OPC_FilterValue, 1, 98, 7, // Skip to: 6697
/* 4807 */    MCD_OPC_Decode, 209, 4, 70, // Opcode: SRADIo
/* 4811 */    MCD_OPC_FilterValue, 28, 31, 0, // Skip to: 4846
/* 4815 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4818 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4832
/* 4822 */    MCD_OPC_CheckField, 11, 5, 0, 77, 7, // Skip to: 6697
/* 4828 */    MCD_OPC_Decode, 255, 1, 67, // Opcode: EXTSH
/* 4832 */    MCD_OPC_FilterValue, 1, 69, 7, // Skip to: 6697
/* 4836 */    MCD_OPC_CheckField, 11, 5, 0, 63, 7, // Skip to: 6697
/* 4842 */    MCD_OPC_Decode, 131, 2, 67, // Opcode: EXTSHo
/* 4846 */    MCD_OPC_FilterValue, 29, 31, 0, // Skip to: 4881
/* 4850 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4853 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4867
/* 4857 */    MCD_OPC_CheckField, 11, 5, 0, 42, 7, // Skip to: 6697
/* 4863 */    MCD_OPC_Decode, 250, 1, 67, // Opcode: EXTSB
/* 4867 */    MCD_OPC_FilterValue, 1, 34, 7, // Skip to: 6697
/* 4871 */    MCD_OPC_CheckField, 11, 5, 0, 28, 7, // Skip to: 6697
/* 4877 */    MCD_OPC_Decode, 254, 1, 67, // Opcode: EXTSBo
/* 4881 */    MCD_OPC_FilterValue, 30, 20, 7, // Skip to: 6697
/* 4885 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4888 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4902
/* 4892 */    MCD_OPC_CheckField, 11, 5, 0, 7, 7, // Skip to: 6697
/* 4898 */    MCD_OPC_Decode, 132, 2, 69, // Opcode: EXTSW
/* 4902 */    MCD_OPC_FilterValue, 1, 255, 6, // Skip to: 6697
/* 4906 */    MCD_OPC_CheckField, 11, 5, 0, 249, 6, // Skip to: 6697
/* 4912 */    MCD_OPC_Decode, 135, 2, 69, // Opcode: EXTSWo
/* 4916 */    MCD_OPC_FilterValue, 14, 183, 0, // Skip to: 5103
/* 4920 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 4923 */    MCD_OPC_FilterValue, 0, 17, 0, // Skip to: 4944
/* 4927 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4930 */    MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 4937
/* 4934 */    MCD_OPC_Decode, 60, 65, // Opcode: AND
/* 4937 */    MCD_OPC_FilterValue, 1, 220, 6, // Skip to: 6697
/* 4941 */    MCD_OPC_Decode, 71, 65, // Opcode: ANDo
/* 4944 */    MCD_OPC_FilterValue, 1, 17, 0, // Skip to: 4965
/* 4948 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4951 */    MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 4958
/* 4955 */    MCD_OPC_Decode, 63, 65, // Opcode: ANDC
/* 4958 */    MCD_OPC_FilterValue, 1, 199, 6, // Skip to: 6697
/* 4962 */    MCD_OPC_Decode, 66, 65, // Opcode: ANDCo
/* 4965 */    MCD_OPC_FilterValue, 3, 19, 0, // Skip to: 4988
/* 4969 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4972 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 4980
/* 4976 */    MCD_OPC_Decode, 141, 4, 65, // Opcode: NOR
/* 4980 */    MCD_OPC_FilterValue, 1, 177, 6, // Skip to: 6697
/* 4984 */    MCD_OPC_Decode, 144, 4, 65, // Opcode: NORo
/* 4988 */    MCD_OPC_FilterValue, 8, 19, 0, // Skip to: 5011
/* 4992 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4995 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5003
/* 4999 */    MCD_OPC_Decode, 238, 1, 65, // Opcode: EQV
/* 5003 */    MCD_OPC_FilterValue, 1, 154, 6, // Skip to: 6697
/* 5007 */    MCD_OPC_Decode, 241, 1, 65, // Opcode: EQVo
/* 5011 */    MCD_OPC_FilterValue, 9, 19, 0, // Skip to: 5034
/* 5015 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5018 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5026
/* 5022 */    MCD_OPC_Decode, 229, 6, 65, // Opcode: XOR
/* 5026 */    MCD_OPC_FilterValue, 1, 131, 6, // Skip to: 6697
/* 5030 */    MCD_OPC_Decode, 236, 6, 65, // Opcode: XORo
/* 5034 */    MCD_OPC_FilterValue, 12, 19, 0, // Skip to: 5057
/* 5038 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5041 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5049
/* 5045 */    MCD_OPC_Decode, 148, 4, 65, // Opcode: ORC
/* 5049 */    MCD_OPC_FilterValue, 1, 108, 6, // Skip to: 6697
/* 5053 */    MCD_OPC_Decode, 151, 4, 65, // Opcode: ORCo
/* 5057 */    MCD_OPC_FilterValue, 13, 19, 0, // Skip to: 5080
/* 5061 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5064 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5072
/* 5068 */    MCD_OPC_Decode, 145, 4, 65, // Opcode: OR
/* 5072 */    MCD_OPC_FilterValue, 1, 85, 6, // Skip to: 6697
/* 5076 */    MCD_OPC_Decode, 156, 4, 65, // Opcode: ORo
/* 5080 */    MCD_OPC_FilterValue, 14, 77, 6, // Skip to: 6697
/* 5084 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5087 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5095
/* 5091 */    MCD_OPC_Decode, 130, 4, 65, // Opcode: NAND
/* 5095 */    MCD_OPC_FilterValue, 1, 62, 6, // Skip to: 6697
/* 5099 */    MCD_OPC_Decode, 133, 4, 65, // Opcode: NANDo
/* 5103 */    MCD_OPC_FilterValue, 15, 54, 6, // Skip to: 6697
/* 5107 */    MCD_OPC_CheckField, 23, 3, 0, 48, 6, // Skip to: 6697
/* 5113 */    MCD_OPC_CheckField, 6, 15, 1, 42, 6, // Skip to: 6697
/* 5119 */    MCD_OPC_CheckField, 0, 2, 0, 36, 6, // Skip to: 6697
/* 5125 */    MCD_OPC_Decode, 228, 6, 60, // Opcode: WAIT
/* 5129 */    MCD_OPC_FilterValue, 32, 4, 0, // Skip to: 5137
/* 5133 */    MCD_OPC_Decode, 197, 3, 71, // Opcode: LWZ
/* 5137 */    MCD_OPC_FilterValue, 33, 4, 0, // Skip to: 5145
/* 5141 */    MCD_OPC_Decode, 199, 3, 71, // Opcode: LWZU
/* 5145 */    MCD_OPC_FilterValue, 34, 4, 0, // Skip to: 5153
/* 5149 */    MCD_OPC_Decode, 129, 3, 71, // Opcode: LBZ
/* 5153 */    MCD_OPC_FilterValue, 35, 4, 0, // Skip to: 5161
/* 5157 */    MCD_OPC_Decode, 131, 3, 71, // Opcode: LBZU
/* 5161 */    MCD_OPC_FilterValue, 36, 4, 0, // Skip to: 5169
/* 5165 */    MCD_OPC_Decode, 133, 5, 71, // Opcode: STW
/* 5169 */    MCD_OPC_FilterValue, 37, 4, 0, // Skip to: 5177
/* 5173 */    MCD_OPC_Decode, 137, 5, 71, // Opcode: STWU
/* 5177 */    MCD_OPC_FilterValue, 38, 4, 0, // Skip to: 5185
/* 5181 */    MCD_OPC_Decode, 223, 4, 71, // Opcode: STB
/* 5185 */    MCD_OPC_FilterValue, 39, 4, 0, // Skip to: 5193
/* 5189 */    MCD_OPC_Decode, 225, 4, 71, // Opcode: STBU
/* 5193 */    MCD_OPC_FilterValue, 40, 4, 0, // Skip to: 5201
/* 5197 */    MCD_OPC_Decode, 170, 3, 71, // Opcode: LHZ
/* 5201 */    MCD_OPC_FilterValue, 41, 4, 0, // Skip to: 5209
/* 5205 */    MCD_OPC_Decode, 172, 3, 71, // Opcode: LHZU
/* 5209 */    MCD_OPC_FilterValue, 42, 4, 0, // Skip to: 5217
/* 5213 */    MCD_OPC_Decode, 161, 3, 71, // Opcode: LHA
/* 5217 */    MCD_OPC_FilterValue, 43, 4, 0, // Skip to: 5225
/* 5221 */    MCD_OPC_Decode, 163, 3, 71, // Opcode: LHAU
/* 5225 */    MCD_OPC_FilterValue, 44, 4, 0, // Skip to: 5233
/* 5229 */    MCD_OPC_Decode, 246, 4, 71, // Opcode: STH
/* 5233 */    MCD_OPC_FilterValue, 45, 4, 0, // Skip to: 5241
/* 5237 */    MCD_OPC_Decode, 249, 4, 71, // Opcode: STHU
/* 5241 */    MCD_OPC_FilterValue, 46, 4, 0, // Skip to: 5249
/* 5245 */    MCD_OPC_Decode, 182, 3, 71, // Opcode: LMW
/* 5249 */    MCD_OPC_FilterValue, 47, 4, 0, // Skip to: 5257
/* 5253 */    MCD_OPC_Decode, 255, 4, 71, // Opcode: STMW
/* 5257 */    MCD_OPC_FilterValue, 48, 4, 0, // Skip to: 5265
/* 5261 */    MCD_OPC_Decode, 157, 3, 72, // Opcode: LFS
/* 5265 */    MCD_OPC_FilterValue, 49, 4, 0, // Skip to: 5273
/* 5269 */    MCD_OPC_Decode, 158, 3, 72, // Opcode: LFSU
/* 5273 */    MCD_OPC_FilterValue, 50, 4, 0, // Skip to: 5281
/* 5277 */    MCD_OPC_Decode, 151, 3, 73, // Opcode: LFD
/* 5281 */    MCD_OPC_FilterValue, 51, 4, 0, // Skip to: 5289
/* 5285 */    MCD_OPC_Decode, 152, 3, 73, // Opcode: LFDU
/* 5289 */    MCD_OPC_FilterValue, 52, 4, 0, // Skip to: 5297
/* 5293 */    MCD_OPC_Decode, 242, 4, 72, // Opcode: STFS
/* 5297 */    MCD_OPC_FilterValue, 53, 4, 0, // Skip to: 5305
/* 5301 */    MCD_OPC_Decode, 243, 4, 72, // Opcode: STFSU
/* 5305 */    MCD_OPC_FilterValue, 54, 4, 0, // Skip to: 5313
/* 5309 */    MCD_OPC_Decode, 237, 4, 73, // Opcode: STFD
/* 5313 */    MCD_OPC_FilterValue, 55, 4, 0, // Skip to: 5321
/* 5317 */    MCD_OPC_Decode, 238, 4, 73, // Opcode: STFDU
/* 5321 */    MCD_OPC_FilterValue, 58, 27, 0, // Skip to: 5352
/* 5325 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5328 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5336
/* 5332 */    MCD_OPC_Decode, 137, 3, 74, // Opcode: LD
/* 5336 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 5344
/* 5340 */    MCD_OPC_Decode, 140, 3, 74, // Opcode: LDU
/* 5344 */    MCD_OPC_FilterValue, 2, 69, 5, // Skip to: 6697
/* 5348 */    MCD_OPC_Decode, 190, 3, 74, // Opcode: LWA
/* 5352 */    MCD_OPC_FilterValue, 59, 113, 1, // Skip to: 5725
/* 5356 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 5359 */    MCD_OPC_FilterValue, 28, 31, 0, // Skip to: 5394
/* 5363 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 5366 */    MCD_OPC_FilterValue, 26, 10, 0, // Skip to: 5380
/* 5370 */    MCD_OPC_CheckField, 16, 5, 0, 41, 5, // Skip to: 6697
/* 5376 */    MCD_OPC_Decode, 146, 2, 75, // Opcode: FCFIDS
/* 5380 */    MCD_OPC_FilterValue, 30, 33, 5, // Skip to: 6697
/* 5384 */    MCD_OPC_CheckField, 16, 5, 0, 27, 5, // Skip to: 6697
/* 5390 */    MCD_OPC_Decode, 149, 2, 75, // Opcode: FCFIDUS
/* 5394 */    MCD_OPC_FilterValue, 29, 31, 0, // Skip to: 5429
/* 5398 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 5401 */    MCD_OPC_FilterValue, 26, 10, 0, // Skip to: 5415
/* 5405 */    MCD_OPC_CheckField, 16, 5, 0, 6, 5, // Skip to: 6697
/* 5411 */    MCD_OPC_Decode, 147, 2, 75, // Opcode: FCFIDSo
/* 5415 */    MCD_OPC_FilterValue, 30, 254, 4, // Skip to: 6697
/* 5419 */    MCD_OPC_CheckField, 16, 5, 0, 248, 4, // Skip to: 6697
/* 5425 */    MCD_OPC_Decode, 150, 2, 75, // Opcode: FCFIDUSo
/* 5429 */    MCD_OPC_FilterValue, 36, 10, 0, // Skip to: 5443
/* 5433 */    MCD_OPC_CheckField, 6, 5, 0, 234, 4, // Skip to: 6697
/* 5439 */    MCD_OPC_Decode, 172, 2, 76, // Opcode: FDIVS
/* 5443 */    MCD_OPC_FilterValue, 37, 10, 0, // Skip to: 5457
/* 5447 */    MCD_OPC_CheckField, 6, 5, 0, 220, 4, // Skip to: 6697
/* 5453 */    MCD_OPC_Decode, 173, 2, 76, // Opcode: FDIVSo
/* 5457 */    MCD_OPC_FilterValue, 40, 10, 0, // Skip to: 5471
/* 5461 */    MCD_OPC_CheckField, 6, 5, 0, 206, 4, // Skip to: 6697
/* 5467 */    MCD_OPC_Decode, 240, 2, 76, // Opcode: FSUBS
/* 5471 */    MCD_OPC_FilterValue, 41, 10, 0, // Skip to: 5485
/* 5475 */    MCD_OPC_CheckField, 6, 5, 0, 192, 4, // Skip to: 6697
/* 5481 */    MCD_OPC_Decode, 241, 2, 76, // Opcode: FSUBSo
/* 5485 */    MCD_OPC_FilterValue, 42, 10, 0, // Skip to: 5499
/* 5489 */    MCD_OPC_CheckField, 6, 5, 0, 178, 4, // Skip to: 6697
/* 5495 */    MCD_OPC_Decode, 141, 2, 76, // Opcode: FADDS
/* 5499 */    MCD_OPC_FilterValue, 43, 10, 0, // Skip to: 5513
/* 5503 */    MCD_OPC_CheckField, 6, 5, 0, 164, 4, // Skip to: 6697
/* 5509 */    MCD_OPC_Decode, 142, 2, 76, // Opcode: FADDSo
/* 5513 */    MCD_OPC_FilterValue, 44, 16, 0, // Skip to: 5533
/* 5517 */    MCD_OPC_CheckField, 16, 5, 0, 150, 4, // Skip to: 6697
/* 5523 */    MCD_OPC_CheckField, 6, 5, 0, 144, 4, // Skip to: 6697
/* 5529 */    MCD_OPC_Decode, 236, 2, 77, // Opcode: FSQRTS
/* 5533 */    MCD_OPC_FilterValue, 45, 16, 0, // Skip to: 5553
/* 5537 */    MCD_OPC_CheckField, 16, 5, 0, 130, 4, // Skip to: 6697
/* 5543 */    MCD_OPC_CheckField, 6, 5, 0, 124, 4, // Skip to: 6697
/* 5549 */    MCD_OPC_Decode, 237, 2, 77, // Opcode: FSQRTSo
/* 5553 */    MCD_OPC_FilterValue, 48, 16, 0, // Skip to: 5573
/* 5557 */    MCD_OPC_CheckField, 16, 5, 0, 110, 4, // Skip to: 6697
/* 5563 */    MCD_OPC_CheckField, 6, 5, 0, 104, 4, // Skip to: 6697
/* 5569 */    MCD_OPC_Decode, 206, 2, 77, // Opcode: FRES
/* 5573 */    MCD_OPC_FilterValue, 49, 16, 0, // Skip to: 5593
/* 5577 */    MCD_OPC_CheckField, 16, 5, 0, 90, 4, // Skip to: 6697
/* 5583 */    MCD_OPC_CheckField, 6, 5, 0, 84, 4, // Skip to: 6697
/* 5589 */    MCD_OPC_Decode, 207, 2, 77, // Opcode: FRESo
/* 5593 */    MCD_OPC_FilterValue, 50, 10, 0, // Skip to: 5607
/* 5597 */    MCD_OPC_CheckField, 11, 5, 0, 70, 4, // Skip to: 6697
/* 5603 */    MCD_OPC_Decode, 186, 2, 78, // Opcode: FMULS
/* 5607 */    MCD_OPC_FilterValue, 51, 10, 0, // Skip to: 5621
/* 5611 */    MCD_OPC_CheckField, 11, 5, 0, 56, 4, // Skip to: 6697
/* 5617 */    MCD_OPC_Decode, 187, 2, 78, // Opcode: FMULSo
/* 5621 */    MCD_OPC_FilterValue, 52, 16, 0, // Skip to: 5641
/* 5625 */    MCD_OPC_CheckField, 16, 5, 0, 42, 4, // Skip to: 6697
/* 5631 */    MCD_OPC_CheckField, 6, 5, 0, 36, 4, // Skip to: 6697
/* 5637 */    MCD_OPC_Decode, 228, 2, 77, // Opcode: FRSQRTES
/* 5641 */    MCD_OPC_FilterValue, 53, 16, 0, // Skip to: 5661
/* 5645 */    MCD_OPC_CheckField, 16, 5, 0, 22, 4, // Skip to: 6697
/* 5651 */    MCD_OPC_CheckField, 6, 5, 0, 16, 4, // Skip to: 6697
/* 5657 */    MCD_OPC_Decode, 229, 2, 77, // Opcode: FRSQRTESo
/* 5661 */    MCD_OPC_FilterValue, 56, 4, 0, // Skip to: 5669
/* 5665 */    MCD_OPC_Decode, 182, 2, 79, // Opcode: FMSUBS
/* 5669 */    MCD_OPC_FilterValue, 57, 4, 0, // Skip to: 5677
/* 5673 */    MCD_OPC_Decode, 183, 2, 79, // Opcode: FMSUBSo
/* 5677 */    MCD_OPC_FilterValue, 58, 4, 0, // Skip to: 5685
/* 5681 */    MCD_OPC_Decode, 176, 2, 79, // Opcode: FMADDS
/* 5685 */    MCD_OPC_FilterValue, 59, 4, 0, // Skip to: 5693
/* 5689 */    MCD_OPC_Decode, 177, 2, 79, // Opcode: FMADDSo
/* 5693 */    MCD_OPC_FilterValue, 60, 4, 0, // Skip to: 5701
/* 5697 */    MCD_OPC_Decode, 202, 2, 79, // Opcode: FNMSUBS
/* 5701 */    MCD_OPC_FilterValue, 61, 4, 0, // Skip to: 5709
/* 5705 */    MCD_OPC_Decode, 203, 2, 79, // Opcode: FNMSUBSo
/* 5709 */    MCD_OPC_FilterValue, 62, 4, 0, // Skip to: 5717
/* 5713 */    MCD_OPC_Decode, 198, 2, 79, // Opcode: FNMADDS
/* 5717 */    MCD_OPC_FilterValue, 63, 208, 3, // Skip to: 6697
/* 5721 */    MCD_OPC_Decode, 199, 2, 79, // Opcode: FNMADDSo
/* 5725 */    MCD_OPC_FilterValue, 62, 19, 0, // Skip to: 5748
/* 5729 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5732 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5740
/* 5736 */    MCD_OPC_Decode, 231, 4, 74, // Opcode: STD
/* 5740 */    MCD_OPC_FilterValue, 1, 185, 3, // Skip to: 6697
/* 5744 */    MCD_OPC_Decode, 234, 4, 74, // Opcode: STDU
/* 5748 */    MCD_OPC_FilterValue, 63, 177, 3, // Skip to: 6697
/* 5752 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 5755 */    MCD_OPC_FilterValue, 0, 16, 0, // Skip to: 5775
/* 5759 */    MCD_OPC_CheckField, 21, 2, 0, 164, 3, // Skip to: 6697
/* 5765 */    MCD_OPC_CheckField, 6, 5, 0, 158, 3, // Skip to: 6697
/* 5771 */    MCD_OPC_Decode, 154, 2, 80, // Opcode: FCMPUS
/* 5775 */    MCD_OPC_FilterValue, 12, 19, 0, // Skip to: 5798
/* 5779 */    MCD_OPC_ExtractField, 6, 15,  // Inst{20-6} ...
/* 5782 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 5790
/* 5786 */    MCD_OPC_Decode, 230, 3, 81, // Opcode: MTFSB1
/* 5790 */    MCD_OPC_FilterValue, 2, 135, 3, // Skip to: 6697
/* 5794 */    MCD_OPC_Decode, 229, 3, 81, // Opcode: MTFSB0
/* 5798 */    MCD_OPC_FilterValue, 14, 37, 0, // Skip to: 5839
/* 5802 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 5805 */    MCD_OPC_FilterValue, 18, 10, 0, // Skip to: 5819
/* 5809 */    MCD_OPC_CheckField, 11, 10, 0, 114, 3, // Skip to: 6697
/* 5815 */    MCD_OPC_Decode, 210, 3, 82, // Opcode: MFFS
/* 5819 */    MCD_OPC_FilterValue, 22, 106, 3, // Skip to: 6697
/* 5823 */    MCD_OPC_CheckField, 25, 1, 0, 100, 3, // Skip to: 6697
/* 5829 */    MCD_OPC_CheckField, 16, 1, 0, 94, 3, // Skip to: 6697
/* 5835 */    MCD_OPC_Decode, 231, 3, 83, // Opcode: MTFSF
/* 5839 */    MCD_OPC_FilterValue, 16, 123, 0, // Skip to: 5966
/* 5843 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 5846 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5854
/* 5850 */    MCD_OPC_Decode, 157, 2, 76, // Opcode: FCPSGNS
/* 5854 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 5868
/* 5858 */    MCD_OPC_CheckField, 16, 5, 0, 65, 3, // Skip to: 6697
/* 5864 */    MCD_OPC_Decode, 195, 2, 77, // Opcode: FNEGS
/* 5868 */    MCD_OPC_FilterValue, 2, 10, 0, // Skip to: 5882
/* 5872 */    MCD_OPC_CheckField, 16, 5, 0, 51, 3, // Skip to: 6697
/* 5878 */    MCD_OPC_Decode, 179, 2, 77, // Opcode: FMR
/* 5882 */    MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 5896
/* 5886 */    MCD_OPC_CheckField, 16, 5, 0, 37, 3, // Skip to: 6697
/* 5892 */    MCD_OPC_Decode, 191, 2, 77, // Opcode: FNABSS
/* 5896 */    MCD_OPC_FilterValue, 8, 10, 0, // Skip to: 5910
/* 5900 */    MCD_OPC_CheckField, 16, 5, 0, 23, 3, // Skip to: 6697
/* 5906 */    MCD_OPC_Decode, 138, 2, 77, // Opcode: FABSS
/* 5910 */    MCD_OPC_FilterValue, 12, 10, 0, // Skip to: 5924
/* 5914 */    MCD_OPC_CheckField, 16, 5, 0, 9, 3, // Skip to: 6697
/* 5920 */    MCD_OPC_Decode, 215, 2, 77, // Opcode: FRINS
/* 5924 */    MCD_OPC_FilterValue, 13, 10, 0, // Skip to: 5938
/* 5928 */    MCD_OPC_CheckField, 16, 5, 0, 251, 2, // Skip to: 6697
/* 5934 */    MCD_OPC_Decode, 223, 2, 77, // Opcode: FRIZS
/* 5938 */    MCD_OPC_FilterValue, 14, 10, 0, // Skip to: 5952
/* 5942 */    MCD_OPC_CheckField, 16, 5, 0, 237, 2, // Skip to: 6697
/* 5948 */    MCD_OPC_Decode, 219, 2, 77, // Opcode: FRIPS
/* 5952 */    MCD_OPC_FilterValue, 15, 229, 2, // Skip to: 6697
/* 5956 */    MCD_OPC_CheckField, 16, 5, 0, 223, 2, // Skip to: 6697
/* 5962 */    MCD_OPC_Decode, 211, 2, 77, // Opcode: FRIMS
/* 5966 */    MCD_OPC_FilterValue, 17, 123, 0, // Skip to: 6093
/* 5970 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 5973 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5981
/* 5977 */    MCD_OPC_Decode, 158, 2, 76, // Opcode: FCPSGNSo
/* 5981 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 5995
/* 5985 */    MCD_OPC_CheckField, 16, 5, 0, 194, 2, // Skip to: 6697
/* 5991 */    MCD_OPC_Decode, 196, 2, 77, // Opcode: FNEGSo
/* 5995 */    MCD_OPC_FilterValue, 2, 10, 0, // Skip to: 6009
/* 5999 */    MCD_OPC_CheckField, 16, 5, 0, 180, 2, // Skip to: 6697
/* 6005 */    MCD_OPC_Decode, 180, 2, 77, // Opcode: FMRo
/* 6009 */    MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 6023
/* 6013 */    MCD_OPC_CheckField, 16, 5, 0, 166, 2, // Skip to: 6697
/* 6019 */    MCD_OPC_Decode, 192, 2, 77, // Opcode: FNABSSo
/* 6023 */    MCD_OPC_FilterValue, 8, 10, 0, // Skip to: 6037
/* 6027 */    MCD_OPC_CheckField, 16, 5, 0, 152, 2, // Skip to: 6697
/* 6033 */    MCD_OPC_Decode, 139, 2, 77, // Opcode: FABSSo
/* 6037 */    MCD_OPC_FilterValue, 12, 10, 0, // Skip to: 6051
/* 6041 */    MCD_OPC_CheckField, 16, 5, 0, 138, 2, // Skip to: 6697
/* 6047 */    MCD_OPC_Decode, 216, 2, 77, // Opcode: FRINSo
/* 6051 */    MCD_OPC_FilterValue, 13, 10, 0, // Skip to: 6065
/* 6055 */    MCD_OPC_CheckField, 16, 5, 0, 124, 2, // Skip to: 6697
/* 6061 */    MCD_OPC_Decode, 224, 2, 77, // Opcode: FRIZSo
/* 6065 */    MCD_OPC_FilterValue, 14, 10, 0, // Skip to: 6079
/* 6069 */    MCD_OPC_CheckField, 16, 5, 0, 110, 2, // Skip to: 6697
/* 6075 */    MCD_OPC_Decode, 220, 2, 77, // Opcode: FRIPSo
/* 6079 */    MCD_OPC_FilterValue, 15, 102, 2, // Skip to: 6697
/* 6083 */    MCD_OPC_CheckField, 16, 5, 0, 96, 2, // Skip to: 6697
/* 6089 */    MCD_OPC_Decode, 212, 2, 77, // Opcode: FRIMSo
/* 6093 */    MCD_OPC_FilterValue, 24, 16, 0, // Skip to: 6113
/* 6097 */    MCD_OPC_CheckField, 16, 5, 0, 82, 2, // Skip to: 6697
/* 6103 */    MCD_OPC_CheckField, 6, 5, 0, 76, 2, // Skip to: 6697
/* 6109 */    MCD_OPC_Decode, 225, 2, 75, // Opcode: FRSP
/* 6113 */    MCD_OPC_FilterValue, 25, 16, 0, // Skip to: 6133
/* 6117 */    MCD_OPC_CheckField, 16, 5, 0, 62, 2, // Skip to: 6697
/* 6123 */    MCD_OPC_CheckField, 6, 5, 0, 56, 2, // Skip to: 6697
/* 6129 */    MCD_OPC_Decode, 226, 2, 75, // Opcode: FRSPo
/* 6133 */    MCD_OPC_FilterValue, 28, 59, 0, // Skip to: 6196
/* 6137 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 6140 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 6154
/* 6144 */    MCD_OPC_CheckField, 16, 5, 0, 35, 2, // Skip to: 6697
/* 6150 */    MCD_OPC_Decode, 165, 2, 84, // Opcode: FCTIW
/* 6154 */    MCD_OPC_FilterValue, 25, 10, 0, // Skip to: 6168
/* 6158 */    MCD_OPC_CheckField, 16, 5, 0, 21, 2, // Skip to: 6697
/* 6164 */    MCD_OPC_Decode, 159, 2, 84, // Opcode: FCTID
/* 6168 */    MCD_OPC_FilterValue, 26, 10, 0, // Skip to: 6182
/* 6172 */    MCD_OPC_CheckField, 16, 5, 0, 7, 2, // Skip to: 6697
/* 6178 */    MCD_OPC_Decode, 145, 2, 84, // Opcode: FCFID
/* 6182 */    MCD_OPC_FilterValue, 30, 255, 1, // Skip to: 6697
/* 6186 */    MCD_OPC_CheckField, 16, 5, 0, 249, 1, // Skip to: 6697
/* 6192 */    MCD_OPC_Decode, 148, 2, 84, // Opcode: FCFIDU
/* 6196 */    MCD_OPC_FilterValue, 29, 59, 0, // Skip to: 6259
/* 6200 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 6203 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 6217
/* 6207 */    MCD_OPC_CheckField, 16, 5, 0, 228, 1, // Skip to: 6697
/* 6213 */    MCD_OPC_Decode, 170, 2, 84, // Opcode: FCTIWo
/* 6217 */    MCD_OPC_FilterValue, 25, 10, 0, // Skip to: 6231
/* 6221 */    MCD_OPC_CheckField, 16, 5, 0, 214, 1, // Skip to: 6697
/* 6227 */    MCD_OPC_Decode, 164, 2, 84, // Opcode: FCTIDo
/* 6231 */    MCD_OPC_FilterValue, 26, 10, 0, // Skip to: 6245
/* 6235 */    MCD_OPC_CheckField, 16, 5, 0, 200, 1, // Skip to: 6697
/* 6241 */    MCD_OPC_Decode, 152, 2, 84, // Opcode: FCFIDo
/* 6245 */    MCD_OPC_FilterValue, 30, 192, 1, // Skip to: 6697
/* 6249 */    MCD_OPC_CheckField, 16, 5, 0, 186, 1, // Skip to: 6697
/* 6255 */    MCD_OPC_Decode, 151, 2, 84, // Opcode: FCFIDUo
/* 6259 */    MCD_OPC_FilterValue, 30, 59, 0, // Skip to: 6322
/* 6263 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 6266 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 6280
/* 6270 */    MCD_OPC_CheckField, 16, 5, 0, 165, 1, // Skip to: 6697
/* 6276 */    MCD_OPC_Decode, 168, 2, 84, // Opcode: FCTIWZ
/* 6280 */    MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 6294
/* 6284 */    MCD_OPC_CheckField, 16, 5, 0, 151, 1, // Skip to: 6697
/* 6290 */    MCD_OPC_Decode, 166, 2, 84, // Opcode: FCTIWUZ
/* 6294 */    MCD_OPC_FilterValue, 25, 10, 0, // Skip to: 6308
/* 6298 */    MCD_OPC_CheckField, 16, 5, 0, 137, 1, // Skip to: 6697
/* 6304 */    MCD_OPC_Decode, 162, 2, 84, // Opcode: FCTIDZ
/* 6308 */    MCD_OPC_FilterValue, 29, 129, 1, // Skip to: 6697
/* 6312 */    MCD_OPC_CheckField, 16, 5, 0, 123, 1, // Skip to: 6697
/* 6318 */    MCD_OPC_Decode, 160, 2, 84, // Opcode: FCTIDUZ
/* 6322 */    MCD_OPC_FilterValue, 31, 59, 0, // Skip to: 6385
/* 6326 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 6329 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 6343
/* 6333 */    MCD_OPC_CheckField, 16, 5, 0, 102, 1, // Skip to: 6697
/* 6339 */    MCD_OPC_Decode, 169, 2, 84, // Opcode: FCTIWZo
/* 6343 */    MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 6357
/* 6347 */    MCD_OPC_CheckField, 16, 5, 0, 88, 1, // Skip to: 6697
/* 6353 */    MCD_OPC_Decode, 167, 2, 84, // Opcode: FCTIWUZo
/* 6357 */    MCD_OPC_FilterValue, 25, 10, 0, // Skip to: 6371
/* 6361 */    MCD_OPC_CheckField, 16, 5, 0, 74, 1, // Skip to: 6697
/* 6367 */    MCD_OPC_Decode, 163, 2, 84, // Opcode: FCTIDZo
/* 6371 */    MCD_OPC_FilterValue, 29, 66, 1, // Skip to: 6697
/* 6375 */    MCD_OPC_CheckField, 16, 5, 0, 60, 1, // Skip to: 6697
/* 6381 */    MCD_OPC_Decode, 161, 2, 84, // Opcode: FCTIDUZo
/* 6385 */    MCD_OPC_FilterValue, 36, 10, 0, // Skip to: 6399
/* 6389 */    MCD_OPC_CheckField, 6, 5, 0, 46, 1, // Skip to: 6697
/* 6395 */    MCD_OPC_Decode, 171, 2, 85, // Opcode: FDIV
/* 6399 */    MCD_OPC_FilterValue, 37, 10, 0, // Skip to: 6413
/* 6403 */    MCD_OPC_CheckField, 6, 5, 0, 32, 1, // Skip to: 6697
/* 6409 */    MCD_OPC_Decode, 174, 2, 85, // Opcode: FDIVo
/* 6413 */    MCD_OPC_FilterValue, 40, 10, 0, // Skip to: 6427
/* 6417 */    MCD_OPC_CheckField, 6, 5, 0, 18, 1, // Skip to: 6697
/* 6423 */    MCD_OPC_Decode, 239, 2, 85, // Opcode: FSUB
/* 6427 */    MCD_OPC_FilterValue, 41, 10, 0, // Skip to: 6441
/* 6431 */    MCD_OPC_CheckField, 6, 5, 0, 4, 1, // Skip to: 6697
/* 6437 */    MCD_OPC_Decode, 242, 2, 85, // Opcode: FSUBo
/* 6441 */    MCD_OPC_FilterValue, 42, 10, 0, // Skip to: 6455
/* 6445 */    MCD_OPC_CheckField, 6, 5, 0, 246, 0, // Skip to: 6697
/* 6451 */    MCD_OPC_Decode, 140, 2, 85, // Opcode: FADD
/* 6455 */    MCD_OPC_FilterValue, 43, 10, 0, // Skip to: 6469
/* 6459 */    MCD_OPC_CheckField, 6, 5, 0, 232, 0, // Skip to: 6697
/* 6465 */    MCD_OPC_Decode, 143, 2, 85, // Opcode: FADDo
/* 6469 */    MCD_OPC_FilterValue, 44, 16, 0, // Skip to: 6489
/* 6473 */    MCD_OPC_CheckField, 16, 5, 0, 218, 0, // Skip to: 6697
/* 6479 */    MCD_OPC_CheckField, 6, 5, 0, 212, 0, // Skip to: 6697
/* 6485 */    MCD_OPC_Decode, 235, 2, 84, // Opcode: FSQRT
/* 6489 */    MCD_OPC_FilterValue, 45, 16, 0, // Skip to: 6509
/* 6493 */    MCD_OPC_CheckField, 16, 5, 0, 198, 0, // Skip to: 6697
/* 6499 */    MCD_OPC_CheckField, 6, 5, 0, 192, 0, // Skip to: 6697
/* 6505 */    MCD_OPC_Decode, 238, 2, 84, // Opcode: FSQRTo
/* 6509 */    MCD_OPC_FilterValue, 46, 4, 0, // Skip to: 6517
/* 6513 */    MCD_OPC_Decode, 233, 2, 86, // Opcode: FSELS
/* 6517 */    MCD_OPC_FilterValue, 47, 4, 0, // Skip to: 6525
/* 6521 */    MCD_OPC_Decode, 234, 2, 86, // Opcode: FSELSo
/* 6525 */    MCD_OPC_FilterValue, 48, 16, 0, // Skip to: 6545
/* 6529 */    MCD_OPC_CheckField, 16, 5, 0, 162, 0, // Skip to: 6697
/* 6535 */    MCD_OPC_CheckField, 6, 5, 0, 156, 0, // Skip to: 6697
/* 6541 */    MCD_OPC_Decode, 205, 2, 84, // Opcode: FRE
/* 6545 */    MCD_OPC_FilterValue, 49, 16, 0, // Skip to: 6565
/* 6549 */    MCD_OPC_CheckField, 16, 5, 0, 142, 0, // Skip to: 6697
/* 6555 */    MCD_OPC_CheckField, 6, 5, 0, 136, 0, // Skip to: 6697
/* 6561 */    MCD_OPC_Decode, 208, 2, 84, // Opcode: FREo
/* 6565 */    MCD_OPC_FilterValue, 50, 10, 0, // Skip to: 6579
/* 6569 */    MCD_OPC_CheckField, 11, 5, 0, 122, 0, // Skip to: 6697
/* 6575 */    MCD_OPC_Decode, 185, 2, 87, // Opcode: FMUL
/* 6579 */    MCD_OPC_FilterValue, 51, 10, 0, // Skip to: 6593
/* 6583 */    MCD_OPC_CheckField, 11, 5, 0, 108, 0, // Skip to: 6697
/* 6589 */    MCD_OPC_Decode, 188, 2, 87, // Opcode: FMULo
/* 6593 */    MCD_OPC_FilterValue, 52, 16, 0, // Skip to: 6613
/* 6597 */    MCD_OPC_CheckField, 16, 5, 0, 94, 0, // Skip to: 6697
/* 6603 */    MCD_OPC_CheckField, 6, 5, 0, 88, 0, // Skip to: 6697
/* 6609 */    MCD_OPC_Decode, 227, 2, 84, // Opcode: FRSQRTE
/* 6613 */    MCD_OPC_FilterValue, 53, 16, 0, // Skip to: 6633
/* 6617 */    MCD_OPC_CheckField, 16, 5, 0, 74, 0, // Skip to: 6697
/* 6623 */    MCD_OPC_CheckField, 6, 5, 0, 68, 0, // Skip to: 6697
/* 6629 */    MCD_OPC_Decode, 230, 2, 84, // Opcode: FRSQRTEo
/* 6633 */    MCD_OPC_FilterValue, 56, 4, 0, // Skip to: 6641
/* 6637 */    MCD_OPC_Decode, 181, 2, 88, // Opcode: FMSUB
/* 6641 */    MCD_OPC_FilterValue, 57, 4, 0, // Skip to: 6649
/* 6645 */    MCD_OPC_Decode, 184, 2, 88, // Opcode: FMSUBo
/* 6649 */    MCD_OPC_FilterValue, 58, 4, 0, // Skip to: 6657
/* 6653 */    MCD_OPC_Decode, 175, 2, 88, // Opcode: FMADD
/* 6657 */    MCD_OPC_FilterValue, 59, 4, 0, // Skip to: 6665
/* 6661 */    MCD_OPC_Decode, 178, 2, 88, // Opcode: FMADDo
/* 6665 */    MCD_OPC_FilterValue, 60, 4, 0, // Skip to: 6673
/* 6669 */    MCD_OPC_Decode, 201, 2, 88, // Opcode: FNMSUB
/* 6673 */    MCD_OPC_FilterValue, 61, 4, 0, // Skip to: 6681
/* 6677 */    MCD_OPC_Decode, 204, 2, 88, // Opcode: FNMSUBo
/* 6681 */    MCD_OPC_FilterValue, 62, 4, 0, // Skip to: 6689
/* 6685 */    MCD_OPC_Decode, 197, 2, 88, // Opcode: FNMADD
/* 6689 */    MCD_OPC_FilterValue, 63, 4, 0, // Skip to: 6697
/* 6693 */    MCD_OPC_Decode, 200, 2, 88, // Opcode: FNMADDo
/* 6697 */    MCD_OPC_Fail,
  0
};

static bool checkDecoderPredicate(unsigned Idx, uint64_t Bits)
{
  //llvm_unreachable("Invalid index!");
  return true;
}

#define DecodeToMCInst(fname,fieldname, InsnType) \
static DecodeStatus fname(DecodeStatus S, unsigned Idx, InsnType insn, MCInst *MI, \
		uint64_t Address, const void *Decoder) \
{ \
  InsnType tmp; \
  switch (Idx) { \
  default: \
  case 0: \
    tmp = fieldname(insn, 21, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeSImmOperand(MI, tmp, Address, Decoder, 16) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 1: \
    tmp = fieldname(insn, 21, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeSImmOperand(MI, tmp, Address, Decoder, 16) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 2: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 3: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 4: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 5: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 6: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 7: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (decodeSImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 8: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 9: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 4); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 10: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 11: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeSImmOperand(MI, tmp, Address, Decoder, 16) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 12: \
    tmp = fieldname(insn, 23, 3); \
    if (DecodeCRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 16) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 13: \
    tmp = fieldname(insn, 23, 3); \
    if (DecodeCRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 16) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 14: \
    tmp = fieldname(insn, 23, 3); \
    if (DecodeCRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeSImmOperand(MI, tmp, Address, Decoder, 16) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 15: \
    tmp = fieldname(insn, 23, 3); \
    if (DecodeCRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeSImmOperand(MI, tmp, Address, Decoder, 16) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 16: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeSImmOperand(MI, tmp, Address, Decoder, 16) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 17: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRC_NOR0RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeSImmOperand(MI, tmp, Address, Decoder, 16) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 18: \
    tmp = fieldname(insn, 2, 14); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 19: \
    tmp = fieldname(insn, 21, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeCRBITRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 2, 14); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 20: \
    tmp = fieldname(insn, 5, 7); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 21: \
    tmp = fieldname(insn, 2, 24); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 22: \
    tmp = fieldname(insn, 23, 3); \
    if (DecodeCRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 18, 3); \
    if (DecodeCRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 23: \
    return S; \
  case 24: \
    tmp = fieldname(insn, 21, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeCRBITRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 25: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeCRBITRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeCRBITRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeCRBITRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 26: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 1, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 27: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 1, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 28: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 1, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 29: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 16); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 16) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 30: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 1, 1) << 5); \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 6) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 5, 1) << 5); \
    tmp |= (fieldname(insn, 6, 5) << 0); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 6) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 31: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 1, 1) << 5); \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 6) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 5, 1) << 5); \
    tmp |= (fieldname(insn, 6, 5) << 0); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 6) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 32: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 5, 1) << 5); \
    tmp |= (fieldname(insn, 6, 5) << 0); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 6) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 33: \
    tmp = fieldname(insn, 23, 3); \
    if (DecodeCRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 34: \
    tmp = fieldname(insn, 23, 3); \
    if (DecodeCRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 35: \
    tmp = fieldname(insn, 21, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 36: \
    tmp = fieldname(insn, 21, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 37: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 38: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 39: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 40: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 41: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRC_NOR0RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeCRBITRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 42: \
    tmp = fieldname(insn, 12, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 43: \
    tmp = fieldname(insn, 12, 8); \
    if (decodeCRBitMOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 44: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 45: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 8); \
    if (decodeCRBitMOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 46: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 47: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 48: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 49: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 11, 5) << 5); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 50: \
    tmp = 0; \
    tmp |= (fieldname(insn, 11, 5) << 5); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 51: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 52: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 53: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 54: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 55: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 56: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 57: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 58: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 59: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 60: \
    tmp = fieldname(insn, 21, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 61: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 62: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 63: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 64: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 65: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 66: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 67: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 68: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 69: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 70: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 1, 1) << 5); \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 6) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 71: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 21); \
    if (decodeMemRIOperands(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 72: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 21); \
    if (decodeMemRIOperands(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 73: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 21); \
    if (decodeMemRIOperands(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 74: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 2, 19); \
    if (decodeMemRIXOperands(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 75: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 76: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 77: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 78: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 79: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 80: \
    tmp = fieldname(insn, 23, 3); \
    if (DecodeCRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 81: \
    tmp = fieldname(insn, 21, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 82: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 83: \
    tmp = fieldname(insn, 17, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 84: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 85: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 86: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 87: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 88: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  } \
}

// DecodeToMCInst(decodeToMCInst_2, fieldFromInstruction_2, uint16_t)
DecodeToMCInst(decodeToMCInst_4, fieldFromInstruction_4, uint32_t)

#define DecodeInstruction(fname, fieldname, decoder, InsnType) \
static DecodeStatus fname(const uint8_t DecodeTable[], MCInst *MI, \
                                      InsnType insn, uint64_t Address, \
                                      int feature) \
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
      Opc = (uint32_t)decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      DecodeIdx = (uint32_t)decodeULEB128(Ptr, &Len); \
      Ptr += Len; \
      MCInst_setOpcode(MI, Opc); \
      return decoder(S, DecodeIdx, insn, MI, Address, 0); \
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

//DecodeInstruction(decodeInstruction_2, fieldFromInstruction_2, decodeToMCInst_2, uint16_t)

DecodeInstruction(decodeInstruction_4, fieldFromInstruction_4, decodeToMCInst_4, uint32_t)
