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
/* 7 */       MCD_OPC_Decode, 161, 7, 0, // Opcode: TDI
/* 11 */      MCD_OPC_FilterValue, 3, 4, 0, // Skip to: 19
/* 15 */      MCD_OPC_Decode, 178, 7, 1, // Opcode: TWI
/* 19 */      MCD_OPC_FilterValue, 4, 155, 5, // Skip to: 1458
/* 23 */      MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 26 */      MCD_OPC_FilterValue, 0, 163, 0, // Skip to: 193
/* 30 */      MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 33 */      MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 41
/* 37 */      MCD_OPC_Decode, 186, 7, 2, // Opcode: VADDUBM
/* 41 */      MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 49
/* 45 */      MCD_OPC_Decode, 188, 7, 2, // Opcode: VADDUHM
/* 49 */      MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 57
/* 53 */      MCD_OPC_Decode, 190, 7, 2, // Opcode: VADDUWM
/* 57 */      MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 65
/* 61 */      MCD_OPC_Decode, 181, 7, 2, // Opcode: VADDCUW
/* 65 */      MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 73
/* 69 */      MCD_OPC_Decode, 187, 7, 2, // Opcode: VADDUBS
/* 73 */      MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 81
/* 77 */      MCD_OPC_Decode, 189, 7, 2, // Opcode: VADDUHS
/* 81 */      MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 89
/* 85 */      MCD_OPC_Decode, 191, 7, 2, // Opcode: VADDUWS
/* 89 */      MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 97
/* 93 */      MCD_OPC_Decode, 183, 7, 2, // Opcode: VADDSBS
/* 97 */      MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 105
/* 101 */     MCD_OPC_Decode, 184, 7, 2, // Opcode: VADDSHS
/* 105 */     MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 113
/* 109 */     MCD_OPC_Decode, 185, 7, 2, // Opcode: VADDSWS
/* 113 */     MCD_OPC_FilterValue, 16, 4, 0, // Skip to: 121
/* 117 */     MCD_OPC_Decode, 194, 8, 2, // Opcode: VSUBUBM
/* 121 */     MCD_OPC_FilterValue, 17, 4, 0, // Skip to: 129
/* 125 */     MCD_OPC_Decode, 196, 8, 2, // Opcode: VSUBUHM
/* 129 */     MCD_OPC_FilterValue, 18, 4, 0, // Skip to: 137
/* 133 */     MCD_OPC_Decode, 198, 8, 2, // Opcode: VSUBUWM
/* 137 */     MCD_OPC_FilterValue, 22, 4, 0, // Skip to: 145
/* 141 */     MCD_OPC_Decode, 189, 8, 2, // Opcode: VSUBCUW
/* 145 */     MCD_OPC_FilterValue, 24, 4, 0, // Skip to: 153
/* 149 */     MCD_OPC_Decode, 195, 8, 2, // Opcode: VSUBUBS
/* 153 */     MCD_OPC_FilterValue, 25, 4, 0, // Skip to: 161
/* 157 */     MCD_OPC_Decode, 197, 8, 2, // Opcode: VSUBUHS
/* 161 */     MCD_OPC_FilterValue, 26, 4, 0, // Skip to: 169
/* 165 */     MCD_OPC_Decode, 199, 8, 2, // Opcode: VSUBUWS
/* 169 */     MCD_OPC_FilterValue, 28, 4, 0, // Skip to: 177
/* 173 */     MCD_OPC_Decode, 191, 8, 2, // Opcode: VSUBSBS
/* 177 */     MCD_OPC_FilterValue, 29, 4, 0, // Skip to: 185
/* 181 */     MCD_OPC_Decode, 192, 8, 2, // Opcode: VSUBSHS
/* 185 */     MCD_OPC_FilterValue, 30, 223, 35, // Skip to: 9372
/* 189 */     MCD_OPC_Decode, 193, 8, 2, // Opcode: VSUBSWS
/* 193 */     MCD_OPC_FilterValue, 2, 147, 0, // Skip to: 344
/* 197 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 200 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 208
/* 204 */     MCD_OPC_Decode, 241, 7, 2, // Opcode: VMAXUB
/* 208 */     MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 216
/* 212 */     MCD_OPC_Decode, 242, 7, 2, // Opcode: VMAXUH
/* 216 */     MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 224
/* 220 */     MCD_OPC_Decode, 243, 7, 2, // Opcode: VMAXUW
/* 224 */     MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 232
/* 228 */     MCD_OPC_Decode, 238, 7, 2, // Opcode: VMAXSB
/* 232 */     MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 240
/* 236 */     MCD_OPC_Decode, 239, 7, 2, // Opcode: VMAXSH
/* 240 */     MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 248
/* 244 */     MCD_OPC_Decode, 240, 7, 2, // Opcode: VMAXSW
/* 248 */     MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 256
/* 252 */     MCD_OPC_Decode, 250, 7, 2, // Opcode: VMINUB
/* 256 */     MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 264
/* 260 */     MCD_OPC_Decode, 251, 7, 2, // Opcode: VMINUH
/* 264 */     MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 272
/* 268 */     MCD_OPC_Decode, 252, 7, 2, // Opcode: VMINUW
/* 272 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 280
/* 276 */     MCD_OPC_Decode, 247, 7, 2, // Opcode: VMINSB
/* 280 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 288
/* 284 */     MCD_OPC_Decode, 248, 7, 2, // Opcode: VMINSH
/* 288 */     MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 296
/* 292 */     MCD_OPC_Decode, 249, 7, 2, // Opcode: VMINSW
/* 296 */     MCD_OPC_FilterValue, 16, 4, 0, // Skip to: 304
/* 300 */     MCD_OPC_Decode, 197, 7, 2, // Opcode: VAVGUB
/* 304 */     MCD_OPC_FilterValue, 17, 4, 0, // Skip to: 312
/* 308 */     MCD_OPC_Decode, 198, 7, 2, // Opcode: VAVGUH
/* 312 */     MCD_OPC_FilterValue, 18, 4, 0, // Skip to: 320
/* 316 */     MCD_OPC_Decode, 199, 7, 2, // Opcode: VAVGUW
/* 320 */     MCD_OPC_FilterValue, 20, 4, 0, // Skip to: 328
/* 324 */     MCD_OPC_Decode, 194, 7, 2, // Opcode: VAVGSB
/* 328 */     MCD_OPC_FilterValue, 21, 4, 0, // Skip to: 336
/* 332 */     MCD_OPC_Decode, 195, 7, 2, // Opcode: VAVGSH
/* 336 */     MCD_OPC_FilterValue, 22, 72, 35, // Skip to: 9372
/* 340 */     MCD_OPC_Decode, 196, 7, 2, // Opcode: VAVGSW
/* 344 */     MCD_OPC_FilterValue, 4, 183, 0, // Skip to: 531
/* 348 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 351 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 359
/* 355 */     MCD_OPC_Decode, 164, 8, 2, // Opcode: VRLB
/* 359 */     MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 367
/* 363 */     MCD_OPC_Decode, 165, 8, 2, // Opcode: VRLH
/* 367 */     MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 375
/* 371 */     MCD_OPC_Decode, 166, 8, 2, // Opcode: VRLW
/* 375 */     MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 383
/* 379 */     MCD_OPC_Decode, 170, 8, 2, // Opcode: VSLB
/* 383 */     MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 391
/* 387 */     MCD_OPC_Decode, 172, 8, 2, // Opcode: VSLH
/* 391 */     MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 399
/* 395 */     MCD_OPC_Decode, 174, 8, 2, // Opcode: VSLW
/* 399 */     MCD_OPC_FilterValue, 7, 4, 0, // Skip to: 407
/* 403 */     MCD_OPC_Decode, 169, 8, 2, // Opcode: VSL
/* 407 */     MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 415
/* 411 */     MCD_OPC_Decode, 185, 8, 2, // Opcode: VSRB
/* 415 */     MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 423
/* 419 */     MCD_OPC_Decode, 186, 8, 2, // Opcode: VSRH
/* 423 */     MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 431
/* 427 */     MCD_OPC_Decode, 188, 8, 2, // Opcode: VSRW
/* 431 */     MCD_OPC_FilterValue, 11, 4, 0, // Skip to: 439
/* 435 */     MCD_OPC_Decode, 181, 8, 2, // Opcode: VSR
/* 439 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 447
/* 443 */     MCD_OPC_Decode, 182, 8, 2, // Opcode: VSRAB
/* 447 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 455
/* 451 */     MCD_OPC_Decode, 183, 8, 2, // Opcode: VSRAH
/* 455 */     MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 463
/* 459 */     MCD_OPC_Decode, 184, 8, 2, // Opcode: VSRAW
/* 463 */     MCD_OPC_FilterValue, 16, 4, 0, // Skip to: 471
/* 467 */     MCD_OPC_Decode, 192, 7, 2, // Opcode: VAND
/* 471 */     MCD_OPC_FilterValue, 17, 4, 0, // Skip to: 479
/* 475 */     MCD_OPC_Decode, 193, 7, 2, // Opcode: VANDC
/* 479 */     MCD_OPC_FilterValue, 18, 4, 0, // Skip to: 487
/* 483 */     MCD_OPC_Decode, 148, 8, 2, // Opcode: VOR
/* 487 */     MCD_OPC_FilterValue, 19, 4, 0, // Skip to: 495
/* 491 */     MCD_OPC_Decode, 211, 8, 2, // Opcode: VXOR
/* 495 */     MCD_OPC_FilterValue, 20, 4, 0, // Skip to: 503
/* 499 */     MCD_OPC_Decode, 147, 8, 2, // Opcode: VNOR
/* 503 */     MCD_OPC_FilterValue, 24, 10, 0, // Skip to: 517
/* 507 */     MCD_OPC_CheckField, 11, 10, 0, 155, 34, // Skip to: 9372
/* 513 */     MCD_OPC_Decode, 177, 5, 3, // Opcode: MFVSCR
/* 517 */     MCD_OPC_FilterValue, 25, 147, 34, // Skip to: 9372
/* 521 */     MCD_OPC_CheckField, 16, 10, 0, 141, 34, // Skip to: 9372
/* 527 */     MCD_OPC_Decode, 200, 5, 4, // Opcode: MTVSCR
/* 531 */     MCD_OPC_FilterValue, 6, 211, 0, // Skip to: 746
/* 535 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 538 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 546
/* 542 */     MCD_OPC_Decode, 208, 7, 2, // Opcode: VCMPEQUB
/* 546 */     MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 554
/* 550 */     MCD_OPC_Decode, 210, 7, 2, // Opcode: VCMPEQUH
/* 554 */     MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 562
/* 558 */     MCD_OPC_Decode, 212, 7, 2, // Opcode: VCMPEQUW
/* 562 */     MCD_OPC_FilterValue, 3, 4, 0, // Skip to: 570
/* 566 */     MCD_OPC_Decode, 206, 7, 2, // Opcode: VCMPEQFP
/* 570 */     MCD_OPC_FilterValue, 7, 4, 0, // Skip to: 578
/* 574 */     MCD_OPC_Decode, 214, 7, 2, // Opcode: VCMPGEFP
/* 578 */     MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 586
/* 582 */     MCD_OPC_Decode, 224, 7, 2, // Opcode: VCMPGTUB
/* 586 */     MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 594
/* 590 */     MCD_OPC_Decode, 226, 7, 2, // Opcode: VCMPGTUH
/* 594 */     MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 602
/* 598 */     MCD_OPC_Decode, 228, 7, 2, // Opcode: VCMPGTUW
/* 602 */     MCD_OPC_FilterValue, 11, 4, 0, // Skip to: 610
/* 606 */     MCD_OPC_Decode, 216, 7, 2, // Opcode: VCMPGTFP
/* 610 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 618
/* 614 */     MCD_OPC_Decode, 218, 7, 2, // Opcode: VCMPGTSB
/* 618 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 626
/* 622 */     MCD_OPC_Decode, 220, 7, 2, // Opcode: VCMPGTSH
/* 626 */     MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 634
/* 630 */     MCD_OPC_Decode, 222, 7, 2, // Opcode: VCMPGTSW
/* 634 */     MCD_OPC_FilterValue, 15, 4, 0, // Skip to: 642
/* 638 */     MCD_OPC_Decode, 204, 7, 2, // Opcode: VCMPBFP
/* 642 */     MCD_OPC_FilterValue, 16, 4, 0, // Skip to: 650
/* 646 */     MCD_OPC_Decode, 209, 7, 2, // Opcode: VCMPEQUBo
/* 650 */     MCD_OPC_FilterValue, 17, 4, 0, // Skip to: 658
/* 654 */     MCD_OPC_Decode, 211, 7, 2, // Opcode: VCMPEQUHo
/* 658 */     MCD_OPC_FilterValue, 18, 4, 0, // Skip to: 666
/* 662 */     MCD_OPC_Decode, 213, 7, 2, // Opcode: VCMPEQUWo
/* 666 */     MCD_OPC_FilterValue, 19, 4, 0, // Skip to: 674
/* 670 */     MCD_OPC_Decode, 207, 7, 2, // Opcode: VCMPEQFPo
/* 674 */     MCD_OPC_FilterValue, 23, 4, 0, // Skip to: 682
/* 678 */     MCD_OPC_Decode, 215, 7, 2, // Opcode: VCMPGEFPo
/* 682 */     MCD_OPC_FilterValue, 24, 4, 0, // Skip to: 690
/* 686 */     MCD_OPC_Decode, 225, 7, 2, // Opcode: VCMPGTUBo
/* 690 */     MCD_OPC_FilterValue, 25, 4, 0, // Skip to: 698
/* 694 */     MCD_OPC_Decode, 227, 7, 2, // Opcode: VCMPGTUHo
/* 698 */     MCD_OPC_FilterValue, 26, 4, 0, // Skip to: 706
/* 702 */     MCD_OPC_Decode, 229, 7, 2, // Opcode: VCMPGTUWo
/* 706 */     MCD_OPC_FilterValue, 27, 4, 0, // Skip to: 714
/* 710 */     MCD_OPC_Decode, 217, 7, 2, // Opcode: VCMPGTFPo
/* 714 */     MCD_OPC_FilterValue, 28, 4, 0, // Skip to: 722
/* 718 */     MCD_OPC_Decode, 219, 7, 2, // Opcode: VCMPGTSBo
/* 722 */     MCD_OPC_FilterValue, 29, 4, 0, // Skip to: 730
/* 726 */     MCD_OPC_Decode, 221, 7, 2, // Opcode: VCMPGTSHo
/* 730 */     MCD_OPC_FilterValue, 30, 4, 0, // Skip to: 738
/* 734 */     MCD_OPC_Decode, 223, 7, 2, // Opcode: VCMPGTSWo
/* 738 */     MCD_OPC_FilterValue, 31, 182, 33, // Skip to: 9372
/* 742 */     MCD_OPC_Decode, 205, 7, 2, // Opcode: VCMPBFPo
/* 746 */     MCD_OPC_FilterValue, 8, 107, 0, // Skip to: 857
/* 750 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 753 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 761
/* 757 */     MCD_OPC_Decode, 144, 8, 2, // Opcode: VMULOUB
/* 761 */     MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 769
/* 765 */     MCD_OPC_Decode, 145, 8, 2, // Opcode: VMULOUH
/* 769 */     MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 777
/* 773 */     MCD_OPC_Decode, 142, 8, 2, // Opcode: VMULOSB
/* 777 */     MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 785
/* 781 */     MCD_OPC_Decode, 143, 8, 2, // Opcode: VMULOSH
/* 785 */     MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 793
/* 789 */     MCD_OPC_Decode, 140, 8, 2, // Opcode: VMULEUB
/* 793 */     MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 801
/* 797 */     MCD_OPC_Decode, 141, 8, 2, // Opcode: VMULEUH
/* 801 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 809
/* 805 */     MCD_OPC_Decode, 138, 8, 2, // Opcode: VMULESB
/* 809 */     MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 817
/* 813 */     MCD_OPC_Decode, 139, 8, 2, // Opcode: VMULESH
/* 817 */     MCD_OPC_FilterValue, 24, 4, 0, // Skip to: 825
/* 821 */     MCD_OPC_Decode, 203, 8, 2, // Opcode: VSUM4UBS
/* 825 */     MCD_OPC_FilterValue, 25, 4, 0, // Skip to: 833
/* 829 */     MCD_OPC_Decode, 202, 8, 2, // Opcode: VSUM4SHS
/* 833 */     MCD_OPC_FilterValue, 26, 4, 0, // Skip to: 841
/* 837 */     MCD_OPC_Decode, 200, 8, 2, // Opcode: VSUM2SWS
/* 841 */     MCD_OPC_FilterValue, 28, 4, 0, // Skip to: 849
/* 845 */     MCD_OPC_Decode, 201, 8, 2, // Opcode: VSUM4SBS
/* 849 */     MCD_OPC_FilterValue, 30, 71, 33, // Skip to: 9372
/* 853 */     MCD_OPC_Decode, 204, 8, 2, // Opcode: VSUMSWS
/* 857 */     MCD_OPC_FilterValue, 10, 179, 0, // Skip to: 1040
/* 861 */     MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 864 */     MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 872
/* 868 */     MCD_OPC_Decode, 182, 7, 2, // Opcode: VADDFP
/* 872 */     MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 880
/* 876 */     MCD_OPC_Decode, 190, 8, 2, // Opcode: VSUBFP
/* 880 */     MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 894
/* 884 */     MCD_OPC_CheckField, 16, 5, 0, 34, 33, // Skip to: 9372
/* 890 */     MCD_OPC_Decode, 159, 8, 5, // Opcode: VREFP
/* 894 */     MCD_OPC_FilterValue, 5, 10, 0, // Skip to: 908
/* 898 */     MCD_OPC_CheckField, 16, 5, 0, 20, 33, // Skip to: 9372
/* 904 */     MCD_OPC_Decode, 167, 8, 5, // Opcode: VRSQRTEFP
/* 908 */     MCD_OPC_FilterValue, 6, 10, 0, // Skip to: 922
/* 912 */     MCD_OPC_CheckField, 16, 5, 0, 6, 33, // Skip to: 9372
/* 918 */     MCD_OPC_Decode, 234, 7, 5, // Opcode: VEXPTEFP
/* 922 */     MCD_OPC_FilterValue, 7, 10, 0, // Skip to: 936
/* 926 */     MCD_OPC_CheckField, 16, 5, 0, 248, 32, // Skip to: 9372
/* 932 */     MCD_OPC_Decode, 235, 7, 5, // Opcode: VLOGEFP
/* 936 */     MCD_OPC_FilterValue, 8, 10, 0, // Skip to: 950
/* 940 */     MCD_OPC_CheckField, 16, 5, 0, 234, 32, // Skip to: 9372
/* 946 */     MCD_OPC_Decode, 161, 8, 5, // Opcode: VRFIN
/* 950 */     MCD_OPC_FilterValue, 9, 10, 0, // Skip to: 964
/* 954 */     MCD_OPC_CheckField, 16, 5, 0, 220, 32, // Skip to: 9372
/* 960 */     MCD_OPC_Decode, 163, 8, 5, // Opcode: VRFIZ
/* 964 */     MCD_OPC_FilterValue, 10, 10, 0, // Skip to: 978
/* 968 */     MCD_OPC_CheckField, 16, 5, 0, 206, 32, // Skip to: 9372
/* 974 */     MCD_OPC_Decode, 162, 8, 5, // Opcode: VRFIP
/* 978 */     MCD_OPC_FilterValue, 11, 10, 0, // Skip to: 992
/* 982 */     MCD_OPC_CheckField, 16, 5, 0, 192, 32, // Skip to: 9372
/* 988 */     MCD_OPC_Decode, 160, 8, 5, // Opcode: VRFIM
/* 992 */     MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 1000
/* 996 */     MCD_OPC_Decode, 202, 7, 6, // Opcode: VCFUX
/* 1000 */    MCD_OPC_FilterValue, 13, 4, 0, // Skip to: 1008
/* 1004 */    MCD_OPC_Decode, 200, 7, 6, // Opcode: VCFSX
/* 1008 */    MCD_OPC_FilterValue, 14, 4, 0, // Skip to: 1016
/* 1012 */    MCD_OPC_Decode, 232, 7, 6, // Opcode: VCTUXS
/* 1016 */    MCD_OPC_FilterValue, 15, 4, 0, // Skip to: 1024
/* 1020 */    MCD_OPC_Decode, 230, 7, 6, // Opcode: VCTSXS
/* 1024 */    MCD_OPC_FilterValue, 16, 4, 0, // Skip to: 1032
/* 1028 */    MCD_OPC_Decode, 237, 7, 2, // Opcode: VMAXFP
/* 1032 */    MCD_OPC_FilterValue, 17, 144, 32, // Skip to: 9372
/* 1036 */    MCD_OPC_Decode, 246, 7, 2, // Opcode: VMINFP
/* 1040 */    MCD_OPC_FilterValue, 12, 133, 0, // Skip to: 1177
/* 1044 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 1047 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 1055
/* 1051 */    MCD_OPC_Decode, 254, 7, 2, // Opcode: VMRGHB
/* 1055 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 1063
/* 1059 */    MCD_OPC_Decode, 255, 7, 2, // Opcode: VMRGHH
/* 1063 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 1071
/* 1067 */    MCD_OPC_Decode, 128, 8, 2, // Opcode: VMRGHW
/* 1071 */    MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 1079
/* 1075 */    MCD_OPC_Decode, 129, 8, 2, // Opcode: VMRGLB
/* 1079 */    MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 1087
/* 1083 */    MCD_OPC_Decode, 130, 8, 2, // Opcode: VMRGLH
/* 1087 */    MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 1095
/* 1091 */    MCD_OPC_Decode, 131, 8, 2, // Opcode: VMRGLW
/* 1095 */    MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 1103
/* 1099 */    MCD_OPC_Decode, 175, 8, 6, // Opcode: VSPLTB
/* 1103 */    MCD_OPC_FilterValue, 9, 4, 0, // Skip to: 1111
/* 1107 */    MCD_OPC_Decode, 176, 8, 6, // Opcode: VSPLTH
/* 1111 */    MCD_OPC_FilterValue, 10, 4, 0, // Skip to: 1119
/* 1115 */    MCD_OPC_Decode, 180, 8, 6, // Opcode: VSPLTW
/* 1119 */    MCD_OPC_FilterValue, 12, 10, 0, // Skip to: 1133
/* 1123 */    MCD_OPC_CheckField, 11, 5, 0, 51, 32, // Skip to: 9372
/* 1129 */    MCD_OPC_Decode, 177, 8, 7, // Opcode: VSPLTISB
/* 1133 */    MCD_OPC_FilterValue, 13, 10, 0, // Skip to: 1147
/* 1137 */    MCD_OPC_CheckField, 11, 5, 0, 37, 32, // Skip to: 9372
/* 1143 */    MCD_OPC_Decode, 178, 8, 7, // Opcode: VSPLTISH
/* 1147 */    MCD_OPC_FilterValue, 14, 10, 0, // Skip to: 1161
/* 1151 */    MCD_OPC_CheckField, 11, 5, 0, 23, 32, // Skip to: 9372
/* 1157 */    MCD_OPC_Decode, 179, 8, 7, // Opcode: VSPLTISW
/* 1161 */    MCD_OPC_FilterValue, 16, 4, 0, // Skip to: 1169
/* 1165 */    MCD_OPC_Decode, 173, 8, 2, // Opcode: VSLO
/* 1169 */    MCD_OPC_FilterValue, 17, 7, 32, // Skip to: 9372
/* 1173 */    MCD_OPC_Decode, 187, 8, 2, // Opcode: VSRO
/* 1177 */    MCD_OPC_FilterValue, 14, 159, 0, // Skip to: 1340
/* 1181 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 1184 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 1192
/* 1188 */    MCD_OPC_Decode, 155, 8, 2, // Opcode: VPKUHUM
/* 1192 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 1200
/* 1196 */    MCD_OPC_Decode, 157, 8, 2, // Opcode: VPKUWUM
/* 1200 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 1208
/* 1204 */    MCD_OPC_Decode, 156, 8, 2, // Opcode: VPKUHUS
/* 1208 */    MCD_OPC_FilterValue, 3, 4, 0, // Skip to: 1216
/* 1212 */    MCD_OPC_Decode, 158, 8, 2, // Opcode: VPKUWUS
/* 1216 */    MCD_OPC_FilterValue, 4, 4, 0, // Skip to: 1224
/* 1220 */    MCD_OPC_Decode, 152, 8, 2, // Opcode: VPKSHUS
/* 1224 */    MCD_OPC_FilterValue, 5, 4, 0, // Skip to: 1232
/* 1228 */    MCD_OPC_Decode, 154, 8, 2, // Opcode: VPKSWUS
/* 1232 */    MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 1240
/* 1236 */    MCD_OPC_Decode, 151, 8, 2, // Opcode: VPKSHSS
/* 1240 */    MCD_OPC_FilterValue, 7, 4, 0, // Skip to: 1248
/* 1244 */    MCD_OPC_Decode, 153, 8, 2, // Opcode: VPKSWSS
/* 1248 */    MCD_OPC_FilterValue, 8, 10, 0, // Skip to: 1262
/* 1252 */    MCD_OPC_CheckField, 16, 5, 0, 178, 31, // Skip to: 9372
/* 1258 */    MCD_OPC_Decode, 206, 8, 5, // Opcode: VUPKHSB
/* 1262 */    MCD_OPC_FilterValue, 9, 10, 0, // Skip to: 1276
/* 1266 */    MCD_OPC_CheckField, 16, 5, 0, 164, 31, // Skip to: 9372
/* 1272 */    MCD_OPC_Decode, 207, 8, 5, // Opcode: VUPKHSH
/* 1276 */    MCD_OPC_FilterValue, 10, 10, 0, // Skip to: 1290
/* 1280 */    MCD_OPC_CheckField, 16, 5, 0, 150, 31, // Skip to: 9372
/* 1286 */    MCD_OPC_Decode, 209, 8, 5, // Opcode: VUPKLSB
/* 1290 */    MCD_OPC_FilterValue, 11, 10, 0, // Skip to: 1304
/* 1294 */    MCD_OPC_CheckField, 16, 5, 0, 136, 31, // Skip to: 9372
/* 1300 */    MCD_OPC_Decode, 210, 8, 5, // Opcode: VUPKLSH
/* 1304 */    MCD_OPC_FilterValue, 12, 4, 0, // Skip to: 1312
/* 1308 */    MCD_OPC_Decode, 150, 8, 2, // Opcode: VPKPX
/* 1312 */    MCD_OPC_FilterValue, 13, 10, 0, // Skip to: 1326
/* 1316 */    MCD_OPC_CheckField, 16, 5, 0, 114, 31, // Skip to: 9372
/* 1322 */    MCD_OPC_Decode, 205, 8, 5, // Opcode: VUPKHPX
/* 1326 */    MCD_OPC_FilterValue, 15, 106, 31, // Skip to: 9372
/* 1330 */    MCD_OPC_CheckField, 16, 5, 0, 100, 31, // Skip to: 9372
/* 1336 */    MCD_OPC_Decode, 208, 8, 5, // Opcode: VUPKLPX
/* 1340 */    MCD_OPC_FilterValue, 32, 4, 0, // Skip to: 1348
/* 1344 */    MCD_OPC_Decode, 244, 7, 8, // Opcode: VMHADDSHS
/* 1348 */    MCD_OPC_FilterValue, 33, 4, 0, // Skip to: 1356
/* 1352 */    MCD_OPC_Decode, 245, 7, 8, // Opcode: VMHRADDSHS
/* 1356 */    MCD_OPC_FilterValue, 34, 4, 0, // Skip to: 1364
/* 1360 */    MCD_OPC_Decode, 253, 7, 8, // Opcode: VMLADDUHM
/* 1364 */    MCD_OPC_FilterValue, 36, 4, 0, // Skip to: 1372
/* 1368 */    MCD_OPC_Decode, 135, 8, 8, // Opcode: VMSUMUBM
/* 1372 */    MCD_OPC_FilterValue, 37, 4, 0, // Skip to: 1380
/* 1376 */    MCD_OPC_Decode, 132, 8, 8, // Opcode: VMSUMMBM
/* 1380 */    MCD_OPC_FilterValue, 38, 4, 0, // Skip to: 1388
/* 1384 */    MCD_OPC_Decode, 136, 8, 8, // Opcode: VMSUMUHM
/* 1388 */    MCD_OPC_FilterValue, 39, 4, 0, // Skip to: 1396
/* 1392 */    MCD_OPC_Decode, 137, 8, 8, // Opcode: VMSUMUHS
/* 1396 */    MCD_OPC_FilterValue, 40, 4, 0, // Skip to: 1404
/* 1400 */    MCD_OPC_Decode, 133, 8, 8, // Opcode: VMSUMSHM
/* 1404 */    MCD_OPC_FilterValue, 41, 4, 0, // Skip to: 1412
/* 1408 */    MCD_OPC_Decode, 134, 8, 8, // Opcode: VMSUMSHS
/* 1412 */    MCD_OPC_FilterValue, 42, 4, 0, // Skip to: 1420
/* 1416 */    MCD_OPC_Decode, 168, 8, 8, // Opcode: VSEL
/* 1420 */    MCD_OPC_FilterValue, 43, 4, 0, // Skip to: 1428
/* 1424 */    MCD_OPC_Decode, 149, 8, 8, // Opcode: VPERM
/* 1428 */    MCD_OPC_FilterValue, 44, 10, 0, // Skip to: 1442
/* 1432 */    MCD_OPC_CheckField, 10, 1, 0, 254, 30, // Skip to: 9372
/* 1438 */    MCD_OPC_Decode, 171, 8, 9, // Opcode: VSLDOI
/* 1442 */    MCD_OPC_FilterValue, 46, 4, 0, // Skip to: 1450
/* 1446 */    MCD_OPC_Decode, 236, 7, 10, // Opcode: VMADDFP
/* 1450 */    MCD_OPC_FilterValue, 47, 238, 30, // Skip to: 9372
/* 1454 */    MCD_OPC_Decode, 146, 8, 10, // Opcode: VNMSUBFP
/* 1458 */    MCD_OPC_FilterValue, 7, 4, 0, // Skip to: 1466
/* 1462 */    MCD_OPC_Decode, 211, 5, 11, // Opcode: MULLI
/* 1466 */    MCD_OPC_FilterValue, 8, 4, 0, // Skip to: 1474
/* 1470 */    MCD_OPC_Decode, 132, 7, 11, // Opcode: SUBFIC
/* 1474 */    MCD_OPC_FilterValue, 10, 19, 0, // Skip to: 1497
/* 1478 */    MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 1481 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 1489
/* 1485 */    MCD_OPC_Decode, 212, 1, 12, // Opcode: CMPLWI
/* 1489 */    MCD_OPC_FilterValue, 1, 199, 30, // Skip to: 9372
/* 1493 */    MCD_OPC_Decode, 210, 1, 13, // Opcode: CMPLDI
/* 1497 */    MCD_OPC_FilterValue, 11, 19, 0, // Skip to: 1520
/* 1501 */    MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 1504 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 1512
/* 1508 */    MCD_OPC_Decode, 214, 1, 14, // Opcode: CMPWI
/* 1512 */    MCD_OPC_FilterValue, 1, 176, 30, // Skip to: 9372
/* 1516 */    MCD_OPC_Decode, 208, 1, 15, // Opcode: CMPDI
/* 1520 */    MCD_OPC_FilterValue, 12, 3, 0, // Skip to: 1527
/* 1524 */    MCD_OPC_Decode, 37, 11, // Opcode: ADDIC
/* 1527 */    MCD_OPC_FilterValue, 13, 3, 0, // Skip to: 1534
/* 1531 */    MCD_OPC_Decode, 39, 11, // Opcode: ADDICo
/* 1534 */    MCD_OPC_FilterValue, 14, 13, 0, // Skip to: 1551
/* 1538 */    MCD_OPC_CheckField, 16, 5, 0, 4, 0, // Skip to: 1548
/* 1544 */    MCD_OPC_Decode, 252, 4, 16, // Opcode: LI
/* 1548 */    MCD_OPC_Decode, 35, 17, // Opcode: ADDI
/* 1551 */    MCD_OPC_FilterValue, 15, 13, 0, // Skip to: 1568
/* 1555 */    MCD_OPC_CheckField, 16, 5, 0, 4, 0, // Skip to: 1565
/* 1561 */    MCD_OPC_Decode, 254, 4, 16, // Opcode: LIS
/* 1565 */    MCD_OPC_Decode, 40, 17, // Opcode: ADDIS
/* 1568 */    MCD_OPC_FilterValue, 16, 7, 1, // Skip to: 1835
/* 1572 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 1575 */    MCD_OPC_FilterValue, 0, 61, 0, // Skip to: 1640
/* 1579 */    MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 1582 */    MCD_OPC_FilterValue, 128, 4, 4, 0, // Skip to: 1591
/* 1587 */    MCD_OPC_Decode, 146, 1, 18, // Opcode: BDNZ
/* 1591 */    MCD_OPC_FilterValue, 192, 4, 4, 0, // Skip to: 1600
/* 1596 */    MCD_OPC_Decode, 166, 1, 18, // Opcode: BDZ
/* 1600 */    MCD_OPC_FilterValue, 128, 6, 4, 0, // Skip to: 1609
/* 1605 */    MCD_OPC_Decode, 164, 1, 18, // Opcode: BDNZm
/* 1609 */    MCD_OPC_FilterValue, 160, 6, 4, 0, // Skip to: 1618
/* 1614 */    MCD_OPC_Decode, 165, 1, 18, // Opcode: BDNZp
/* 1618 */    MCD_OPC_FilterValue, 192, 6, 4, 0, // Skip to: 1627
/* 1623 */    MCD_OPC_Decode, 184, 1, 18, // Opcode: BDZm
/* 1627 */    MCD_OPC_FilterValue, 224, 6, 4, 0, // Skip to: 1636
/* 1632 */    MCD_OPC_Decode, 185, 1, 18, // Opcode: BDZp
/* 1636 */    MCD_OPC_Decode, 237, 9, 19, // Opcode: gBC
/* 1640 */    MCD_OPC_FilterValue, 1, 61, 0, // Skip to: 1705
/* 1644 */    MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 1647 */    MCD_OPC_FilterValue, 128, 4, 4, 0, // Skip to: 1656
/* 1652 */    MCD_OPC_Decode, 151, 1, 18, // Opcode: BDNZL
/* 1656 */    MCD_OPC_FilterValue, 192, 4, 4, 0, // Skip to: 1665
/* 1661 */    MCD_OPC_Decode, 171, 1, 18, // Opcode: BDZL
/* 1665 */    MCD_OPC_FilterValue, 128, 6, 4, 0, // Skip to: 1674
/* 1670 */    MCD_OPC_Decode, 162, 1, 18, // Opcode: BDNZLm
/* 1674 */    MCD_OPC_FilterValue, 160, 6, 4, 0, // Skip to: 1683
/* 1679 */    MCD_OPC_Decode, 163, 1, 18, // Opcode: BDNZLp
/* 1683 */    MCD_OPC_FilterValue, 192, 6, 4, 0, // Skip to: 1692
/* 1688 */    MCD_OPC_Decode, 182, 1, 18, // Opcode: BDZLm
/* 1692 */    MCD_OPC_FilterValue, 224, 6, 4, 0, // Skip to: 1701
/* 1697 */    MCD_OPC_Decode, 183, 1, 18, // Opcode: BDZLp
/* 1701 */    MCD_OPC_Decode, 241, 9, 19, // Opcode: gBCL
/* 1705 */    MCD_OPC_FilterValue, 2, 61, 0, // Skip to: 1770
/* 1709 */    MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 1712 */    MCD_OPC_FilterValue, 128, 4, 4, 0, // Skip to: 1721
/* 1717 */    MCD_OPC_Decode, 148, 1, 18, // Opcode: BDNZA
/* 1721 */    MCD_OPC_FilterValue, 192, 4, 4, 0, // Skip to: 1730
/* 1726 */    MCD_OPC_Decode, 168, 1, 18, // Opcode: BDZA
/* 1730 */    MCD_OPC_FilterValue, 128, 6, 4, 0, // Skip to: 1739
/* 1735 */    MCD_OPC_Decode, 149, 1, 18, // Opcode: BDNZAm
/* 1739 */    MCD_OPC_FilterValue, 160, 6, 4, 0, // Skip to: 1748
/* 1744 */    MCD_OPC_Decode, 150, 1, 18, // Opcode: BDNZAp
/* 1748 */    MCD_OPC_FilterValue, 192, 6, 4, 0, // Skip to: 1757
/* 1753 */    MCD_OPC_Decode, 169, 1, 18, // Opcode: BDZAm
/* 1757 */    MCD_OPC_FilterValue, 224, 6, 4, 0, // Skip to: 1766
/* 1762 */    MCD_OPC_Decode, 170, 1, 18, // Opcode: BDZAp
/* 1766 */    MCD_OPC_Decode, 238, 9, 19, // Opcode: gBCA
/* 1770 */    MCD_OPC_FilterValue, 3, 174, 29, // Skip to: 9372
/* 1774 */    MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 1777 */    MCD_OPC_FilterValue, 128, 4, 4, 0, // Skip to: 1786
/* 1782 */    MCD_OPC_Decode, 152, 1, 18, // Opcode: BDNZLA
/* 1786 */    MCD_OPC_FilterValue, 192, 4, 4, 0, // Skip to: 1795
/* 1791 */    MCD_OPC_Decode, 172, 1, 18, // Opcode: BDZLA
/* 1795 */    MCD_OPC_FilterValue, 128, 6, 4, 0, // Skip to: 1804
/* 1800 */    MCD_OPC_Decode, 153, 1, 18, // Opcode: BDNZLAm
/* 1804 */    MCD_OPC_FilterValue, 160, 6, 4, 0, // Skip to: 1813
/* 1809 */    MCD_OPC_Decode, 154, 1, 18, // Opcode: BDNZLAp
/* 1813 */    MCD_OPC_FilterValue, 192, 6, 4, 0, // Skip to: 1822
/* 1818 */    MCD_OPC_Decode, 173, 1, 18, // Opcode: BDZLAm
/* 1822 */    MCD_OPC_FilterValue, 224, 6, 4, 0, // Skip to: 1831
/* 1827 */    MCD_OPC_Decode, 174, 1, 18, // Opcode: BDZLAp
/* 1831 */    MCD_OPC_Decode, 242, 9, 19, // Opcode: gBCLA
/* 1835 */    MCD_OPC_FilterValue, 17, 10, 0, // Skip to: 1849
/* 1839 */    MCD_OPC_CheckField, 1, 1, 1, 103, 29, // Skip to: 9372
/* 1845 */    MCD_OPC_Decode, 155, 6, 20, // Opcode: SC
/* 1849 */    MCD_OPC_FilterValue, 18, 33, 0, // Skip to: 1886
/* 1853 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 1856 */    MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 1863
/* 1860 */    MCD_OPC_Decode, 113, 21, // Opcode: B
/* 1863 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 1871
/* 1867 */    MCD_OPC_Decode, 186, 1, 21, // Opcode: BL
/* 1871 */    MCD_OPC_FilterValue, 2, 3, 0, // Skip to: 1878
/* 1875 */    MCD_OPC_Decode, 114, 21, // Opcode: BA
/* 1878 */    MCD_OPC_FilterValue, 3, 66, 29, // Skip to: 9372
/* 1882 */    MCD_OPC_Decode, 192, 1, 21, // Opcode: BLA
/* 1886 */    MCD_OPC_FilterValue, 19, 235, 1, // Skip to: 2381
/* 1890 */    MCD_OPC_ExtractField, 0, 11,  // Inst{10-0} ...
/* 1893 */    MCD_OPC_FilterValue, 0, 16, 0, // Skip to: 1913
/* 1897 */    MCD_OPC_CheckField, 21, 2, 0, 45, 29, // Skip to: 9372
/* 1903 */    MCD_OPC_CheckField, 11, 7, 0, 39, 29, // Skip to: 9372
/* 1909 */    MCD_OPC_Decode, 158, 5, 22, // Opcode: MCRF
/* 1913 */    MCD_OPC_FilterValue, 32, 119, 0, // Skip to: 2036
/* 1917 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 1920 */    MCD_OPC_FilterValue, 0, 24, 29, // Skip to: 9372
/* 1924 */    MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 1927 */    MCD_OPC_FilterValue, 128, 4, 10, 0, // Skip to: 1942
/* 1932 */    MCD_OPC_CheckField, 11, 2, 0, 94, 0, // Skip to: 2032
/* 1938 */    MCD_OPC_Decode, 155, 1, 23, // Opcode: BDNZLR
/* 1942 */    MCD_OPC_FilterValue, 192, 4, 10, 0, // Skip to: 1957
/* 1947 */    MCD_OPC_CheckField, 11, 2, 0, 79, 0, // Skip to: 2032
/* 1953 */    MCD_OPC_Decode, 175, 1, 23, // Opcode: BDZLR
/* 1957 */    MCD_OPC_FilterValue, 128, 5, 10, 0, // Skip to: 1972
/* 1962 */    MCD_OPC_CheckField, 11, 2, 0, 64, 0, // Skip to: 2032
/* 1968 */    MCD_OPC_Decode, 195, 1, 23, // Opcode: BLR
/* 1972 */    MCD_OPC_FilterValue, 128, 6, 10, 0, // Skip to: 1987
/* 1977 */    MCD_OPC_CheckField, 11, 2, 0, 49, 0, // Skip to: 2032
/* 1983 */    MCD_OPC_Decode, 160, 1, 23, // Opcode: BDNZLRm
/* 1987 */    MCD_OPC_FilterValue, 160, 6, 10, 0, // Skip to: 2002
/* 1992 */    MCD_OPC_CheckField, 11, 2, 0, 34, 0, // Skip to: 2032
/* 1998 */    MCD_OPC_Decode, 161, 1, 23, // Opcode: BDNZLRp
/* 2002 */    MCD_OPC_FilterValue, 192, 6, 10, 0, // Skip to: 2017
/* 2007 */    MCD_OPC_CheckField, 11, 2, 0, 19, 0, // Skip to: 2032
/* 2013 */    MCD_OPC_Decode, 180, 1, 23, // Opcode: BDZLRm
/* 2017 */    MCD_OPC_FilterValue, 224, 6, 10, 0, // Skip to: 2032
/* 2022 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 2032
/* 2028 */    MCD_OPC_Decode, 181, 1, 23, // Opcode: BDZLRp
/* 2032 */    MCD_OPC_Decode, 243, 9, 24, // Opcode: gBCLR
/* 2036 */    MCD_OPC_FilterValue, 33, 119, 0, // Skip to: 2159
/* 2040 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 2043 */    MCD_OPC_FilterValue, 0, 157, 28, // Skip to: 9372
/* 2047 */    MCD_OPC_ExtractField, 16, 10,  // Inst{25-16} ...
/* 2050 */    MCD_OPC_FilterValue, 128, 4, 10, 0, // Skip to: 2065
/* 2055 */    MCD_OPC_CheckField, 11, 2, 0, 94, 0, // Skip to: 2155
/* 2061 */    MCD_OPC_Decode, 157, 1, 23, // Opcode: BDNZLRL
/* 2065 */    MCD_OPC_FilterValue, 192, 4, 10, 0, // Skip to: 2080
/* 2070 */    MCD_OPC_CheckField, 11, 2, 0, 79, 0, // Skip to: 2155
/* 2076 */    MCD_OPC_Decode, 177, 1, 23, // Opcode: BDZLRL
/* 2080 */    MCD_OPC_FilterValue, 128, 5, 10, 0, // Skip to: 2095
/* 2085 */    MCD_OPC_CheckField, 11, 2, 0, 64, 0, // Skip to: 2155
/* 2091 */    MCD_OPC_Decode, 196, 1, 23, // Opcode: BLRL
/* 2095 */    MCD_OPC_FilterValue, 128, 6, 10, 0, // Skip to: 2110
/* 2100 */    MCD_OPC_CheckField, 11, 2, 0, 49, 0, // Skip to: 2155
/* 2106 */    MCD_OPC_Decode, 158, 1, 23, // Opcode: BDNZLRLm
/* 2110 */    MCD_OPC_FilterValue, 160, 6, 10, 0, // Skip to: 2125
/* 2115 */    MCD_OPC_CheckField, 11, 2, 0, 34, 0, // Skip to: 2155
/* 2121 */    MCD_OPC_Decode, 159, 1, 23, // Opcode: BDNZLRLp
/* 2125 */    MCD_OPC_FilterValue, 192, 6, 10, 0, // Skip to: 2140
/* 2130 */    MCD_OPC_CheckField, 11, 2, 0, 19, 0, // Skip to: 2155
/* 2136 */    MCD_OPC_Decode, 178, 1, 23, // Opcode: BDZLRLm
/* 2140 */    MCD_OPC_FilterValue, 224, 6, 10, 0, // Skip to: 2155
/* 2145 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 2155
/* 2151 */    MCD_OPC_Decode, 179, 1, 23, // Opcode: BDZLRLp
/* 2155 */    MCD_OPC_Decode, 244, 9, 24, // Opcode: gBCLRL
/* 2159 */    MCD_OPC_FilterValue, 36, 10, 0, // Skip to: 2173
/* 2163 */    MCD_OPC_CheckField, 11, 15, 0, 35, 28, // Skip to: 9372
/* 2169 */    MCD_OPC_Decode, 254, 5, 23, // Opcode: RFID
/* 2173 */    MCD_OPC_FilterValue, 66, 4, 0, // Skip to: 2181
/* 2177 */    MCD_OPC_Decode, 225, 1, 25, // Opcode: CRNOR
/* 2181 */    MCD_OPC_FilterValue, 76, 10, 0, // Skip to: 2195
/* 2185 */    MCD_OPC_CheckField, 11, 15, 0, 13, 28, // Skip to: 9372
/* 2191 */    MCD_OPC_Decode, 255, 5, 23, // Opcode: RFMCI
/* 2195 */    MCD_OPC_FilterValue, 78, 10, 0, // Skip to: 2209
/* 2199 */    MCD_OPC_CheckField, 11, 15, 0, 255, 27, // Skip to: 9372
/* 2205 */    MCD_OPC_Decode, 252, 5, 23, // Opcode: RFDI
/* 2209 */    MCD_OPC_FilterValue, 100, 10, 0, // Skip to: 2223
/* 2213 */    MCD_OPC_CheckField, 11, 15, 0, 241, 27, // Skip to: 9372
/* 2219 */    MCD_OPC_Decode, 253, 5, 23, // Opcode: RFI
/* 2223 */    MCD_OPC_FilterValue, 102, 10, 0, // Skip to: 2237
/* 2227 */    MCD_OPC_CheckField, 11, 15, 0, 227, 27, // Skip to: 9372
/* 2233 */    MCD_OPC_Decode, 251, 5, 23, // Opcode: RFCI
/* 2237 */    MCD_OPC_FilterValue, 130, 2, 4, 0, // Skip to: 2246
/* 2242 */    MCD_OPC_Decode, 222, 1, 25, // Opcode: CRANDC
/* 2246 */    MCD_OPC_FilterValue, 172, 2, 10, 0, // Skip to: 2261
/* 2251 */    MCD_OPC_CheckField, 11, 15, 0, 203, 27, // Skip to: 9372
/* 2257 */    MCD_OPC_Decode, 201, 4, 23, // Opcode: ISYNC
/* 2261 */    MCD_OPC_FilterValue, 130, 3, 4, 0, // Skip to: 2270
/* 2266 */    MCD_OPC_Decode, 230, 1, 25, // Opcode: CRXOR
/* 2270 */    MCD_OPC_FilterValue, 194, 3, 4, 0, // Skip to: 2279
/* 2275 */    MCD_OPC_Decode, 224, 1, 25, // Opcode: CRNAND
/* 2279 */    MCD_OPC_FilterValue, 130, 4, 4, 0, // Skip to: 2288
/* 2284 */    MCD_OPC_Decode, 221, 1, 25, // Opcode: CRAND
/* 2288 */    MCD_OPC_FilterValue, 194, 4, 4, 0, // Skip to: 2297
/* 2293 */    MCD_OPC_Decode, 223, 1, 25, // Opcode: CREQV
/* 2297 */    MCD_OPC_FilterValue, 194, 6, 4, 0, // Skip to: 2306
/* 2302 */    MCD_OPC_Decode, 227, 1, 25, // Opcode: CRORC
/* 2306 */    MCD_OPC_FilterValue, 130, 7, 4, 0, // Skip to: 2315
/* 2311 */    MCD_OPC_Decode, 226, 1, 25, // Opcode: CROR
/* 2315 */    MCD_OPC_FilterValue, 160, 8, 28, 0, // Skip to: 2348
/* 2320 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 2323 */    MCD_OPC_FilterValue, 0, 133, 27, // Skip to: 9372
/* 2327 */    MCD_OPC_CheckField, 16, 10, 128, 5, 10, 0, // Skip to: 2344
/* 2334 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 2344
/* 2340 */    MCD_OPC_Decode, 141, 1, 23, // Opcode: BCTR
/* 2344 */    MCD_OPC_Decode, 239, 9, 24, // Opcode: gBCCTR
/* 2348 */    MCD_OPC_FilterValue, 161, 8, 107, 27, // Skip to: 9372
/* 2353 */    MCD_OPC_ExtractField, 13, 3,  // Inst{15-13} ...
/* 2356 */    MCD_OPC_FilterValue, 0, 100, 27, // Skip to: 9372
/* 2360 */    MCD_OPC_CheckField, 16, 10, 128, 5, 10, 0, // Skip to: 2377
/* 2367 */    MCD_OPC_CheckField, 11, 2, 0, 4, 0, // Skip to: 2377
/* 2373 */    MCD_OPC_Decode, 143, 1, 23, // Opcode: BCTRL
/* 2377 */    MCD_OPC_Decode, 240, 9, 24, // Opcode: gBCCTRL
/* 2381 */    MCD_OPC_FilterValue, 20, 19, 0, // Skip to: 2404
/* 2385 */    MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 2388 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2396
/* 2392 */    MCD_OPC_Decode, 141, 6, 26, // Opcode: RLWIMI
/* 2396 */    MCD_OPC_FilterValue, 1, 60, 27, // Skip to: 9372
/* 2400 */    MCD_OPC_Decode, 144, 6, 26, // Opcode: RLWIMIo
/* 2404 */    MCD_OPC_FilterValue, 21, 19, 0, // Skip to: 2427
/* 2408 */    MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 2411 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2419
/* 2415 */    MCD_OPC_Decode, 145, 6, 27, // Opcode: RLWINM
/* 2419 */    MCD_OPC_FilterValue, 1, 37, 27, // Skip to: 9372
/* 2423 */    MCD_OPC_Decode, 148, 6, 27, // Opcode: RLWINMo
/* 2427 */    MCD_OPC_FilterValue, 23, 19, 0, // Skip to: 2450
/* 2431 */    MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 2434 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2442
/* 2438 */    MCD_OPC_Decode, 149, 6, 28, // Opcode: RLWNM
/* 2442 */    MCD_OPC_FilterValue, 1, 14, 27, // Skip to: 9372
/* 2446 */    MCD_OPC_Decode, 150, 6, 28, // Opcode: RLWNMo
/* 2450 */    MCD_OPC_FilterValue, 24, 14, 0, // Skip to: 2468
/* 2454 */    MCD_OPC_CheckField, 0, 26, 0, 4, 0, // Skip to: 2464
/* 2460 */    MCD_OPC_Decode, 225, 5, 23, // Opcode: NOP
/* 2464 */    MCD_OPC_Decode, 239, 5, 29, // Opcode: ORI
/* 2468 */    MCD_OPC_FilterValue, 25, 4, 0, // Skip to: 2476
/* 2472 */    MCD_OPC_Decode, 241, 5, 29, // Opcode: ORIS
/* 2476 */    MCD_OPC_FilterValue, 26, 4, 0, // Skip to: 2484
/* 2480 */    MCD_OPC_Decode, 224, 8, 29, // Opcode: XORI
/* 2484 */    MCD_OPC_FilterValue, 27, 4, 0, // Skip to: 2492
/* 2488 */    MCD_OPC_Decode, 226, 8, 29, // Opcode: XORIS
/* 2492 */    MCD_OPC_FilterValue, 28, 3, 0, // Skip to: 2499
/* 2496 */    MCD_OPC_Decode, 74, 29, // Opcode: ANDIo
/* 2499 */    MCD_OPC_FilterValue, 29, 3, 0, // Skip to: 2506
/* 2503 */    MCD_OPC_Decode, 72, 29, // Opcode: ANDISo
/* 2506 */    MCD_OPC_FilterValue, 30, 134, 0, // Skip to: 2644
/* 2510 */    MCD_OPC_ExtractField, 2, 3,  // Inst{4-2} ...
/* 2513 */    MCD_OPC_FilterValue, 0, 19, 0, // Skip to: 2536
/* 2517 */    MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 2520 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2528
/* 2524 */    MCD_OPC_Decode, 133, 6, 30, // Opcode: RLDICL
/* 2528 */    MCD_OPC_FilterValue, 1, 184, 26, // Skip to: 9372
/* 2532 */    MCD_OPC_Decode, 135, 6, 30, // Opcode: RLDICLo
/* 2536 */    MCD_OPC_FilterValue, 1, 19, 0, // Skip to: 2559
/* 2540 */    MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 2543 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2551
/* 2547 */    MCD_OPC_Decode, 136, 6, 30, // Opcode: RLDICR
/* 2551 */    MCD_OPC_FilterValue, 1, 161, 26, // Skip to: 9372
/* 2555 */    MCD_OPC_Decode, 137, 6, 30, // Opcode: RLDICRo
/* 2559 */    MCD_OPC_FilterValue, 2, 19, 0, // Skip to: 2582
/* 2563 */    MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 2566 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2574
/* 2570 */    MCD_OPC_Decode, 132, 6, 30, // Opcode: RLDIC
/* 2574 */    MCD_OPC_FilterValue, 1, 138, 26, // Skip to: 9372
/* 2578 */    MCD_OPC_Decode, 138, 6, 30, // Opcode: RLDICo
/* 2582 */    MCD_OPC_FilterValue, 3, 19, 0, // Skip to: 2605
/* 2586 */    MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 2589 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2597
/* 2593 */    MCD_OPC_Decode, 139, 6, 31, // Opcode: RLDIMI
/* 2597 */    MCD_OPC_FilterValue, 1, 115, 26, // Skip to: 9372
/* 2601 */    MCD_OPC_Decode, 140, 6, 31, // Opcode: RLDIMIo
/* 2605 */    MCD_OPC_FilterValue, 4, 107, 26, // Skip to: 9372
/* 2609 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 2612 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2620
/* 2616 */    MCD_OPC_Decode, 128, 6, 32, // Opcode: RLDCL
/* 2620 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 2628
/* 2624 */    MCD_OPC_Decode, 129, 6, 32, // Opcode: RLDCLo
/* 2628 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 2636
/* 2632 */    MCD_OPC_Decode, 130, 6, 32, // Opcode: RLDCR
/* 2636 */    MCD_OPC_FilterValue, 3, 76, 26, // Skip to: 9372
/* 2640 */    MCD_OPC_Decode, 131, 6, 32, // Opcode: RLDCRo
/* 2644 */    MCD_OPC_FilterValue, 31, 38, 12, // Skip to: 5758
/* 2648 */    MCD_OPC_ExtractField, 2, 4,  // Inst{5-2} ...
/* 2651 */    MCD_OPC_FilterValue, 0, 73, 0, // Skip to: 2728
/* 2655 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 2658 */    MCD_OPC_FilterValue, 0, 31, 0, // Skip to: 2693
/* 2662 */    MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 2665 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 2679
/* 2669 */    MCD_OPC_CheckField, 0, 2, 0, 41, 26, // Skip to: 9372
/* 2675 */    MCD_OPC_Decode, 213, 1, 33, // Opcode: CMPW
/* 2679 */    MCD_OPC_FilterValue, 1, 33, 26, // Skip to: 9372
/* 2683 */    MCD_OPC_CheckField, 0, 2, 0, 27, 26, // Skip to: 9372
/* 2689 */    MCD_OPC_Decode, 207, 1, 34, // Opcode: CMPD
/* 2693 */    MCD_OPC_FilterValue, 1, 19, 26, // Skip to: 9372
/* 2697 */    MCD_OPC_ExtractField, 21, 2,  // Inst{22-21} ...
/* 2700 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 2714
/* 2704 */    MCD_OPC_CheckField, 0, 2, 0, 6, 26, // Skip to: 9372
/* 2710 */    MCD_OPC_Decode, 211, 1, 33, // Opcode: CMPLW
/* 2714 */    MCD_OPC_FilterValue, 1, 254, 25, // Skip to: 9372
/* 2718 */    MCD_OPC_CheckField, 0, 2, 0, 248, 25, // Skip to: 9372
/* 2724 */    MCD_OPC_Decode, 209, 1, 34, // Opcode: CMPLD
/* 2728 */    MCD_OPC_FilterValue, 1, 65, 0, // Skip to: 2797
/* 2732 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 2735 */    MCD_OPC_FilterValue, 4, 16, 0, // Skip to: 2755
/* 2739 */    MCD_OPC_CheckField, 16, 1, 0, 227, 25, // Skip to: 9372
/* 2745 */    MCD_OPC_CheckField, 1, 1, 1, 221, 25, // Skip to: 9372
/* 2751 */    MCD_OPC_Decode, 219, 8, 35, // Opcode: WRTEE
/* 2755 */    MCD_OPC_FilterValue, 5, 10, 0, // Skip to: 2769
/* 2759 */    MCD_OPC_CheckField, 1, 1, 1, 207, 25, // Skip to: 9372
/* 2765 */    MCD_OPC_Decode, 220, 8, 36, // Opcode: WRTEEI
/* 2769 */    MCD_OPC_FilterValue, 10, 10, 0, // Skip to: 2783
/* 2773 */    MCD_OPC_CheckField, 0, 2, 2, 193, 25, // Skip to: 9372
/* 2779 */    MCD_OPC_Decode, 163, 5, 37, // Opcode: MFDCR
/* 2783 */    MCD_OPC_FilterValue, 14, 185, 25, // Skip to: 9372
/* 2787 */    MCD_OPC_CheckField, 0, 2, 2, 179, 25, // Skip to: 9372
/* 2793 */    MCD_OPC_Decode, 185, 5, 37, // Opcode: MTDCR
/* 2797 */    MCD_OPC_FilterValue, 2, 44, 0, // Skip to: 2845
/* 2801 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 2804 */    MCD_OPC_FilterValue, 0, 23, 0, // Skip to: 2831
/* 2808 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 2811 */    MCD_OPC_FilterValue, 0, 157, 25, // Skip to: 9372
/* 2815 */    MCD_OPC_CheckField, 11, 15, 128, 248, 1, 4, 0, // Skip to: 2827
/* 2823 */    MCD_OPC_Decode, 176, 7, 23, // Opcode: TRAP
/* 2827 */    MCD_OPC_Decode, 177, 7, 38, // Opcode: TW
/* 2831 */    MCD_OPC_FilterValue, 2, 137, 25, // Skip to: 9372
/* 2835 */    MCD_OPC_CheckField, 0, 2, 0, 131, 25, // Skip to: 9372
/* 2841 */    MCD_OPC_Decode, 160, 7, 39, // Opcode: TD
/* 2845 */    MCD_OPC_FilterValue, 3, 201, 0, // Skip to: 3050
/* 2849 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 2852 */    MCD_OPC_FilterValue, 0, 19, 0, // Skip to: 2875
/* 2856 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 2859 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2867
/* 2863 */    MCD_OPC_Decode, 133, 5, 40, // Opcode: LVSL
/* 2867 */    MCD_OPC_FilterValue, 2, 101, 25, // Skip to: 9372
/* 2871 */    MCD_OPC_Decode, 130, 5, 40, // Opcode: LVEBX
/* 2875 */    MCD_OPC_FilterValue, 1, 19, 0, // Skip to: 2898
/* 2879 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 2882 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 2890
/* 2886 */    MCD_OPC_Decode, 134, 5, 40, // Opcode: LVSR
/* 2890 */    MCD_OPC_FilterValue, 2, 78, 25, // Skip to: 9372
/* 2894 */    MCD_OPC_Decode, 131, 5, 40, // Opcode: LVEHX
/* 2898 */    MCD_OPC_FilterValue, 2, 10, 0, // Skip to: 2912
/* 2902 */    MCD_OPC_CheckField, 0, 2, 2, 64, 25, // Skip to: 9372
/* 2908 */    MCD_OPC_Decode, 132, 5, 40, // Opcode: LVEWX
/* 2912 */    MCD_OPC_FilterValue, 3, 10, 0, // Skip to: 2926
/* 2916 */    MCD_OPC_CheckField, 0, 2, 2, 50, 25, // Skip to: 9372
/* 2922 */    MCD_OPC_Decode, 135, 5, 40, // Opcode: LVX
/* 2926 */    MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 2940
/* 2930 */    MCD_OPC_CheckField, 0, 2, 2, 36, 25, // Skip to: 9372
/* 2936 */    MCD_OPC_Decode, 231, 6, 40, // Opcode: STVEBX
/* 2940 */    MCD_OPC_FilterValue, 5, 10, 0, // Skip to: 2954
/* 2944 */    MCD_OPC_CheckField, 0, 2, 2, 22, 25, // Skip to: 9372
/* 2950 */    MCD_OPC_Decode, 232, 6, 40, // Opcode: STVEHX
/* 2954 */    MCD_OPC_FilterValue, 6, 10, 0, // Skip to: 2968
/* 2958 */    MCD_OPC_CheckField, 0, 2, 2, 8, 25, // Skip to: 9372
/* 2964 */    MCD_OPC_Decode, 233, 6, 40, // Opcode: STVEWX
/* 2968 */    MCD_OPC_FilterValue, 7, 10, 0, // Skip to: 2982
/* 2972 */    MCD_OPC_CheckField, 0, 2, 2, 250, 24, // Skip to: 9372
/* 2978 */    MCD_OPC_Decode, 234, 6, 40, // Opcode: STVX
/* 2982 */    MCD_OPC_FilterValue, 11, 10, 0, // Skip to: 2996
/* 2986 */    MCD_OPC_CheckField, 0, 2, 2, 236, 24, // Skip to: 9372
/* 2992 */    MCD_OPC_Decode, 136, 5, 40, // Opcode: LVXL
/* 2996 */    MCD_OPC_FilterValue, 14, 16, 0, // Skip to: 3016
/* 3000 */    MCD_OPC_CheckField, 21, 5, 0, 222, 24, // Skip to: 9372
/* 3006 */    MCD_OPC_CheckField, 0, 2, 0, 216, 24, // Skip to: 9372
/* 3012 */    MCD_OPC_Decode, 239, 1, 41, // Opcode: DCCCI
/* 3016 */    MCD_OPC_FilterValue, 15, 10, 0, // Skip to: 3030
/* 3020 */    MCD_OPC_CheckField, 0, 2, 2, 202, 24, // Skip to: 9372
/* 3026 */    MCD_OPC_Decode, 235, 6, 40, // Opcode: STVXL
/* 3030 */    MCD_OPC_FilterValue, 30, 194, 24, // Skip to: 9372
/* 3034 */    MCD_OPC_CheckField, 21, 5, 0, 188, 24, // Skip to: 9372
/* 3040 */    MCD_OPC_CheckField, 0, 2, 0, 182, 24, // Skip to: 9372
/* 3046 */    MCD_OPC_Decode, 192, 4, 41, // Opcode: ICCCI
/* 3050 */    MCD_OPC_FilterValue, 4, 22, 1, // Skip to: 3332
/* 3054 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 3057 */    MCD_OPC_FilterValue, 0, 35, 0, // Skip to: 3096
/* 3061 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3064 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 3072
/* 3068 */    MCD_OPC_Decode, 252, 6, 42, // Opcode: SUBFC
/* 3072 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 3080
/* 3076 */    MCD_OPC_Decode, 255, 6, 42, // Opcode: SUBFCo
/* 3080 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 3088
/* 3084 */    MCD_OPC_Decode, 202, 5, 43, // Opcode: MULHDU
/* 3088 */    MCD_OPC_FilterValue, 3, 136, 24, // Skip to: 9372
/* 3092 */    MCD_OPC_Decode, 203, 5, 43, // Opcode: MULHDUo
/* 3096 */    MCD_OPC_FilterValue, 1, 19, 0, // Skip to: 3119
/* 3100 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3103 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 3111
/* 3107 */    MCD_OPC_Decode, 249, 6, 42, // Opcode: SUBF
/* 3111 */    MCD_OPC_FilterValue, 1, 113, 24, // Skip to: 9372
/* 3115 */    MCD_OPC_Decode, 142, 7, 42, // Opcode: SUBFo
/* 3119 */    MCD_OPC_FilterValue, 2, 19, 0, // Skip to: 3142
/* 3123 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3126 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 3134
/* 3130 */    MCD_OPC_Decode, 201, 5, 43, // Opcode: MULHD
/* 3134 */    MCD_OPC_FilterValue, 3, 90, 24, // Skip to: 9372
/* 3138 */    MCD_OPC_Decode, 204, 5, 43, // Opcode: MULHDo
/* 3142 */    MCD_OPC_FilterValue, 3, 31, 0, // Skip to: 3177
/* 3146 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3149 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 3163
/* 3153 */    MCD_OPC_CheckField, 11, 5, 0, 69, 24, // Skip to: 9372
/* 3159 */    MCD_OPC_Decode, 221, 5, 44, // Opcode: NEG
/* 3163 */    MCD_OPC_FilterValue, 1, 61, 24, // Skip to: 9372
/* 3167 */    MCD_OPC_CheckField, 11, 5, 0, 55, 24, // Skip to: 9372
/* 3173 */    MCD_OPC_Decode, 224, 5, 44, // Opcode: NEGo
/* 3177 */    MCD_OPC_FilterValue, 4, 19, 0, // Skip to: 3200
/* 3181 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3184 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 3192
/* 3188 */    MCD_OPC_Decode, 128, 7, 42, // Opcode: SUBFE
/* 3192 */    MCD_OPC_FilterValue, 1, 32, 24, // Skip to: 9372
/* 3196 */    MCD_OPC_Decode, 131, 7, 42, // Opcode: SUBFEo
/* 3200 */    MCD_OPC_FilterValue, 6, 31, 0, // Skip to: 3235
/* 3204 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3207 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 3221
/* 3211 */    MCD_OPC_CheckField, 11, 5, 0, 11, 24, // Skip to: 9372
/* 3217 */    MCD_OPC_Decode, 138, 7, 44, // Opcode: SUBFZE
/* 3221 */    MCD_OPC_FilterValue, 1, 3, 24, // Skip to: 9372
/* 3225 */    MCD_OPC_CheckField, 11, 5, 0, 253, 23, // Skip to: 9372
/* 3231 */    MCD_OPC_Decode, 141, 7, 44, // Opcode: SUBFZEo
/* 3235 */    MCD_OPC_FilterValue, 7, 47, 0, // Skip to: 3286
/* 3239 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3242 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 3256
/* 3246 */    MCD_OPC_CheckField, 11, 5, 0, 232, 23, // Skip to: 9372
/* 3252 */    MCD_OPC_Decode, 134, 7, 44, // Opcode: SUBFME
/* 3256 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 3270
/* 3260 */    MCD_OPC_CheckField, 11, 5, 0, 218, 23, // Skip to: 9372
/* 3266 */    MCD_OPC_Decode, 137, 7, 44, // Opcode: SUBFMEo
/* 3270 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 3278
/* 3274 */    MCD_OPC_Decode, 209, 5, 43, // Opcode: MULLD
/* 3278 */    MCD_OPC_FilterValue, 3, 202, 23, // Skip to: 9372
/* 3282 */    MCD_OPC_Decode, 210, 5, 43, // Opcode: MULLDo
/* 3286 */    MCD_OPC_FilterValue, 14, 19, 0, // Skip to: 3309
/* 3290 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3293 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 3301
/* 3297 */    MCD_OPC_Decode, 241, 1, 43, // Opcode: DIVDU
/* 3301 */    MCD_OPC_FilterValue, 3, 179, 23, // Skip to: 9372
/* 3305 */    MCD_OPC_Decode, 242, 1, 43, // Opcode: DIVDUo
/* 3309 */    MCD_OPC_FilterValue, 15, 171, 23, // Skip to: 9372
/* 3313 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3316 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 3324
/* 3320 */    MCD_OPC_Decode, 240, 1, 43, // Opcode: DIVD
/* 3324 */    MCD_OPC_FilterValue, 3, 156, 23, // Skip to: 9372
/* 3328 */    MCD_OPC_Decode, 243, 1, 43, // Opcode: DIVDo
/* 3332 */    MCD_OPC_FilterValue, 5, 233, 0, // Skip to: 3569
/* 3336 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 3339 */    MCD_OPC_FilterValue, 0, 33, 0, // Skip to: 3376
/* 3343 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3346 */    MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 3353
/* 3350 */    MCD_OPC_Decode, 27, 42, // Opcode: ADDC
/* 3353 */    MCD_OPC_FilterValue, 1, 3, 0, // Skip to: 3360
/* 3357 */    MCD_OPC_Decode, 30, 42, // Opcode: ADDCo
/* 3360 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 3368
/* 3364 */    MCD_OPC_Decode, 206, 5, 42, // Opcode: MULHWU
/* 3368 */    MCD_OPC_FilterValue, 3, 112, 23, // Skip to: 9372
/* 3372 */    MCD_OPC_Decode, 207, 5, 42, // Opcode: MULHWUo
/* 3376 */    MCD_OPC_FilterValue, 2, 19, 0, // Skip to: 3399
/* 3380 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3383 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 3391
/* 3387 */    MCD_OPC_Decode, 205, 5, 42, // Opcode: MULHW
/* 3391 */    MCD_OPC_FilterValue, 3, 89, 23, // Skip to: 9372
/* 3395 */    MCD_OPC_Decode, 208, 5, 42, // Opcode: MULHWo
/* 3399 */    MCD_OPC_FilterValue, 4, 17, 0, // Skip to: 3420
/* 3403 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3406 */    MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 3413
/* 3410 */    MCD_OPC_Decode, 31, 42, // Opcode: ADDE
/* 3413 */    MCD_OPC_FilterValue, 1, 67, 23, // Skip to: 9372
/* 3417 */    MCD_OPC_Decode, 34, 42, // Opcode: ADDEo
/* 3420 */    MCD_OPC_FilterValue, 6, 29, 0, // Skip to: 3453
/* 3424 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3427 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 3440
/* 3431 */    MCD_OPC_CheckField, 11, 5, 0, 47, 23, // Skip to: 9372
/* 3437 */    MCD_OPC_Decode, 59, 44, // Opcode: ADDZE
/* 3440 */    MCD_OPC_FilterValue, 1, 40, 23, // Skip to: 9372
/* 3444 */    MCD_OPC_CheckField, 11, 5, 0, 34, 23, // Skip to: 9372
/* 3450 */    MCD_OPC_Decode, 62, 44, // Opcode: ADDZEo
/* 3453 */    MCD_OPC_FilterValue, 7, 45, 0, // Skip to: 3502
/* 3457 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3460 */    MCD_OPC_FilterValue, 0, 9, 0, // Skip to: 3473
/* 3464 */    MCD_OPC_CheckField, 11, 5, 0, 14, 23, // Skip to: 9372
/* 3470 */    MCD_OPC_Decode, 55, 44, // Opcode: ADDME
/* 3473 */    MCD_OPC_FilterValue, 1, 9, 0, // Skip to: 3486
/* 3477 */    MCD_OPC_CheckField, 11, 5, 0, 1, 23, // Skip to: 9372
/* 3483 */    MCD_OPC_Decode, 58, 44, // Opcode: ADDMEo
/* 3486 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 3494
/* 3490 */    MCD_OPC_Decode, 213, 5, 42, // Opcode: MULLW
/* 3494 */    MCD_OPC_FilterValue, 3, 242, 22, // Skip to: 9372
/* 3498 */    MCD_OPC_Decode, 214, 5, 42, // Opcode: MULLWo
/* 3502 */    MCD_OPC_FilterValue, 8, 17, 0, // Skip to: 3523
/* 3506 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3509 */    MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 3516
/* 3513 */    MCD_OPC_Decode, 20, 42, // Opcode: ADD4
/* 3516 */    MCD_OPC_FilterValue, 1, 220, 22, // Skip to: 9372
/* 3520 */    MCD_OPC_Decode, 22, 42, // Opcode: ADD4o
/* 3523 */    MCD_OPC_FilterValue, 14, 19, 0, // Skip to: 3546
/* 3527 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3530 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 3538
/* 3534 */    MCD_OPC_Decode, 245, 1, 42, // Opcode: DIVWU
/* 3538 */    MCD_OPC_FilterValue, 3, 198, 22, // Skip to: 9372
/* 3542 */    MCD_OPC_Decode, 246, 1, 42, // Opcode: DIVWUo
/* 3546 */    MCD_OPC_FilterValue, 15, 190, 22, // Skip to: 9372
/* 3550 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3553 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 3561
/* 3557 */    MCD_OPC_Decode, 244, 1, 42, // Opcode: DIVW
/* 3561 */    MCD_OPC_FilterValue, 3, 175, 22, // Skip to: 9372
/* 3565 */    MCD_OPC_Decode, 247, 1, 42, // Opcode: DIVWo
/* 3569 */    MCD_OPC_FilterValue, 6, 101, 0, // Skip to: 3674
/* 3573 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 3576 */    MCD_OPC_FilterValue, 10, 10, 0, // Skip to: 3590
/* 3580 */    MCD_OPC_CheckField, 0, 2, 0, 154, 22, // Skip to: 9372
/* 3586 */    MCD_OPC_Decode, 155, 5, 45, // Opcode: LXVDSX
/* 3590 */    MCD_OPC_FilterValue, 18, 10, 0, // Skip to: 3604
/* 3594 */    MCD_OPC_CheckField, 0, 2, 0, 140, 22, // Skip to: 9372
/* 3600 */    MCD_OPC_Decode, 153, 5, 46, // Opcode: LXSDX
/* 3604 */    MCD_OPC_FilterValue, 22, 10, 0, // Skip to: 3618
/* 3608 */    MCD_OPC_CheckField, 1, 1, 0, 126, 22, // Skip to: 9372
/* 3614 */    MCD_OPC_Decode, 246, 6, 47, // Opcode: STXSDX
/* 3618 */    MCD_OPC_FilterValue, 24, 10, 0, // Skip to: 3632
/* 3622 */    MCD_OPC_CheckField, 0, 2, 0, 112, 22, // Skip to: 9372
/* 3628 */    MCD_OPC_Decode, 156, 5, 45, // Opcode: LXVW4X
/* 3632 */    MCD_OPC_FilterValue, 26, 10, 0, // Skip to: 3646
/* 3636 */    MCD_OPC_CheckField, 0, 2, 0, 98, 22, // Skip to: 9372
/* 3642 */    MCD_OPC_Decode, 154, 5, 45, // Opcode: LXVD2X
/* 3646 */    MCD_OPC_FilterValue, 28, 10, 0, // Skip to: 3660
/* 3650 */    MCD_OPC_CheckField, 1, 1, 0, 84, 22, // Skip to: 9372
/* 3656 */    MCD_OPC_Decode, 248, 6, 48, // Opcode: STXVW4X
/* 3660 */    MCD_OPC_FilterValue, 30, 76, 22, // Skip to: 9372
/* 3664 */    MCD_OPC_CheckField, 1, 1, 0, 70, 22, // Skip to: 9372
/* 3670 */    MCD_OPC_Decode, 247, 6, 48, // Opcode: STXVD2X
/* 3674 */    MCD_OPC_FilterValue, 7, 10, 0, // Skip to: 3688
/* 3678 */    MCD_OPC_CheckField, 0, 2, 2, 56, 22, // Skip to: 9372
/* 3684 */    MCD_OPC_Decode, 199, 4, 49, // Opcode: ISEL
/* 3688 */    MCD_OPC_FilterValue, 8, 43, 0, // Skip to: 3735
/* 3692 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 3695 */    MCD_OPC_FilterValue, 0, 16, 0, // Skip to: 3715
/* 3699 */    MCD_OPC_CheckField, 6, 6, 4, 35, 22, // Skip to: 9372
/* 3705 */    MCD_OPC_CheckField, 0, 2, 0, 29, 22, // Skip to: 9372
/* 3711 */    MCD_OPC_Decode, 179, 5, 50, // Opcode: MTCRF
/* 3715 */    MCD_OPC_FilterValue, 1, 21, 22, // Skip to: 9372
/* 3719 */    MCD_OPC_CheckField, 6, 6, 4, 15, 22, // Skip to: 9372
/* 3725 */    MCD_OPC_CheckField, 0, 2, 0, 9, 22, // Skip to: 9372
/* 3731 */    MCD_OPC_Decode, 193, 5, 51, // Opcode: MTOCRF
/* 3735 */    MCD_OPC_FilterValue, 9, 246, 1, // Skip to: 4241
/* 3739 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 3742 */    MCD_OPC_FilterValue, 0, 43, 0, // Skip to: 3789
/* 3746 */    MCD_OPC_ExtractField, 20, 1,  // Inst{20} ...
/* 3749 */    MCD_OPC_FilterValue, 0, 16, 0, // Skip to: 3769
/* 3753 */    MCD_OPC_CheckField, 11, 9, 0, 237, 21, // Skip to: 9372
/* 3759 */    MCD_OPC_CheckField, 0, 2, 2, 231, 21, // Skip to: 9372
/* 3765 */    MCD_OPC_Decode, 159, 5, 35, // Opcode: MFCR
/* 3769 */    MCD_OPC_FilterValue, 1, 223, 21, // Skip to: 9372
/* 3773 */    MCD_OPC_CheckField, 11, 1, 0, 217, 21, // Skip to: 9372
/* 3779 */    MCD_OPC_CheckField, 0, 2, 2, 211, 21, // Skip to: 9372
/* 3785 */    MCD_OPC_Decode, 168, 5, 52, // Opcode: MFOCRF
/* 3789 */    MCD_OPC_FilterValue, 2, 16, 0, // Skip to: 3809
/* 3793 */    MCD_OPC_CheckField, 11, 10, 0, 197, 21, // Skip to: 9372
/* 3799 */    MCD_OPC_CheckField, 0, 2, 2, 191, 21, // Skip to: 9372
/* 3805 */    MCD_OPC_Decode, 167, 5, 35, // Opcode: MFMSR
/* 3809 */    MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 3823
/* 3813 */    MCD_OPC_CheckField, 1, 1, 0, 177, 21, // Skip to: 9372
/* 3819 */    MCD_OPC_Decode, 191, 5, 53, // Opcode: MTMSR
/* 3823 */    MCD_OPC_FilterValue, 5, 10, 0, // Skip to: 3837
/* 3827 */    MCD_OPC_CheckField, 1, 1, 0, 163, 21, // Skip to: 9372
/* 3833 */    MCD_OPC_Decode, 192, 5, 53, // Opcode: MTMSRD
/* 3837 */    MCD_OPC_FilterValue, 6, 10, 0, // Skip to: 3851
/* 3841 */    MCD_OPC_CheckField, 1, 1, 0, 149, 21, // Skip to: 9372
/* 3847 */    MCD_OPC_Decode, 196, 5, 54, // Opcode: MTSR
/* 3851 */    MCD_OPC_FilterValue, 7, 10, 0, // Skip to: 3865
/* 3855 */    MCD_OPC_CheckField, 1, 1, 0, 135, 21, // Skip to: 9372
/* 3861 */    MCD_OPC_Decode, 197, 5, 55, // Opcode: MTSRIN
/* 3865 */    MCD_OPC_FilterValue, 8, 16, 0, // Skip to: 3885
/* 3869 */    MCD_OPC_CheckField, 16, 10, 0, 121, 21, // Skip to: 9372
/* 3875 */    MCD_OPC_CheckField, 0, 2, 0, 115, 21, // Skip to: 9372
/* 3881 */    MCD_OPC_Decode, 164, 7, 56, // Opcode: TLBIEL
/* 3885 */    MCD_OPC_FilterValue, 9, 16, 0, // Skip to: 3905
/* 3889 */    MCD_OPC_CheckField, 16, 5, 0, 101, 21, // Skip to: 9372
/* 3895 */    MCD_OPC_CheckField, 0, 2, 0, 95, 21, // Skip to: 9372
/* 3901 */    MCD_OPC_Decode, 163, 7, 55, // Opcode: TLBIE
/* 3905 */    MCD_OPC_FilterValue, 10, 32, 0, // Skip to: 3941
/* 3909 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3912 */    MCD_OPC_FilterValue, 2, 80, 21, // Skip to: 9372
/* 3916 */    MCD_OPC_ExtractField, 11, 10,  // Inst{20-11} ...
/* 3919 */    MCD_OPC_FilterValue, 128, 2, 4, 0, // Skip to: 3928
/* 3924 */    MCD_OPC_Decode, 165, 5, 35, // Opcode: MFLR
/* 3928 */    MCD_OPC_FilterValue, 160, 2, 4, 0, // Skip to: 3937
/* 3933 */    MCD_OPC_Decode, 161, 5, 35, // Opcode: MFCTR
/* 3937 */    MCD_OPC_Decode, 170, 5, 37, // Opcode: MFSPR
/* 3941 */    MCD_OPC_FilterValue, 11, 25, 0, // Skip to: 3970
/* 3945 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 3948 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 3962
/* 3952 */    MCD_OPC_CheckField, 11, 15, 0, 38, 21, // Skip to: 9372
/* 3958 */    MCD_OPC_Decode, 162, 7, 23, // Opcode: TLBIA
/* 3962 */    MCD_OPC_FilterValue, 2, 30, 21, // Skip to: 9372
/* 3966 */    MCD_OPC_Decode, 173, 5, 37, // Opcode: MFTB
/* 3970 */    MCD_OPC_FilterValue, 12, 16, 0, // Skip to: 3990
/* 3974 */    MCD_OPC_CheckField, 16, 5, 0, 16, 21, // Skip to: 9372
/* 3980 */    MCD_OPC_CheckField, 0, 2, 0, 10, 21, // Skip to: 9372
/* 3986 */    MCD_OPC_Decode, 169, 6, 55, // Opcode: SLBMTE
/* 3990 */    MCD_OPC_FilterValue, 13, 16, 0, // Skip to: 4010
/* 3994 */    MCD_OPC_CheckField, 16, 10, 0, 252, 20, // Skip to: 9372
/* 4000 */    MCD_OPC_CheckField, 0, 2, 0, 246, 20, // Skip to: 9372
/* 4006 */    MCD_OPC_Decode, 167, 6, 56, // Opcode: SLBIE
/* 4010 */    MCD_OPC_FilterValue, 14, 32, 0, // Skip to: 4046
/* 4014 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4017 */    MCD_OPC_FilterValue, 2, 231, 20, // Skip to: 9372
/* 4021 */    MCD_OPC_ExtractField, 11, 10,  // Inst{20-11} ...
/* 4024 */    MCD_OPC_FilterValue, 128, 2, 4, 0, // Skip to: 4033
/* 4029 */    MCD_OPC_Decode, 189, 5, 35, // Opcode: MTLR
/* 4033 */    MCD_OPC_FilterValue, 160, 2, 4, 0, // Skip to: 4042
/* 4038 */    MCD_OPC_Decode, 181, 5, 35, // Opcode: MTCTR
/* 4042 */    MCD_OPC_Decode, 195, 5, 57, // Opcode: MTSPR
/* 4046 */    MCD_OPC_FilterValue, 15, 16, 0, // Skip to: 4066
/* 4050 */    MCD_OPC_CheckField, 11, 15, 0, 196, 20, // Skip to: 9372
/* 4056 */    MCD_OPC_CheckField, 0, 2, 0, 190, 20, // Skip to: 9372
/* 4062 */    MCD_OPC_Decode, 166, 6, 23, // Opcode: SLBIA
/* 4066 */    MCD_OPC_FilterValue, 18, 10, 0, // Skip to: 4080
/* 4070 */    MCD_OPC_CheckField, 1, 1, 1, 176, 20, // Skip to: 9372
/* 4076 */    MCD_OPC_Decode, 171, 5, 54, // Opcode: MFSR
/* 4080 */    MCD_OPC_FilterValue, 20, 10, 0, // Skip to: 4094
/* 4084 */    MCD_OPC_CheckField, 1, 1, 1, 162, 20, // Skip to: 9372
/* 4090 */    MCD_OPC_Decode, 172, 5, 55, // Opcode: MFSRIN
/* 4094 */    MCD_OPC_FilterValue, 24, 16, 0, // Skip to: 4114
/* 4098 */    MCD_OPC_CheckField, 21, 5, 0, 148, 20, // Skip to: 9372
/* 4104 */    MCD_OPC_CheckField, 0, 2, 0, 142, 20, // Skip to: 9372
/* 4110 */    MCD_OPC_Decode, 165, 7, 41, // Opcode: TLBIVAX
/* 4114 */    MCD_OPC_FilterValue, 28, 43, 0, // Skip to: 4161
/* 4118 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4121 */    MCD_OPC_FilterValue, 0, 14, 0, // Skip to: 4139
/* 4125 */    MCD_OPC_CheckField, 21, 5, 0, 4, 0, // Skip to: 4135
/* 4131 */    MCD_OPC_Decode, 170, 7, 41, // Opcode: TLBSX
/* 4135 */    MCD_OPC_Decode, 171, 7, 42, // Opcode: TLBSX2
/* 4139 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 4147
/* 4143 */    MCD_OPC_Decode, 172, 7, 42, // Opcode: TLBSX2D
/* 4147 */    MCD_OPC_FilterValue, 2, 101, 20, // Skip to: 9372
/* 4151 */    MCD_OPC_CheckField, 16, 5, 0, 95, 20, // Skip to: 9372
/* 4157 */    MCD_OPC_Decode, 168, 6, 55, // Opcode: SLBMFEE
/* 4161 */    MCD_OPC_FilterValue, 29, 21, 0, // Skip to: 4186
/* 4165 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4168 */    MCD_OPC_FilterValue, 0, 80, 20, // Skip to: 9372
/* 4172 */    MCD_OPC_CheckField, 11, 15, 0, 4, 0, // Skip to: 4182
/* 4178 */    MCD_OPC_Decode, 168, 7, 23, // Opcode: TLBRE
/* 4182 */    MCD_OPC_Decode, 169, 7, 58, // Opcode: TLBRE2
/* 4186 */    MCD_OPC_FilterValue, 30, 31, 0, // Skip to: 4221
/* 4190 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4193 */    MCD_OPC_FilterValue, 0, 55, 20, // Skip to: 9372
/* 4197 */    MCD_OPC_CheckField, 11, 15, 0, 4, 0, // Skip to: 4207
/* 4203 */    MCD_OPC_Decode, 174, 7, 23, // Opcode: TLBWE
/* 4207 */    MCD_OPC_CheckField, 16, 10, 0, 4, 0, // Skip to: 4217
/* 4213 */    MCD_OPC_Decode, 166, 7, 56, // Opcode: TLBLD
/* 4217 */    MCD_OPC_Decode, 175, 7, 58, // Opcode: TLBWE2
/* 4221 */    MCD_OPC_FilterValue, 31, 27, 20, // Skip to: 9372
/* 4225 */    MCD_OPC_CheckField, 16, 10, 0, 21, 20, // Skip to: 9372
/* 4231 */    MCD_OPC_CheckField, 0, 2, 0, 15, 20, // Skip to: 9372
/* 4237 */    MCD_OPC_Decode, 167, 7, 56, // Opcode: TLBLI
/* 4241 */    MCD_OPC_FilterValue, 10, 166, 0, // Skip to: 4411
/* 4245 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 4248 */    MCD_OPC_FilterValue, 0, 19, 0, // Skip to: 4271
/* 4252 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4255 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 4263
/* 4259 */    MCD_OPC_Decode, 138, 5, 59, // Opcode: LWARX
/* 4263 */    MCD_OPC_FilterValue, 2, 241, 19, // Skip to: 9372
/* 4267 */    MCD_OPC_Decode, 217, 4, 60, // Opcode: LDX
/* 4271 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 4285
/* 4275 */    MCD_OPC_CheckField, 0, 2, 2, 227, 19, // Skip to: 9372
/* 4281 */    MCD_OPC_Decode, 216, 4, 61, // Opcode: LDUX
/* 4285 */    MCD_OPC_FilterValue, 2, 10, 0, // Skip to: 4299
/* 4289 */    MCD_OPC_CheckField, 0, 2, 0, 213, 19, // Skip to: 9372
/* 4295 */    MCD_OPC_Decode, 213, 4, 60, // Opcode: LDARX
/* 4299 */    MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 4313
/* 4303 */    MCD_OPC_CheckField, 0, 2, 2, 199, 19, // Skip to: 9372
/* 4309 */    MCD_OPC_Decode, 210, 6, 60, // Opcode: STDX
/* 4313 */    MCD_OPC_FilterValue, 5, 10, 0, // Skip to: 4327
/* 4317 */    MCD_OPC_CheckField, 0, 2, 2, 185, 19, // Skip to: 9372
/* 4323 */    MCD_OPC_Decode, 209, 6, 62, // Opcode: STDUX
/* 4327 */    MCD_OPC_FilterValue, 10, 10, 0, // Skip to: 4341
/* 4331 */    MCD_OPC_CheckField, 0, 2, 2, 171, 19, // Skip to: 9372
/* 4337 */    MCD_OPC_Decode, 140, 5, 60, // Opcode: LWAX
/* 4341 */    MCD_OPC_FilterValue, 11, 10, 0, // Skip to: 4355
/* 4345 */    MCD_OPC_CheckField, 0, 2, 2, 157, 19, // Skip to: 9372
/* 4351 */    MCD_OPC_Decode, 139, 5, 61, // Opcode: LWAUX
/* 4355 */    MCD_OPC_FilterValue, 16, 10, 0, // Skip to: 4369
/* 4359 */    MCD_OPC_CheckField, 0, 2, 0, 143, 19, // Skip to: 9372
/* 4365 */    MCD_OPC_Decode, 214, 4, 60, // Opcode: LDBRX
/* 4369 */    MCD_OPC_FilterValue, 18, 10, 0, // Skip to: 4383
/* 4373 */    MCD_OPC_CheckField, 0, 2, 2, 129, 19, // Skip to: 9372
/* 4379 */    MCD_OPC_Decode, 129, 5, 63, // Opcode: LSWI
/* 4383 */    MCD_OPC_FilterValue, 20, 10, 0, // Skip to: 4397
/* 4387 */    MCD_OPC_CheckField, 0, 2, 0, 115, 19, // Skip to: 9372
/* 4393 */    MCD_OPC_Decode, 206, 6, 60, // Opcode: STDBRX
/* 4397 */    MCD_OPC_FilterValue, 22, 107, 19, // Skip to: 9372
/* 4401 */    MCD_OPC_CheckField, 0, 2, 2, 101, 19, // Skip to: 9372
/* 4407 */    MCD_OPC_Decode, 230, 6, 63, // Opcode: STSWI
/* 4411 */    MCD_OPC_FilterValue, 11, 212, 2, // Skip to: 5139
/* 4415 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 4418 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4432
/* 4422 */    MCD_OPC_CheckField, 0, 2, 2, 80, 19, // Skip to: 9372
/* 4428 */    MCD_OPC_Decode, 150, 5, 59, // Opcode: LWZX
/* 4432 */    MCD_OPC_FilterValue, 1, 25, 0, // Skip to: 4461
/* 4436 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4439 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4453
/* 4443 */    MCD_OPC_CheckField, 21, 5, 0, 59, 19, // Skip to: 9372
/* 4449 */    MCD_OPC_Decode, 234, 1, 64, // Opcode: DCBST
/* 4453 */    MCD_OPC_FilterValue, 2, 51, 19, // Skip to: 9372
/* 4457 */    MCD_OPC_Decode, 148, 5, 65, // Opcode: LWZUX
/* 4461 */    MCD_OPC_FilterValue, 2, 25, 0, // Skip to: 4490
/* 4465 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4468 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4482
/* 4472 */    MCD_OPC_CheckField, 21, 5, 0, 30, 19, // Skip to: 9372
/* 4478 */    MCD_OPC_Decode, 232, 1, 64, // Opcode: DCBF
/* 4482 */    MCD_OPC_FilterValue, 2, 22, 19, // Skip to: 9372
/* 4486 */    MCD_OPC_Decode, 210, 4, 59, // Opcode: LBZX
/* 4490 */    MCD_OPC_FilterValue, 3, 10, 0, // Skip to: 4504
/* 4494 */    MCD_OPC_CheckField, 0, 2, 2, 8, 19, // Skip to: 9372
/* 4500 */    MCD_OPC_Decode, 208, 4, 65, // Opcode: LBZUX
/* 4504 */    MCD_OPC_FilterValue, 4, 19, 0, // Skip to: 4527
/* 4508 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4511 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 4519
/* 4515 */    MCD_OPC_Decode, 239, 6, 59, // Opcode: STWCX
/* 4519 */    MCD_OPC_FilterValue, 2, 241, 18, // Skip to: 9372
/* 4523 */    MCD_OPC_Decode, 244, 6, 59, // Opcode: STWX
/* 4527 */    MCD_OPC_FilterValue, 5, 10, 0, // Skip to: 4541
/* 4531 */    MCD_OPC_CheckField, 0, 2, 2, 227, 18, // Skip to: 9372
/* 4537 */    MCD_OPC_Decode, 242, 6, 66, // Opcode: STWUX
/* 4541 */    MCD_OPC_FilterValue, 6, 19, 0, // Skip to: 4564
/* 4545 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4548 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 4556
/* 4552 */    MCD_OPC_Decode, 207, 6, 60, // Opcode: STDCX
/* 4556 */    MCD_OPC_FilterValue, 2, 204, 18, // Skip to: 9372
/* 4560 */    MCD_OPC_Decode, 203, 6, 59, // Opcode: STBX
/* 4564 */    MCD_OPC_FilterValue, 7, 25, 0, // Skip to: 4593
/* 4568 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4571 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4585
/* 4575 */    MCD_OPC_CheckField, 21, 5, 0, 183, 18, // Skip to: 9372
/* 4581 */    MCD_OPC_Decode, 236, 1, 64, // Opcode: DCBTST
/* 4585 */    MCD_OPC_FilterValue, 2, 175, 18, // Skip to: 9372
/* 4589 */    MCD_OPC_Decode, 201, 6, 66, // Opcode: STBUX
/* 4593 */    MCD_OPC_FilterValue, 8, 25, 0, // Skip to: 4622
/* 4597 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4600 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4614
/* 4604 */    MCD_OPC_CheckField, 21, 5, 0, 154, 18, // Skip to: 9372
/* 4610 */    MCD_OPC_Decode, 235, 1, 64, // Opcode: DCBT
/* 4614 */    MCD_OPC_FilterValue, 2, 146, 18, // Skip to: 9372
/* 4618 */    MCD_OPC_Decode, 250, 4, 59, // Opcode: LHZX
/* 4622 */    MCD_OPC_FilterValue, 9, 10, 0, // Skip to: 4636
/* 4626 */    MCD_OPC_CheckField, 0, 2, 2, 132, 18, // Skip to: 9372
/* 4632 */    MCD_OPC_Decode, 248, 4, 65, // Opcode: LHZUX
/* 4636 */    MCD_OPC_FilterValue, 10, 34, 0, // Skip to: 4674
/* 4640 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4643 */    MCD_OPC_FilterValue, 0, 19, 0, // Skip to: 4666
/* 4647 */    MCD_OPC_ExtractField, 23, 3,  // Inst{25-23} ...
/* 4650 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 4658
/* 4654 */    MCD_OPC_Decode, 250, 1, 67, // Opcode: DST
/* 4658 */    MCD_OPC_FilterValue, 4, 102, 18, // Skip to: 9372
/* 4662 */    MCD_OPC_Decode, 128, 2, 67, // Opcode: DSTT
/* 4666 */    MCD_OPC_FilterValue, 2, 94, 18, // Skip to: 9372
/* 4670 */    MCD_OPC_Decode, 241, 4, 59, // Opcode: LHAX
/* 4674 */    MCD_OPC_FilterValue, 11, 34, 0, // Skip to: 4712
/* 4678 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4681 */    MCD_OPC_FilterValue, 0, 19, 0, // Skip to: 4704
/* 4685 */    MCD_OPC_ExtractField, 23, 3,  // Inst{25-23} ...
/* 4688 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 4696
/* 4692 */    MCD_OPC_Decode, 252, 1, 67, // Opcode: DSTST
/* 4696 */    MCD_OPC_FilterValue, 4, 64, 18, // Skip to: 9372
/* 4700 */    MCD_OPC_Decode, 254, 1, 67, // Opcode: DSTSTT
/* 4704 */    MCD_OPC_FilterValue, 2, 56, 18, // Skip to: 9372
/* 4708 */    MCD_OPC_Decode, 239, 4, 65, // Opcode: LHAUX
/* 4712 */    MCD_OPC_FilterValue, 12, 10, 0, // Skip to: 4726
/* 4716 */    MCD_OPC_CheckField, 0, 2, 2, 42, 18, // Skip to: 9372
/* 4722 */    MCD_OPC_Decode, 227, 6, 59, // Opcode: STHX
/* 4726 */    MCD_OPC_FilterValue, 13, 10, 0, // Skip to: 4740
/* 4730 */    MCD_OPC_CheckField, 0, 2, 2, 28, 18, // Skip to: 9372
/* 4736 */    MCD_OPC_Decode, 225, 6, 66, // Opcode: STHUX
/* 4740 */    MCD_OPC_FilterValue, 14, 16, 0, // Skip to: 4760
/* 4744 */    MCD_OPC_CheckField, 21, 5, 0, 14, 18, // Skip to: 9372
/* 4750 */    MCD_OPC_CheckField, 0, 2, 0, 8, 18, // Skip to: 9372
/* 4756 */    MCD_OPC_Decode, 233, 1, 64, // Opcode: DCBI
/* 4760 */    MCD_OPC_FilterValue, 16, 19, 0, // Skip to: 4783
/* 4764 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4767 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 4775
/* 4771 */    MCD_OPC_Decode, 143, 5, 59, // Opcode: LWBRX
/* 4775 */    MCD_OPC_FilterValue, 2, 241, 17, // Skip to: 9372
/* 4779 */    MCD_OPC_Decode, 234, 4, 68, // Opcode: LFSX
/* 4783 */    MCD_OPC_FilterValue, 17, 25, 0, // Skip to: 4812
/* 4787 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4790 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4804
/* 4794 */    MCD_OPC_CheckField, 11, 15, 0, 220, 17, // Skip to: 9372
/* 4800 */    MCD_OPC_Decode, 173, 7, 23, // Opcode: TLBSYNC
/* 4804 */    MCD_OPC_FilterValue, 2, 212, 17, // Skip to: 9372
/* 4808 */    MCD_OPC_Decode, 233, 4, 69, // Opcode: LFSUX
/* 4812 */    MCD_OPC_FilterValue, 18, 31, 0, // Skip to: 4847
/* 4816 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4819 */    MCD_OPC_FilterValue, 0, 16, 0, // Skip to: 4839
/* 4823 */    MCD_OPC_CheckField, 23, 3, 0, 191, 17, // Skip to: 9372
/* 4829 */    MCD_OPC_CheckField, 11, 10, 0, 185, 17, // Skip to: 9372
/* 4835 */    MCD_OPC_Decode, 147, 7, 70, // Opcode: SYNC
/* 4839 */    MCD_OPC_FilterValue, 2, 177, 17, // Skip to: 9372
/* 4843 */    MCD_OPC_Decode, 228, 4, 71, // Opcode: LFDX
/* 4847 */    MCD_OPC_FilterValue, 19, 10, 0, // Skip to: 4861
/* 4851 */    MCD_OPC_CheckField, 0, 2, 2, 163, 17, // Skip to: 9372
/* 4857 */    MCD_OPC_Decode, 227, 4, 72, // Opcode: LFDUX
/* 4861 */    MCD_OPC_FilterValue, 20, 19, 0, // Skip to: 4884
/* 4865 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4868 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 4876
/* 4872 */    MCD_OPC_Decode, 238, 6, 59, // Opcode: STWBRX
/* 4876 */    MCD_OPC_FilterValue, 2, 140, 17, // Skip to: 9372
/* 4880 */    MCD_OPC_Decode, 219, 6, 68, // Opcode: STFSX
/* 4884 */    MCD_OPC_FilterValue, 21, 10, 0, // Skip to: 4898
/* 4888 */    MCD_OPC_CheckField, 0, 2, 2, 126, 17, // Skip to: 9372
/* 4894 */    MCD_OPC_Decode, 218, 6, 73, // Opcode: STFSUX
/* 4898 */    MCD_OPC_FilterValue, 22, 10, 0, // Skip to: 4912
/* 4902 */    MCD_OPC_CheckField, 0, 2, 2, 112, 17, // Skip to: 9372
/* 4908 */    MCD_OPC_Decode, 214, 6, 71, // Opcode: STFDX
/* 4912 */    MCD_OPC_FilterValue, 23, 25, 0, // Skip to: 4941
/* 4916 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 4919 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 4933
/* 4923 */    MCD_OPC_CheckField, 21, 5, 0, 91, 17, // Skip to: 9372
/* 4929 */    MCD_OPC_Decode, 231, 1, 64, // Opcode: DCBA
/* 4933 */    MCD_OPC_FilterValue, 2, 83, 17, // Skip to: 9372
/* 4937 */    MCD_OPC_Decode, 213, 6, 74, // Opcode: STFDUX
/* 4941 */    MCD_OPC_FilterValue, 24, 10, 0, // Skip to: 4955
/* 4945 */    MCD_OPC_CheckField, 0, 2, 0, 69, 17, // Skip to: 9372
/* 4951 */    MCD_OPC_Decode, 243, 4, 59, // Opcode: LHBRX
/* 4955 */    MCD_OPC_FilterValue, 25, 43, 0, // Skip to: 5002
/* 4959 */    MCD_OPC_ExtractField, 23, 3,  // Inst{25-23} ...
/* 4962 */    MCD_OPC_FilterValue, 0, 16, 0, // Skip to: 4982
/* 4966 */    MCD_OPC_CheckField, 11, 10, 0, 48, 17, // Skip to: 9372
/* 4972 */    MCD_OPC_CheckField, 0, 2, 0, 42, 17, // Skip to: 9372
/* 4978 */    MCD_OPC_Decode, 248, 1, 75, // Opcode: DSS
/* 4982 */    MCD_OPC_FilterValue, 4, 34, 17, // Skip to: 9372
/* 4986 */    MCD_OPC_CheckField, 11, 12, 0, 28, 17, // Skip to: 9372
/* 4992 */    MCD_OPC_CheckField, 0, 2, 0, 22, 17, // Skip to: 9372
/* 4998 */    MCD_OPC_Decode, 249, 1, 23, // Opcode: DSSALL
/* 5002 */    MCD_OPC_FilterValue, 26, 41, 0, // Skip to: 5047
/* 5006 */    MCD_OPC_ExtractField, 1, 1,  // Inst{1} ...
/* 5009 */    MCD_OPC_FilterValue, 0, 20, 0, // Skip to: 5033
/* 5013 */    MCD_OPC_CheckField, 11, 15, 0, 10, 0, // Skip to: 5029
/* 5019 */    MCD_OPC_CheckField, 0, 1, 0, 4, 0, // Skip to: 5029
/* 5025 */    MCD_OPC_Decode, 137, 2, 23, // Opcode: EIEIO
/* 5029 */    MCD_OPC_Decode, 157, 5, 76, // Opcode: MBAR
/* 5033 */    MCD_OPC_FilterValue, 1, 239, 16, // Skip to: 9372
/* 5037 */    MCD_OPC_CheckField, 0, 1, 0, 233, 16, // Skip to: 9372
/* 5043 */    MCD_OPC_Decode, 229, 4, 71, // Opcode: LFIWAX
/* 5047 */    MCD_OPC_FilterValue, 27, 10, 0, // Skip to: 5061
/* 5051 */    MCD_OPC_CheckField, 0, 2, 2, 219, 16, // Skip to: 9372
/* 5057 */    MCD_OPC_Decode, 230, 4, 71, // Opcode: LFIWZX
/* 5061 */    MCD_OPC_FilterValue, 28, 10, 0, // Skip to: 5075
/* 5065 */    MCD_OPC_CheckField, 0, 2, 0, 205, 16, // Skip to: 9372
/* 5071 */    MCD_OPC_Decode, 222, 6, 59, // Opcode: STHBRX
/* 5075 */    MCD_OPC_FilterValue, 30, 25, 0, // Skip to: 5104
/* 5079 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5082 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5096
/* 5086 */    MCD_OPC_CheckField, 21, 5, 0, 184, 16, // Skip to: 9372
/* 5092 */    MCD_OPC_Decode, 191, 4, 64, // Opcode: ICBI
/* 5096 */    MCD_OPC_FilterValue, 2, 176, 16, // Skip to: 9372
/* 5100 */    MCD_OPC_Decode, 215, 6, 71, // Opcode: STFIWX
/* 5104 */    MCD_OPC_FilterValue, 31, 168, 16, // Skip to: 9372
/* 5108 */    MCD_OPC_ExtractField, 21, 5,  // Inst{25-21} ...
/* 5111 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5125
/* 5115 */    MCD_OPC_CheckField, 0, 2, 0, 155, 16, // Skip to: 9372
/* 5121 */    MCD_OPC_Decode, 237, 1, 64, // Opcode: DCBZ
/* 5125 */    MCD_OPC_FilterValue, 1, 147, 16, // Skip to: 9372
/* 5129 */    MCD_OPC_CheckField, 0, 2, 0, 141, 16, // Skip to: 9372
/* 5135 */    MCD_OPC_Decode, 238, 1, 64, // Opcode: DCBZL
/* 5139 */    MCD_OPC_FilterValue, 12, 95, 0, // Skip to: 5238
/* 5143 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 5146 */    MCD_OPC_FilterValue, 0, 19, 0, // Skip to: 5169
/* 5150 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5153 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5161
/* 5157 */    MCD_OPC_Decode, 174, 6, 77, // Opcode: SLW
/* 5161 */    MCD_OPC_FilterValue, 1, 111, 16, // Skip to: 9372
/* 5165 */    MCD_OPC_Decode, 177, 6, 77, // Opcode: SLWo
/* 5169 */    MCD_OPC_FilterValue, 16, 19, 0, // Skip to: 5192
/* 5173 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5176 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5184
/* 5180 */    MCD_OPC_Decode, 193, 6, 77, // Opcode: SRW
/* 5184 */    MCD_OPC_FilterValue, 1, 88, 16, // Skip to: 9372
/* 5188 */    MCD_OPC_Decode, 196, 6, 77, // Opcode: SRWo
/* 5192 */    MCD_OPC_FilterValue, 24, 19, 0, // Skip to: 5215
/* 5196 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5199 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5207
/* 5203 */    MCD_OPC_Decode, 185, 6, 77, // Opcode: SRAW
/* 5207 */    MCD_OPC_FilterValue, 1, 65, 16, // Skip to: 9372
/* 5211 */    MCD_OPC_Decode, 188, 6, 77, // Opcode: SRAWo
/* 5215 */    MCD_OPC_FilterValue, 25, 57, 16, // Skip to: 9372
/* 5219 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5222 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5230
/* 5226 */    MCD_OPC_Decode, 186, 6, 78, // Opcode: SRAWI
/* 5230 */    MCD_OPC_FilterValue, 1, 42, 16, // Skip to: 9372
/* 5234 */    MCD_OPC_Decode, 187, 6, 78, // Opcode: SRAWIo
/* 5238 */    MCD_OPC_FilterValue, 13, 47, 1, // Skip to: 5545
/* 5242 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 5245 */    MCD_OPC_FilterValue, 0, 47, 0, // Skip to: 5296
/* 5249 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5252 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5266
/* 5256 */    MCD_OPC_CheckField, 11, 5, 0, 14, 16, // Skip to: 9372
/* 5262 */    MCD_OPC_Decode, 217, 1, 79, // Opcode: CNTLZW
/* 5266 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 5280
/* 5270 */    MCD_OPC_CheckField, 11, 5, 0, 0, 16, // Skip to: 9372
/* 5276 */    MCD_OPC_Decode, 218, 1, 79, // Opcode: CNTLZWo
/* 5280 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 5288
/* 5284 */    MCD_OPC_Decode, 170, 6, 80, // Opcode: SLD
/* 5288 */    MCD_OPC_FilterValue, 3, 240, 15, // Skip to: 9372
/* 5292 */    MCD_OPC_Decode, 173, 6, 80, // Opcode: SLDo
/* 5296 */    MCD_OPC_FilterValue, 1, 31, 0, // Skip to: 5331
/* 5300 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5303 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5317
/* 5307 */    MCD_OPC_CheckField, 11, 5, 0, 219, 15, // Skip to: 9372
/* 5313 */    MCD_OPC_Decode, 215, 1, 81, // Opcode: CNTLZD
/* 5317 */    MCD_OPC_FilterValue, 1, 211, 15, // Skip to: 9372
/* 5321 */    MCD_OPC_CheckField, 11, 5, 0, 205, 15, // Skip to: 9372
/* 5327 */    MCD_OPC_Decode, 216, 1, 81, // Opcode: CNTLZDo
/* 5331 */    MCD_OPC_FilterValue, 11, 16, 0, // Skip to: 5351
/* 5335 */    MCD_OPC_CheckField, 11, 5, 0, 191, 15, // Skip to: 9372
/* 5341 */    MCD_OPC_CheckField, 0, 2, 0, 185, 15, // Skip to: 9372
/* 5347 */    MCD_OPC_Decode, 245, 5, 79, // Opcode: POPCNTW
/* 5351 */    MCD_OPC_FilterValue, 15, 16, 0, // Skip to: 5371
/* 5355 */    MCD_OPC_CheckField, 11, 5, 0, 171, 15, // Skip to: 9372
/* 5361 */    MCD_OPC_CheckField, 0, 2, 0, 165, 15, // Skip to: 9372
/* 5367 */    MCD_OPC_Decode, 244, 5, 81, // Opcode: POPCNTD
/* 5371 */    MCD_OPC_FilterValue, 16, 19, 0, // Skip to: 5394
/* 5375 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5378 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 5386
/* 5382 */    MCD_OPC_Decode, 189, 6, 80, // Opcode: SRD
/* 5386 */    MCD_OPC_FilterValue, 3, 142, 15, // Skip to: 9372
/* 5390 */    MCD_OPC_Decode, 192, 6, 80, // Opcode: SRDo
/* 5394 */    MCD_OPC_FilterValue, 24, 19, 0, // Skip to: 5417
/* 5398 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5401 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5409
/* 5405 */    MCD_OPC_Decode, 181, 6, 80, // Opcode: SRAD
/* 5409 */    MCD_OPC_FilterValue, 1, 119, 15, // Skip to: 9372
/* 5413 */    MCD_OPC_Decode, 184, 6, 80, // Opcode: SRADo
/* 5417 */    MCD_OPC_FilterValue, 25, 19, 0, // Skip to: 5440
/* 5421 */    MCD_OPC_ExtractField, 0, 1,  // Inst{0} ...
/* 5424 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5432
/* 5428 */    MCD_OPC_Decode, 182, 6, 82, // Opcode: SRADI
/* 5432 */    MCD_OPC_FilterValue, 1, 96, 15, // Skip to: 9372
/* 5436 */    MCD_OPC_Decode, 183, 6, 82, // Opcode: SRADIo
/* 5440 */    MCD_OPC_FilterValue, 28, 31, 0, // Skip to: 5475
/* 5444 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5447 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5461
/* 5451 */    MCD_OPC_CheckField, 11, 5, 0, 75, 15, // Skip to: 9372
/* 5457 */    MCD_OPC_Decode, 198, 3, 79, // Opcode: EXTSH
/* 5461 */    MCD_OPC_FilterValue, 1, 67, 15, // Skip to: 9372
/* 5465 */    MCD_OPC_CheckField, 11, 5, 0, 61, 15, // Skip to: 9372
/* 5471 */    MCD_OPC_Decode, 202, 3, 79, // Opcode: EXTSHo
/* 5475 */    MCD_OPC_FilterValue, 29, 31, 0, // Skip to: 5510
/* 5479 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5482 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5496
/* 5486 */    MCD_OPC_CheckField, 11, 5, 0, 40, 15, // Skip to: 9372
/* 5492 */    MCD_OPC_Decode, 193, 3, 79, // Opcode: EXTSB
/* 5496 */    MCD_OPC_FilterValue, 1, 32, 15, // Skip to: 9372
/* 5500 */    MCD_OPC_CheckField, 11, 5, 0, 26, 15, // Skip to: 9372
/* 5506 */    MCD_OPC_Decode, 197, 3, 79, // Opcode: EXTSBo
/* 5510 */    MCD_OPC_FilterValue, 30, 18, 15, // Skip to: 9372
/* 5514 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5517 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 5531
/* 5521 */    MCD_OPC_CheckField, 11, 5, 0, 5, 15, // Skip to: 9372
/* 5527 */    MCD_OPC_Decode, 203, 3, 81, // Opcode: EXTSW
/* 5531 */    MCD_OPC_FilterValue, 1, 253, 14, // Skip to: 9372
/* 5535 */    MCD_OPC_CheckField, 11, 5, 0, 247, 14, // Skip to: 9372
/* 5541 */    MCD_OPC_Decode, 206, 3, 81, // Opcode: EXTSWo
/* 5545 */    MCD_OPC_FilterValue, 14, 183, 0, // Skip to: 5732
/* 5549 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 5552 */    MCD_OPC_FilterValue, 0, 17, 0, // Skip to: 5573
/* 5556 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5559 */    MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 5566
/* 5563 */    MCD_OPC_Decode, 65, 77, // Opcode: AND
/* 5566 */    MCD_OPC_FilterValue, 1, 218, 14, // Skip to: 9372
/* 5570 */    MCD_OPC_Decode, 80, 77, // Opcode: ANDo
/* 5573 */    MCD_OPC_FilterValue, 1, 17, 0, // Skip to: 5594
/* 5577 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5580 */    MCD_OPC_FilterValue, 0, 3, 0, // Skip to: 5587
/* 5584 */    MCD_OPC_Decode, 68, 77, // Opcode: ANDC
/* 5587 */    MCD_OPC_FilterValue, 1, 197, 14, // Skip to: 9372
/* 5591 */    MCD_OPC_Decode, 71, 77, // Opcode: ANDCo
/* 5594 */    MCD_OPC_FilterValue, 3, 19, 0, // Skip to: 5617
/* 5598 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5601 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5609
/* 5605 */    MCD_OPC_Decode, 228, 5, 77, // Opcode: NOR
/* 5609 */    MCD_OPC_FilterValue, 1, 175, 14, // Skip to: 9372
/* 5613 */    MCD_OPC_Decode, 231, 5, 77, // Opcode: NORo
/* 5617 */    MCD_OPC_FilterValue, 8, 19, 0, // Skip to: 5640
/* 5621 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5624 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5632
/* 5628 */    MCD_OPC_Decode, 138, 2, 77, // Opcode: EQV
/* 5632 */    MCD_OPC_FilterValue, 1, 152, 14, // Skip to: 9372
/* 5636 */    MCD_OPC_Decode, 141, 2, 77, // Opcode: EQVo
/* 5640 */    MCD_OPC_FilterValue, 9, 19, 0, // Skip to: 5663
/* 5644 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5647 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5655
/* 5651 */    MCD_OPC_Decode, 221, 8, 77, // Opcode: XOR
/* 5655 */    MCD_OPC_FilterValue, 1, 129, 14, // Skip to: 9372
/* 5659 */    MCD_OPC_Decode, 228, 8, 77, // Opcode: XORo
/* 5663 */    MCD_OPC_FilterValue, 12, 19, 0, // Skip to: 5686
/* 5667 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5670 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5678
/* 5674 */    MCD_OPC_Decode, 235, 5, 77, // Opcode: ORC
/* 5678 */    MCD_OPC_FilterValue, 1, 106, 14, // Skip to: 9372
/* 5682 */    MCD_OPC_Decode, 238, 5, 77, // Opcode: ORCo
/* 5686 */    MCD_OPC_FilterValue, 13, 19, 0, // Skip to: 5709
/* 5690 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5693 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5701
/* 5697 */    MCD_OPC_Decode, 232, 5, 77, // Opcode: OR
/* 5701 */    MCD_OPC_FilterValue, 1, 83, 14, // Skip to: 9372
/* 5705 */    MCD_OPC_Decode, 243, 5, 77, // Opcode: ORo
/* 5709 */    MCD_OPC_FilterValue, 14, 75, 14, // Skip to: 9372
/* 5713 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5716 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5724
/* 5720 */    MCD_OPC_Decode, 217, 5, 77, // Opcode: NAND
/* 5724 */    MCD_OPC_FilterValue, 1, 60, 14, // Skip to: 9372
/* 5728 */    MCD_OPC_Decode, 220, 5, 77, // Opcode: NANDo
/* 5732 */    MCD_OPC_FilterValue, 15, 52, 14, // Skip to: 9372
/* 5736 */    MCD_OPC_CheckField, 23, 3, 0, 46, 14, // Skip to: 9372
/* 5742 */    MCD_OPC_CheckField, 6, 15, 1, 40, 14, // Skip to: 9372
/* 5748 */    MCD_OPC_CheckField, 0, 2, 0, 34, 14, // Skip to: 9372
/* 5754 */    MCD_OPC_Decode, 218, 8, 70, // Opcode: WAIT
/* 5758 */    MCD_OPC_FilterValue, 32, 4, 0, // Skip to: 5766
/* 5762 */    MCD_OPC_Decode, 144, 5, 83, // Opcode: LWZ
/* 5766 */    MCD_OPC_FilterValue, 33, 4, 0, // Skip to: 5774
/* 5770 */    MCD_OPC_Decode, 146, 5, 83, // Opcode: LWZU
/* 5774 */    MCD_OPC_FilterValue, 34, 4, 0, // Skip to: 5782
/* 5778 */    MCD_OPC_Decode, 204, 4, 83, // Opcode: LBZ
/* 5782 */    MCD_OPC_FilterValue, 35, 4, 0, // Skip to: 5790
/* 5786 */    MCD_OPC_Decode, 206, 4, 83, // Opcode: LBZU
/* 5790 */    MCD_OPC_FilterValue, 36, 4, 0, // Skip to: 5798
/* 5794 */    MCD_OPC_Decode, 236, 6, 83, // Opcode: STW
/* 5798 */    MCD_OPC_FilterValue, 37, 4, 0, // Skip to: 5806
/* 5802 */    MCD_OPC_Decode, 240, 6, 83, // Opcode: STWU
/* 5806 */    MCD_OPC_FilterValue, 38, 4, 0, // Skip to: 5814
/* 5810 */    MCD_OPC_Decode, 197, 6, 83, // Opcode: STB
/* 5814 */    MCD_OPC_FilterValue, 39, 4, 0, // Skip to: 5822
/* 5818 */    MCD_OPC_Decode, 199, 6, 83, // Opcode: STBU
/* 5822 */    MCD_OPC_FilterValue, 40, 4, 0, // Skip to: 5830
/* 5826 */    MCD_OPC_Decode, 244, 4, 83, // Opcode: LHZ
/* 5830 */    MCD_OPC_FilterValue, 41, 4, 0, // Skip to: 5838
/* 5834 */    MCD_OPC_Decode, 246, 4, 83, // Opcode: LHZU
/* 5838 */    MCD_OPC_FilterValue, 42, 4, 0, // Skip to: 5846
/* 5842 */    MCD_OPC_Decode, 235, 4, 83, // Opcode: LHA
/* 5846 */    MCD_OPC_FilterValue, 43, 4, 0, // Skip to: 5854
/* 5850 */    MCD_OPC_Decode, 237, 4, 83, // Opcode: LHAU
/* 5854 */    MCD_OPC_FilterValue, 44, 4, 0, // Skip to: 5862
/* 5858 */    MCD_OPC_Decode, 220, 6, 83, // Opcode: STH
/* 5862 */    MCD_OPC_FilterValue, 45, 4, 0, // Skip to: 5870
/* 5866 */    MCD_OPC_Decode, 223, 6, 83, // Opcode: STHU
/* 5870 */    MCD_OPC_FilterValue, 46, 4, 0, // Skip to: 5878
/* 5874 */    MCD_OPC_Decode, 128, 5, 83, // Opcode: LMW
/* 5878 */    MCD_OPC_FilterValue, 47, 4, 0, // Skip to: 5886
/* 5882 */    MCD_OPC_Decode, 229, 6, 83, // Opcode: STMW
/* 5886 */    MCD_OPC_FilterValue, 48, 4, 0, // Skip to: 5894
/* 5890 */    MCD_OPC_Decode, 231, 4, 84, // Opcode: LFS
/* 5894 */    MCD_OPC_FilterValue, 49, 4, 0, // Skip to: 5902
/* 5898 */    MCD_OPC_Decode, 232, 4, 84, // Opcode: LFSU
/* 5902 */    MCD_OPC_FilterValue, 50, 4, 0, // Skip to: 5910
/* 5906 */    MCD_OPC_Decode, 225, 4, 85, // Opcode: LFD
/* 5910 */    MCD_OPC_FilterValue, 51, 4, 0, // Skip to: 5918
/* 5914 */    MCD_OPC_Decode, 226, 4, 85, // Opcode: LFDU
/* 5918 */    MCD_OPC_FilterValue, 52, 4, 0, // Skip to: 5926
/* 5922 */    MCD_OPC_Decode, 216, 6, 84, // Opcode: STFS
/* 5926 */    MCD_OPC_FilterValue, 53, 4, 0, // Skip to: 5934
/* 5930 */    MCD_OPC_Decode, 217, 6, 84, // Opcode: STFSU
/* 5934 */    MCD_OPC_FilterValue, 54, 4, 0, // Skip to: 5942
/* 5938 */    MCD_OPC_Decode, 211, 6, 85, // Opcode: STFD
/* 5942 */    MCD_OPC_FilterValue, 55, 4, 0, // Skip to: 5950
/* 5946 */    MCD_OPC_Decode, 212, 6, 85, // Opcode: STFDU
/* 5950 */    MCD_OPC_FilterValue, 58, 27, 0, // Skip to: 5981
/* 5954 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 5957 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 5965
/* 5961 */    MCD_OPC_Decode, 212, 4, 86, // Opcode: LD
/* 5965 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 5973
/* 5969 */    MCD_OPC_Decode, 215, 4, 86, // Opcode: LDU
/* 5973 */    MCD_OPC_FilterValue, 2, 67, 13, // Skip to: 9372
/* 5977 */    MCD_OPC_Decode, 137, 5, 86, // Opcode: LWA
/* 5981 */    MCD_OPC_FilterValue, 59, 113, 1, // Skip to: 6354
/* 5985 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 5988 */    MCD_OPC_FilterValue, 28, 31, 0, // Skip to: 6023
/* 5992 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 5995 */    MCD_OPC_FilterValue, 26, 10, 0, // Skip to: 6009
/* 5999 */    MCD_OPC_CheckField, 16, 5, 0, 39, 13, // Skip to: 9372
/* 6005 */    MCD_OPC_Decode, 217, 3, 87, // Opcode: FCFIDS
/* 6009 */    MCD_OPC_FilterValue, 30, 31, 13, // Skip to: 9372
/* 6013 */    MCD_OPC_CheckField, 16, 5, 0, 25, 13, // Skip to: 9372
/* 6019 */    MCD_OPC_Decode, 220, 3, 87, // Opcode: FCFIDUS
/* 6023 */    MCD_OPC_FilterValue, 29, 31, 0, // Skip to: 6058
/* 6027 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 6030 */    MCD_OPC_FilterValue, 26, 10, 0, // Skip to: 6044
/* 6034 */    MCD_OPC_CheckField, 16, 5, 0, 4, 13, // Skip to: 9372
/* 6040 */    MCD_OPC_Decode, 218, 3, 87, // Opcode: FCFIDSo
/* 6044 */    MCD_OPC_FilterValue, 30, 252, 12, // Skip to: 9372
/* 6048 */    MCD_OPC_CheckField, 16, 5, 0, 246, 12, // Skip to: 9372
/* 6054 */    MCD_OPC_Decode, 221, 3, 87, // Opcode: FCFIDUSo
/* 6058 */    MCD_OPC_FilterValue, 36, 10, 0, // Skip to: 6072
/* 6062 */    MCD_OPC_CheckField, 6, 5, 0, 232, 12, // Skip to: 9372
/* 6068 */    MCD_OPC_Decode, 243, 3, 88, // Opcode: FDIVS
/* 6072 */    MCD_OPC_FilterValue, 37, 10, 0, // Skip to: 6086
/* 6076 */    MCD_OPC_CheckField, 6, 5, 0, 218, 12, // Skip to: 9372
/* 6082 */    MCD_OPC_Decode, 244, 3, 88, // Opcode: FDIVSo
/* 6086 */    MCD_OPC_FilterValue, 40, 10, 0, // Skip to: 6100
/* 6090 */    MCD_OPC_CheckField, 6, 5, 0, 204, 12, // Skip to: 9372
/* 6096 */    MCD_OPC_Decode, 183, 4, 88, // Opcode: FSUBS
/* 6100 */    MCD_OPC_FilterValue, 41, 10, 0, // Skip to: 6114
/* 6104 */    MCD_OPC_CheckField, 6, 5, 0, 190, 12, // Skip to: 9372
/* 6110 */    MCD_OPC_Decode, 184, 4, 88, // Opcode: FSUBSo
/* 6114 */    MCD_OPC_FilterValue, 42, 10, 0, // Skip to: 6128
/* 6118 */    MCD_OPC_CheckField, 6, 5, 0, 176, 12, // Skip to: 9372
/* 6124 */    MCD_OPC_Decode, 212, 3, 88, // Opcode: FADDS
/* 6128 */    MCD_OPC_FilterValue, 43, 10, 0, // Skip to: 6142
/* 6132 */    MCD_OPC_CheckField, 6, 5, 0, 162, 12, // Skip to: 9372
/* 6138 */    MCD_OPC_Decode, 213, 3, 88, // Opcode: FADDSo
/* 6142 */    MCD_OPC_FilterValue, 44, 16, 0, // Skip to: 6162
/* 6146 */    MCD_OPC_CheckField, 16, 5, 0, 148, 12, // Skip to: 9372
/* 6152 */    MCD_OPC_CheckField, 6, 5, 0, 142, 12, // Skip to: 9372
/* 6158 */    MCD_OPC_Decode, 179, 4, 89, // Opcode: FSQRTS
/* 6162 */    MCD_OPC_FilterValue, 45, 16, 0, // Skip to: 6182
/* 6166 */    MCD_OPC_CheckField, 16, 5, 0, 128, 12, // Skip to: 9372
/* 6172 */    MCD_OPC_CheckField, 6, 5, 0, 122, 12, // Skip to: 9372
/* 6178 */    MCD_OPC_Decode, 180, 4, 89, // Opcode: FSQRTSo
/* 6182 */    MCD_OPC_FilterValue, 48, 16, 0, // Skip to: 6202
/* 6186 */    MCD_OPC_CheckField, 16, 5, 0, 108, 12, // Skip to: 9372
/* 6192 */    MCD_OPC_CheckField, 6, 5, 0, 102, 12, // Skip to: 9372
/* 6198 */    MCD_OPC_Decode, 149, 4, 89, // Opcode: FRES
/* 6202 */    MCD_OPC_FilterValue, 49, 16, 0, // Skip to: 6222
/* 6206 */    MCD_OPC_CheckField, 16, 5, 0, 88, 12, // Skip to: 9372
/* 6212 */    MCD_OPC_CheckField, 6, 5, 0, 82, 12, // Skip to: 9372
/* 6218 */    MCD_OPC_Decode, 150, 4, 89, // Opcode: FRESo
/* 6222 */    MCD_OPC_FilterValue, 50, 10, 0, // Skip to: 6236
/* 6226 */    MCD_OPC_CheckField, 11, 5, 0, 68, 12, // Skip to: 9372
/* 6232 */    MCD_OPC_Decode, 129, 4, 90, // Opcode: FMULS
/* 6236 */    MCD_OPC_FilterValue, 51, 10, 0, // Skip to: 6250
/* 6240 */    MCD_OPC_CheckField, 11, 5, 0, 54, 12, // Skip to: 9372
/* 6246 */    MCD_OPC_Decode, 130, 4, 90, // Opcode: FMULSo
/* 6250 */    MCD_OPC_FilterValue, 52, 16, 0, // Skip to: 6270
/* 6254 */    MCD_OPC_CheckField, 16, 5, 0, 40, 12, // Skip to: 9372
/* 6260 */    MCD_OPC_CheckField, 6, 5, 0, 34, 12, // Skip to: 9372
/* 6266 */    MCD_OPC_Decode, 171, 4, 89, // Opcode: FRSQRTES
/* 6270 */    MCD_OPC_FilterValue, 53, 16, 0, // Skip to: 6290
/* 6274 */    MCD_OPC_CheckField, 16, 5, 0, 20, 12, // Skip to: 9372
/* 6280 */    MCD_OPC_CheckField, 6, 5, 0, 14, 12, // Skip to: 9372
/* 6286 */    MCD_OPC_Decode, 172, 4, 89, // Opcode: FRSQRTESo
/* 6290 */    MCD_OPC_FilterValue, 56, 4, 0, // Skip to: 6298
/* 6294 */    MCD_OPC_Decode, 253, 3, 91, // Opcode: FMSUBS
/* 6298 */    MCD_OPC_FilterValue, 57, 4, 0, // Skip to: 6306
/* 6302 */    MCD_OPC_Decode, 254, 3, 91, // Opcode: FMSUBSo
/* 6306 */    MCD_OPC_FilterValue, 58, 4, 0, // Skip to: 6314
/* 6310 */    MCD_OPC_Decode, 247, 3, 91, // Opcode: FMADDS
/* 6314 */    MCD_OPC_FilterValue, 59, 4, 0, // Skip to: 6322
/* 6318 */    MCD_OPC_Decode, 248, 3, 91, // Opcode: FMADDSo
/* 6322 */    MCD_OPC_FilterValue, 60, 4, 0, // Skip to: 6330
/* 6326 */    MCD_OPC_Decode, 145, 4, 91, // Opcode: FNMSUBS
/* 6330 */    MCD_OPC_FilterValue, 61, 4, 0, // Skip to: 6338
/* 6334 */    MCD_OPC_Decode, 146, 4, 91, // Opcode: FNMSUBSo
/* 6338 */    MCD_OPC_FilterValue, 62, 4, 0, // Skip to: 6346
/* 6342 */    MCD_OPC_Decode, 141, 4, 91, // Opcode: FNMADDS
/* 6346 */    MCD_OPC_FilterValue, 63, 206, 11, // Skip to: 9372
/* 6350 */    MCD_OPC_Decode, 142, 4, 91, // Opcode: FNMADDSo
/* 6354 */    MCD_OPC_FilterValue, 60, 250, 7, // Skip to: 8400
/* 6358 */    MCD_OPC_ExtractField, 4, 2,  // Inst{5-4} ...
/* 6361 */    MCD_OPC_FilterValue, 0, 16, 2, // Skip to: 6893
/* 6365 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 6368 */    MCD_OPC_FilterValue, 4, 19, 0, // Skip to: 6391
/* 6372 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6375 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6383
/* 6379 */    MCD_OPC_Decode, 230, 8, 92, // Opcode: XSADDDP
/* 6383 */    MCD_OPC_FilterValue, 1, 169, 11, // Skip to: 9372
/* 6387 */    MCD_OPC_Decode, 243, 8, 93, // Opcode: XSMADDADP
/* 6391 */    MCD_OPC_FilterValue, 5, 19, 0, // Skip to: 6414
/* 6395 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6398 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6406
/* 6402 */    MCD_OPC_Decode, 136, 9, 92, // Opcode: XSSUBDP
/* 6406 */    MCD_OPC_FilterValue, 1, 146, 11, // Skip to: 9372
/* 6410 */    MCD_OPC_Decode, 244, 8, 93, // Opcode: XSMADDMDP
/* 6414 */    MCD_OPC_FilterValue, 6, 19, 0, // Skip to: 6437
/* 6418 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6421 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6429
/* 6425 */    MCD_OPC_Decode, 249, 8, 92, // Opcode: XSMULDP
/* 6429 */    MCD_OPC_FilterValue, 1, 123, 11, // Skip to: 9372
/* 6433 */    MCD_OPC_Decode, 247, 8, 93, // Opcode: XSMSUBADP
/* 6437 */    MCD_OPC_FilterValue, 7, 19, 0, // Skip to: 6460
/* 6441 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6444 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6452
/* 6448 */    MCD_OPC_Decode, 242, 8, 92, // Opcode: XSDIVDP
/* 6452 */    MCD_OPC_FilterValue, 1, 100, 11, // Skip to: 9372
/* 6456 */    MCD_OPC_Decode, 248, 8, 93, // Opcode: XSMSUBMDP
/* 6460 */    MCD_OPC_FilterValue, 8, 19, 0, // Skip to: 6483
/* 6464 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6467 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6475
/* 6471 */    MCD_OPC_Decode, 142, 9, 94, // Opcode: XVADDSP
/* 6475 */    MCD_OPC_FilterValue, 1, 77, 11, // Skip to: 9372
/* 6479 */    MCD_OPC_Decode, 178, 9, 95, // Opcode: XVMADDASP
/* 6483 */    MCD_OPC_FilterValue, 9, 19, 0, // Skip to: 6506
/* 6487 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6490 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6498
/* 6494 */    MCD_OPC_Decode, 220, 9, 94, // Opcode: XVSUBSP
/* 6498 */    MCD_OPC_FilterValue, 1, 54, 11, // Skip to: 9372
/* 6502 */    MCD_OPC_Decode, 180, 9, 95, // Opcode: XVMADDMSP
/* 6506 */    MCD_OPC_FilterValue, 10, 19, 0, // Skip to: 6529
/* 6510 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6513 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6521
/* 6517 */    MCD_OPC_Decode, 190, 9, 94, // Opcode: XVMULSP
/* 6521 */    MCD_OPC_FilterValue, 1, 31, 11, // Skip to: 9372
/* 6525 */    MCD_OPC_Decode, 186, 9, 95, // Opcode: XVMSUBASP
/* 6529 */    MCD_OPC_FilterValue, 11, 19, 0, // Skip to: 6552
/* 6533 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6536 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6544
/* 6540 */    MCD_OPC_Decode, 176, 9, 94, // Opcode: XVDIVSP
/* 6544 */    MCD_OPC_FilterValue, 1, 8, 11, // Skip to: 9372
/* 6548 */    MCD_OPC_Decode, 188, 9, 95, // Opcode: XVMSUBMSP
/* 6552 */    MCD_OPC_FilterValue, 12, 19, 0, // Skip to: 6575
/* 6556 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6559 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6567
/* 6563 */    MCD_OPC_Decode, 141, 9, 94, // Opcode: XVADDDP
/* 6567 */    MCD_OPC_FilterValue, 1, 241, 10, // Skip to: 9372
/* 6571 */    MCD_OPC_Decode, 177, 9, 95, // Opcode: XVMADDADP
/* 6575 */    MCD_OPC_FilterValue, 13, 19, 0, // Skip to: 6598
/* 6579 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6582 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6590
/* 6586 */    MCD_OPC_Decode, 219, 9, 94, // Opcode: XVSUBDP
/* 6590 */    MCD_OPC_FilterValue, 1, 218, 10, // Skip to: 9372
/* 6594 */    MCD_OPC_Decode, 179, 9, 95, // Opcode: XVMADDMDP
/* 6598 */    MCD_OPC_FilterValue, 14, 19, 0, // Skip to: 6621
/* 6602 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6605 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6613
/* 6609 */    MCD_OPC_Decode, 189, 9, 94, // Opcode: XVMULDP
/* 6613 */    MCD_OPC_FilterValue, 1, 195, 10, // Skip to: 9372
/* 6617 */    MCD_OPC_Decode, 185, 9, 95, // Opcode: XVMSUBADP
/* 6621 */    MCD_OPC_FilterValue, 15, 19, 0, // Skip to: 6644
/* 6625 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6628 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6636
/* 6632 */    MCD_OPC_Decode, 175, 9, 94, // Opcode: XVDIVDP
/* 6636 */    MCD_OPC_FilterValue, 1, 172, 10, // Skip to: 9372
/* 6640 */    MCD_OPC_Decode, 187, 9, 95, // Opcode: XVMSUBMDP
/* 6644 */    MCD_OPC_FilterValue, 20, 19, 0, // Skip to: 6667
/* 6648 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6651 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6659
/* 6655 */    MCD_OPC_Decode, 245, 8, 92, // Opcode: XSMAXDP
/* 6659 */    MCD_OPC_FilterValue, 1, 149, 10, // Skip to: 9372
/* 6663 */    MCD_OPC_Decode, 252, 8, 93, // Opcode: XSNMADDADP
/* 6667 */    MCD_OPC_FilterValue, 21, 19, 0, // Skip to: 6690
/* 6671 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6674 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6682
/* 6678 */    MCD_OPC_Decode, 246, 8, 92, // Opcode: XSMINDP
/* 6682 */    MCD_OPC_FilterValue, 1, 126, 10, // Skip to: 9372
/* 6686 */    MCD_OPC_Decode, 253, 8, 93, // Opcode: XSNMADDMDP
/* 6690 */    MCD_OPC_FilterValue, 22, 19, 0, // Skip to: 6713
/* 6694 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6697 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6705
/* 6701 */    MCD_OPC_Decode, 233, 8, 92, // Opcode: XSCPSGNDP
/* 6705 */    MCD_OPC_FilterValue, 1, 103, 10, // Skip to: 9372
/* 6709 */    MCD_OPC_Decode, 254, 8, 93, // Opcode: XSNMSUBADP
/* 6713 */    MCD_OPC_FilterValue, 23, 10, 0, // Skip to: 6727
/* 6717 */    MCD_OPC_CheckField, 3, 1, 1, 89, 10, // Skip to: 9372
/* 6723 */    MCD_OPC_Decode, 255, 8, 93, // Opcode: XSNMSUBMDP
/* 6727 */    MCD_OPC_FilterValue, 24, 19, 0, // Skip to: 6750
/* 6731 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6734 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6742
/* 6738 */    MCD_OPC_Decode, 182, 9, 94, // Opcode: XVMAXSP
/* 6742 */    MCD_OPC_FilterValue, 1, 66, 10, // Skip to: 9372
/* 6746 */    MCD_OPC_Decode, 196, 9, 95, // Opcode: XVNMADDASP
/* 6750 */    MCD_OPC_FilterValue, 25, 19, 0, // Skip to: 6773
/* 6754 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6757 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6765
/* 6761 */    MCD_OPC_Decode, 184, 9, 94, // Opcode: XVMINSP
/* 6765 */    MCD_OPC_FilterValue, 1, 43, 10, // Skip to: 9372
/* 6769 */    MCD_OPC_Decode, 198, 9, 95, // Opcode: XVNMADDMSP
/* 6773 */    MCD_OPC_FilterValue, 26, 19, 0, // Skip to: 6796
/* 6777 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6780 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6788
/* 6784 */    MCD_OPC_Decode, 156, 9, 94, // Opcode: XVCPSGNSP
/* 6788 */    MCD_OPC_FilterValue, 1, 20, 10, // Skip to: 9372
/* 6792 */    MCD_OPC_Decode, 200, 9, 95, // Opcode: XVNMSUBASP
/* 6796 */    MCD_OPC_FilterValue, 27, 10, 0, // Skip to: 6810
/* 6800 */    MCD_OPC_CheckField, 3, 1, 1, 6, 10, // Skip to: 9372
/* 6806 */    MCD_OPC_Decode, 202, 9, 95, // Opcode: XVNMSUBMSP
/* 6810 */    MCD_OPC_FilterValue, 28, 19, 0, // Skip to: 6833
/* 6814 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6817 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6825
/* 6821 */    MCD_OPC_Decode, 181, 9, 94, // Opcode: XVMAXDP
/* 6825 */    MCD_OPC_FilterValue, 1, 239, 9, // Skip to: 9372
/* 6829 */    MCD_OPC_Decode, 195, 9, 95, // Opcode: XVNMADDADP
/* 6833 */    MCD_OPC_FilterValue, 29, 19, 0, // Skip to: 6856
/* 6837 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6840 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6848
/* 6844 */    MCD_OPC_Decode, 183, 9, 94, // Opcode: XVMINDP
/* 6848 */    MCD_OPC_FilterValue, 1, 216, 9, // Skip to: 9372
/* 6852 */    MCD_OPC_Decode, 197, 9, 95, // Opcode: XVNMADDMDP
/* 6856 */    MCD_OPC_FilterValue, 30, 19, 0, // Skip to: 6879
/* 6860 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6863 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6871
/* 6867 */    MCD_OPC_Decode, 155, 9, 94, // Opcode: XVCPSGNDP
/* 6871 */    MCD_OPC_FilterValue, 1, 193, 9, // Skip to: 9372
/* 6875 */    MCD_OPC_Decode, 199, 9, 95, // Opcode: XVNMSUBADP
/* 6879 */    MCD_OPC_FilterValue, 31, 185, 9, // Skip to: 9372
/* 6883 */    MCD_OPC_CheckField, 3, 1, 1, 179, 9, // Skip to: 9372
/* 6889 */    MCD_OPC_Decode, 201, 9, 95, // Opcode: XVNMSUBMDP
/* 6893 */    MCD_OPC_FilterValue, 1, 92, 1, // Skip to: 7245
/* 6897 */    MCD_OPC_ExtractField, 6, 2,  // Inst{7-6} ...
/* 6900 */    MCD_OPC_FilterValue, 0, 100, 0, // Skip to: 7004
/* 6904 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 6907 */    MCD_OPC_FilterValue, 0, 34, 0, // Skip to: 6945
/* 6911 */    MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 6914 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6922
/* 6918 */    MCD_OPC_Decode, 235, 9, 96, // Opcode: XXSLDWI
/* 6922 */    MCD_OPC_FilterValue, 1, 142, 9, // Skip to: 9372
/* 6926 */    MCD_OPC_ExtractField, 8, 2,  // Inst{9-8} ...
/* 6929 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 6937
/* 6933 */    MCD_OPC_Decode, 225, 9, 94, // Opcode: XXLAND
/* 6937 */    MCD_OPC_FilterValue, 1, 127, 9, // Skip to: 9372
/* 6941 */    MCD_OPC_Decode, 227, 9, 94, // Opcode: XXLNOR
/* 6945 */    MCD_OPC_FilterValue, 1, 119, 9, // Skip to: 9372
/* 6949 */    MCD_OPC_ExtractField, 8, 3,  // Inst{10-8} ...
/* 6952 */    MCD_OPC_FilterValue, 1, 16, 0, // Skip to: 6972
/* 6956 */    MCD_OPC_CheckField, 21, 2, 0, 106, 9, // Skip to: 9372
/* 6962 */    MCD_OPC_CheckField, 0, 1, 0, 100, 9, // Skip to: 9372
/* 6968 */    MCD_OPC_Decode, 232, 8, 97, // Opcode: XSCMPUDP
/* 6972 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 6980
/* 6976 */    MCD_OPC_Decode, 145, 9, 94, // Opcode: XVCMPEQSP
/* 6980 */    MCD_OPC_FilterValue, 3, 4, 0, // Skip to: 6988
/* 6984 */    MCD_OPC_Decode, 143, 9, 94, // Opcode: XVCMPEQDP
/* 6988 */    MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 6996
/* 6992 */    MCD_OPC_Decode, 146, 9, 94, // Opcode: XVCMPEQSPo
/* 6996 */    MCD_OPC_FilterValue, 7, 68, 9, // Skip to: 9372
/* 7000 */    MCD_OPC_Decode, 144, 9, 94, // Opcode: XVCMPEQDPo
/* 7004 */    MCD_OPC_FilterValue, 1, 91, 0, // Skip to: 7099
/* 7008 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 7011 */    MCD_OPC_FilterValue, 0, 25, 0, // Skip to: 7040
/* 7015 */    MCD_OPC_ExtractField, 10, 1,  // Inst{10} ...
/* 7018 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 7026
/* 7022 */    MCD_OPC_Decode, 233, 9, 96, // Opcode: XXPERMDI
/* 7026 */    MCD_OPC_FilterValue, 1, 38, 9, // Skip to: 9372
/* 7030 */    MCD_OPC_CheckField, 8, 2, 0, 32, 9, // Skip to: 9372
/* 7036 */    MCD_OPC_Decode, 226, 9, 94, // Opcode: XXLANDC
/* 7040 */    MCD_OPC_FilterValue, 1, 24, 9, // Skip to: 9372
/* 7044 */    MCD_OPC_ExtractField, 8, 3,  // Inst{10-8} ...
/* 7047 */    MCD_OPC_FilterValue, 1, 16, 0, // Skip to: 7067
/* 7051 */    MCD_OPC_CheckField, 21, 2, 0, 11, 9, // Skip to: 9372
/* 7057 */    MCD_OPC_CheckField, 0, 1, 0, 5, 9, // Skip to: 9372
/* 7063 */    MCD_OPC_Decode, 231, 8, 97, // Opcode: XSCMPODP
/* 7067 */    MCD_OPC_FilterValue, 2, 4, 0, // Skip to: 7075
/* 7071 */    MCD_OPC_Decode, 153, 9, 94, // Opcode: XVCMPGTSP
/* 7075 */    MCD_OPC_FilterValue, 3, 4, 0, // Skip to: 7083
/* 7079 */    MCD_OPC_Decode, 151, 9, 94, // Opcode: XVCMPGTDP
/* 7083 */    MCD_OPC_FilterValue, 6, 4, 0, // Skip to: 7091
/* 7087 */    MCD_OPC_Decode, 154, 9, 94, // Opcode: XVCMPGTSPo
/* 7091 */    MCD_OPC_FilterValue, 7, 229, 8, // Skip to: 9372
/* 7095 */    MCD_OPC_Decode, 152, 9, 94, // Opcode: XVCMPGTDPo
/* 7099 */    MCD_OPC_FilterValue, 2, 122, 0, // Skip to: 7225
/* 7103 */    MCD_OPC_ExtractField, 8, 3,  // Inst{10-8} ...
/* 7106 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 7120
/* 7110 */    MCD_OPC_CheckField, 3, 1, 0, 208, 8, // Skip to: 9372
/* 7116 */    MCD_OPC_Decode, 231, 9, 94, // Opcode: XXMRGHW
/* 7120 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 7134
/* 7124 */    MCD_OPC_CheckField, 3, 1, 0, 194, 8, // Skip to: 9372
/* 7130 */    MCD_OPC_Decode, 232, 9, 94, // Opcode: XXMRGLW
/* 7134 */    MCD_OPC_FilterValue, 2, 31, 0, // Skip to: 7169
/* 7138 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 7141 */    MCD_OPC_FilterValue, 0, 16, 0, // Skip to: 7161
/* 7145 */    MCD_OPC_CheckField, 18, 3, 0, 173, 8, // Skip to: 9372
/* 7151 */    MCD_OPC_CheckField, 2, 1, 0, 167, 8, // Skip to: 9372
/* 7157 */    MCD_OPC_Decode, 236, 9, 98, // Opcode: XXSPLTW
/* 7161 */    MCD_OPC_FilterValue, 1, 159, 8, // Skip to: 9372
/* 7165 */    MCD_OPC_Decode, 149, 9, 94, // Opcode: XVCMPGESP
/* 7169 */    MCD_OPC_FilterValue, 3, 10, 0, // Skip to: 7183
/* 7173 */    MCD_OPC_CheckField, 3, 1, 1, 145, 8, // Skip to: 9372
/* 7179 */    MCD_OPC_Decode, 147, 9, 94, // Opcode: XVCMPGEDP
/* 7183 */    MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 7197
/* 7187 */    MCD_OPC_CheckField, 3, 1, 0, 131, 8, // Skip to: 9372
/* 7193 */    MCD_OPC_Decode, 228, 9, 94, // Opcode: XXLOR
/* 7197 */    MCD_OPC_FilterValue, 6, 10, 0, // Skip to: 7211
/* 7201 */    MCD_OPC_CheckField, 3, 1, 1, 117, 8, // Skip to: 9372
/* 7207 */    MCD_OPC_Decode, 150, 9, 94, // Opcode: XVCMPGESPo
/* 7211 */    MCD_OPC_FilterValue, 7, 109, 8, // Skip to: 9372
/* 7215 */    MCD_OPC_CheckField, 3, 1, 1, 103, 8, // Skip to: 9372
/* 7221 */    MCD_OPC_Decode, 148, 9, 94, // Opcode: XVCMPGEDPo
/* 7225 */    MCD_OPC_FilterValue, 3, 95, 8, // Skip to: 9372
/* 7229 */    MCD_OPC_CheckField, 8, 3, 4, 89, 8, // Skip to: 9372
/* 7235 */    MCD_OPC_CheckField, 3, 1, 0, 83, 8, // Skip to: 9372
/* 7241 */    MCD_OPC_Decode, 230, 9, 94, // Opcode: XXLXOR
/* 7245 */    MCD_OPC_FilterValue, 2, 119, 4, // Skip to: 8392
/* 7249 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 7252 */    MCD_OPC_FilterValue, 4, 59, 0, // Skip to: 7315
/* 7256 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 7259 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 7273
/* 7263 */    MCD_OPC_CheckField, 16, 5, 0, 55, 8, // Skip to: 9372
/* 7269 */    MCD_OPC_Decode, 238, 8, 99, // Opcode: XSCVDPUXWS
/* 7273 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 7287
/* 7277 */    MCD_OPC_CheckField, 16, 5, 0, 41, 8, // Skip to: 9372
/* 7283 */    MCD_OPC_Decode, 128, 9, 99, // Opcode: XSRDPI
/* 7287 */    MCD_OPC_FilterValue, 2, 10, 0, // Skip to: 7301
/* 7291 */    MCD_OPC_CheckField, 16, 5, 0, 27, 8, // Skip to: 9372
/* 7297 */    MCD_OPC_Decode, 134, 9, 99, // Opcode: XSRSQRTEDP
/* 7301 */    MCD_OPC_FilterValue, 3, 19, 8, // Skip to: 9372
/* 7305 */    MCD_OPC_CheckField, 16, 5, 0, 13, 8, // Skip to: 9372
/* 7311 */    MCD_OPC_Decode, 135, 9, 99, // Opcode: XSSQRTDP
/* 7315 */    MCD_OPC_FilterValue, 5, 45, 0, // Skip to: 7364
/* 7319 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 7322 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 7336
/* 7326 */    MCD_OPC_CheckField, 16, 5, 0, 248, 7, // Skip to: 9372
/* 7332 */    MCD_OPC_Decode, 236, 8, 99, // Opcode: XSCVDPSXWS
/* 7336 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 7350
/* 7340 */    MCD_OPC_CheckField, 16, 5, 0, 234, 7, // Skip to: 9372
/* 7346 */    MCD_OPC_Decode, 132, 9, 99, // Opcode: XSRDPIZ
/* 7350 */    MCD_OPC_FilterValue, 2, 226, 7, // Skip to: 9372
/* 7354 */    MCD_OPC_CheckField, 16, 5, 0, 220, 7, // Skip to: 9372
/* 7360 */    MCD_OPC_Decode, 133, 9, 99, // Opcode: XSREDP
/* 7364 */    MCD_OPC_FilterValue, 6, 51, 0, // Skip to: 7419
/* 7368 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 7371 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 7385
/* 7375 */    MCD_OPC_CheckField, 16, 5, 0, 199, 7, // Skip to: 9372
/* 7381 */    MCD_OPC_Decode, 131, 9, 99, // Opcode: XSRDPIP
/* 7385 */    MCD_OPC_FilterValue, 2, 16, 0, // Skip to: 7405
/* 7389 */    MCD_OPC_CheckField, 16, 7, 0, 185, 7, // Skip to: 9372
/* 7395 */    MCD_OPC_CheckField, 0, 1, 0, 179, 7, // Skip to: 9372
/* 7401 */    MCD_OPC_Decode, 138, 9, 100, // Opcode: XSTSQRTDP
/* 7405 */    MCD_OPC_FilterValue, 3, 171, 7, // Skip to: 9372
/* 7409 */    MCD_OPC_CheckField, 16, 5, 0, 165, 7, // Skip to: 9372
/* 7415 */    MCD_OPC_Decode, 129, 9, 99, // Opcode: XSRDPIC
/* 7419 */    MCD_OPC_FilterValue, 7, 43, 0, // Skip to: 7466
/* 7423 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 7426 */    MCD_OPC_FilterValue, 0, 16, 0, // Skip to: 7446
/* 7430 */    MCD_OPC_CheckField, 16, 5, 0, 144, 7, // Skip to: 9372
/* 7436 */    MCD_OPC_CheckField, 2, 1, 1, 138, 7, // Skip to: 9372
/* 7442 */    MCD_OPC_Decode, 130, 9, 99, // Opcode: XSRDPIM
/* 7446 */    MCD_OPC_FilterValue, 1, 130, 7, // Skip to: 9372
/* 7450 */    MCD_OPC_CheckField, 21, 2, 0, 124, 7, // Skip to: 9372
/* 7456 */    MCD_OPC_CheckField, 0, 1, 0, 118, 7, // Skip to: 9372
/* 7462 */    MCD_OPC_Decode, 137, 9, 97, // Opcode: XSTDIVDP
/* 7466 */    MCD_OPC_FilterValue, 8, 59, 0, // Skip to: 7529
/* 7470 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 7473 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 7487
/* 7477 */    MCD_OPC_CheckField, 16, 5, 0, 97, 7, // Skip to: 9372
/* 7483 */    MCD_OPC_Decode, 166, 9, 101, // Opcode: XVCVSPUXWS
/* 7487 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 7501
/* 7491 */    MCD_OPC_CheckField, 16, 5, 0, 83, 7, // Skip to: 9372
/* 7497 */    MCD_OPC_Decode, 210, 9, 101, // Opcode: XVRSPI
/* 7501 */    MCD_OPC_FilterValue, 2, 10, 0, // Skip to: 7515
/* 7505 */    MCD_OPC_CheckField, 16, 5, 0, 69, 7, // Skip to: 9372
/* 7511 */    MCD_OPC_Decode, 216, 9, 101, // Opcode: XVRSQRTESP
/* 7515 */    MCD_OPC_FilterValue, 3, 61, 7, // Skip to: 9372
/* 7519 */    MCD_OPC_CheckField, 16, 5, 0, 55, 7, // Skip to: 9372
/* 7525 */    MCD_OPC_Decode, 218, 9, 101, // Opcode: XVSQRTSP
/* 7529 */    MCD_OPC_FilterValue, 9, 45, 0, // Skip to: 7578
/* 7533 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 7536 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 7550
/* 7540 */    MCD_OPC_CheckField, 16, 5, 0, 34, 7, // Skip to: 9372
/* 7546 */    MCD_OPC_Decode, 164, 9, 101, // Opcode: XVCVSPSXWS
/* 7550 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 7564
/* 7554 */    MCD_OPC_CheckField, 16, 5, 0, 20, 7, // Skip to: 9372
/* 7560 */    MCD_OPC_Decode, 214, 9, 101, // Opcode: XVRSPIZ
/* 7564 */    MCD_OPC_FilterValue, 2, 12, 7, // Skip to: 9372
/* 7568 */    MCD_OPC_CheckField, 16, 5, 0, 6, 7, // Skip to: 9372
/* 7574 */    MCD_OPC_Decode, 209, 9, 101, // Opcode: XVRESP
/* 7578 */    MCD_OPC_FilterValue, 10, 65, 0, // Skip to: 7647
/* 7582 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 7585 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 7599
/* 7589 */    MCD_OPC_CheckField, 16, 5, 0, 241, 6, // Skip to: 9372
/* 7595 */    MCD_OPC_Decode, 174, 9, 101, // Opcode: XVCVUXWSP
/* 7599 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 7613
/* 7603 */    MCD_OPC_CheckField, 16, 5, 0, 227, 6, // Skip to: 9372
/* 7609 */    MCD_OPC_Decode, 213, 9, 101, // Opcode: XVRSPIP
/* 7613 */    MCD_OPC_FilterValue, 2, 16, 0, // Skip to: 7633
/* 7617 */    MCD_OPC_CheckField, 16, 7, 0, 213, 6, // Skip to: 9372
/* 7623 */    MCD_OPC_CheckField, 0, 1, 0, 207, 6, // Skip to: 9372
/* 7629 */    MCD_OPC_Decode, 224, 9, 102, // Opcode: XVTSQRTSP
/* 7633 */    MCD_OPC_FilterValue, 3, 199, 6, // Skip to: 9372
/* 7637 */    MCD_OPC_CheckField, 16, 5, 0, 193, 6, // Skip to: 9372
/* 7643 */    MCD_OPC_Decode, 211, 9, 101, // Opcode: XVRSPIC
/* 7647 */    MCD_OPC_FilterValue, 11, 58, 0, // Skip to: 7709
/* 7651 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 7654 */    MCD_OPC_FilterValue, 0, 31, 0, // Skip to: 7689
/* 7658 */    MCD_OPC_ExtractField, 2, 1,  // Inst{2} ...
/* 7661 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 7675
/* 7665 */    MCD_OPC_CheckField, 16, 5, 0, 165, 6, // Skip to: 9372
/* 7671 */    MCD_OPC_Decode, 170, 9, 101, // Opcode: XVCVSXWSP
/* 7675 */    MCD_OPC_FilterValue, 1, 157, 6, // Skip to: 9372
/* 7679 */    MCD_OPC_CheckField, 16, 5, 0, 151, 6, // Skip to: 9372
/* 7685 */    MCD_OPC_Decode, 212, 9, 101, // Opcode: XVRSPIM
/* 7689 */    MCD_OPC_FilterValue, 1, 143, 6, // Skip to: 9372
/* 7693 */    MCD_OPC_CheckField, 21, 2, 0, 137, 6, // Skip to: 9372
/* 7699 */    MCD_OPC_CheckField, 0, 1, 0, 131, 6, // Skip to: 9372
/* 7705 */    MCD_OPC_Decode, 222, 9, 103, // Opcode: XVTDIVSP
/* 7709 */    MCD_OPC_FilterValue, 12, 59, 0, // Skip to: 7772
/* 7713 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 7716 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 7730
/* 7720 */    MCD_OPC_CheckField, 16, 5, 0, 110, 6, // Skip to: 9372
/* 7726 */    MCD_OPC_Decode, 161, 9, 101, // Opcode: XVCVDPUXWS
/* 7730 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 7744
/* 7734 */    MCD_OPC_CheckField, 16, 5, 0, 96, 6, // Skip to: 9372
/* 7740 */    MCD_OPC_Decode, 203, 9, 101, // Opcode: XVRDPI
/* 7744 */    MCD_OPC_FilterValue, 2, 10, 0, // Skip to: 7758
/* 7748 */    MCD_OPC_CheckField, 16, 5, 0, 82, 6, // Skip to: 9372
/* 7754 */    MCD_OPC_Decode, 215, 9, 101, // Opcode: XVRSQRTEDP
/* 7758 */    MCD_OPC_FilterValue, 3, 74, 6, // Skip to: 9372
/* 7762 */    MCD_OPC_CheckField, 16, 5, 0, 68, 6, // Skip to: 9372
/* 7768 */    MCD_OPC_Decode, 217, 9, 101, // Opcode: XVSQRTDP
/* 7772 */    MCD_OPC_FilterValue, 13, 45, 0, // Skip to: 7821
/* 7776 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 7779 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 7793
/* 7783 */    MCD_OPC_CheckField, 16, 5, 0, 47, 6, // Skip to: 9372
/* 7789 */    MCD_OPC_Decode, 159, 9, 101, // Opcode: XVCVDPSXWS
/* 7793 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 7807
/* 7797 */    MCD_OPC_CheckField, 16, 5, 0, 33, 6, // Skip to: 9372
/* 7803 */    MCD_OPC_Decode, 207, 9, 101, // Opcode: XVRDPIZ
/* 7807 */    MCD_OPC_FilterValue, 2, 25, 6, // Skip to: 9372
/* 7811 */    MCD_OPC_CheckField, 16, 5, 0, 19, 6, // Skip to: 9372
/* 7817 */    MCD_OPC_Decode, 208, 9, 101, // Opcode: XVREDP
/* 7821 */    MCD_OPC_FilterValue, 14, 65, 0, // Skip to: 7890
/* 7825 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 7828 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 7842
/* 7832 */    MCD_OPC_CheckField, 16, 5, 0, 254, 5, // Skip to: 9372
/* 7838 */    MCD_OPC_Decode, 173, 9, 101, // Opcode: XVCVUXWDP
/* 7842 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 7856
/* 7846 */    MCD_OPC_CheckField, 16, 5, 0, 240, 5, // Skip to: 9372
/* 7852 */    MCD_OPC_Decode, 206, 9, 101, // Opcode: XVRDPIP
/* 7856 */    MCD_OPC_FilterValue, 2, 16, 0, // Skip to: 7876
/* 7860 */    MCD_OPC_CheckField, 16, 7, 0, 226, 5, // Skip to: 9372
/* 7866 */    MCD_OPC_CheckField, 0, 1, 0, 220, 5, // Skip to: 9372
/* 7872 */    MCD_OPC_Decode, 223, 9, 102, // Opcode: XVTSQRTDP
/* 7876 */    MCD_OPC_FilterValue, 3, 212, 5, // Skip to: 9372
/* 7880 */    MCD_OPC_CheckField, 16, 5, 0, 206, 5, // Skip to: 9372
/* 7886 */    MCD_OPC_Decode, 204, 9, 101, // Opcode: XVRDPIC
/* 7890 */    MCD_OPC_FilterValue, 15, 58, 0, // Skip to: 7952
/* 7894 */    MCD_OPC_ExtractField, 3, 1,  // Inst{3} ...
/* 7897 */    MCD_OPC_FilterValue, 0, 31, 0, // Skip to: 7932
/* 7901 */    MCD_OPC_ExtractField, 2, 1,  // Inst{2} ...
/* 7904 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 7918
/* 7908 */    MCD_OPC_CheckField, 16, 5, 0, 178, 5, // Skip to: 9372
/* 7914 */    MCD_OPC_Decode, 169, 9, 101, // Opcode: XVCVSXWDP
/* 7918 */    MCD_OPC_FilterValue, 1, 170, 5, // Skip to: 9372
/* 7922 */    MCD_OPC_CheckField, 16, 5, 0, 164, 5, // Skip to: 9372
/* 7928 */    MCD_OPC_Decode, 205, 9, 101, // Opcode: XVRDPIM
/* 7932 */    MCD_OPC_FilterValue, 1, 156, 5, // Skip to: 9372
/* 7936 */    MCD_OPC_CheckField, 21, 2, 0, 150, 5, // Skip to: 9372
/* 7942 */    MCD_OPC_CheckField, 0, 1, 0, 144, 5, // Skip to: 9372
/* 7948 */    MCD_OPC_Decode, 221, 9, 103, // Opcode: XVTDIVDP
/* 7952 */    MCD_OPC_FilterValue, 16, 16, 0, // Skip to: 7972
/* 7956 */    MCD_OPC_CheckField, 16, 5, 0, 130, 5, // Skip to: 9372
/* 7962 */    MCD_OPC_CheckField, 2, 2, 1, 124, 5, // Skip to: 9372
/* 7968 */    MCD_OPC_Decode, 234, 8, 99, // Opcode: XSCVDPSP
/* 7972 */    MCD_OPC_FilterValue, 20, 31, 0, // Skip to: 8007
/* 7976 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 7979 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 7993
/* 7983 */    MCD_OPC_CheckField, 16, 5, 0, 103, 5, // Skip to: 9372
/* 7989 */    MCD_OPC_Decode, 237, 8, 99, // Opcode: XSCVDPUXDS
/* 7993 */    MCD_OPC_FilterValue, 1, 95, 5, // Skip to: 9372
/* 7997 */    MCD_OPC_CheckField, 16, 5, 0, 89, 5, // Skip to: 9372
/* 8003 */    MCD_OPC_Decode, 239, 8, 99, // Opcode: XSCVSPDP
/* 8007 */    MCD_OPC_FilterValue, 21, 31, 0, // Skip to: 8042
/* 8011 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 8014 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 8028
/* 8018 */    MCD_OPC_CheckField, 16, 5, 0, 68, 5, // Skip to: 9372
/* 8024 */    MCD_OPC_Decode, 235, 8, 99, // Opcode: XSCVDPSXDS
/* 8028 */    MCD_OPC_FilterValue, 1, 60, 5, // Skip to: 9372
/* 8032 */    MCD_OPC_CheckField, 16, 5, 0, 54, 5, // Skip to: 9372
/* 8038 */    MCD_OPC_Decode, 229, 8, 99, // Opcode: XSABSDP
/* 8042 */    MCD_OPC_FilterValue, 22, 31, 0, // Skip to: 8077
/* 8046 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 8049 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 8063
/* 8053 */    MCD_OPC_CheckField, 16, 5, 0, 33, 5, // Skip to: 9372
/* 8059 */    MCD_OPC_Decode, 241, 8, 99, // Opcode: XSCVUXDDP
/* 8063 */    MCD_OPC_FilterValue, 1, 25, 5, // Skip to: 9372
/* 8067 */    MCD_OPC_CheckField, 16, 5, 0, 19, 5, // Skip to: 9372
/* 8073 */    MCD_OPC_Decode, 250, 8, 99, // Opcode: XSNABSDP
/* 8077 */    MCD_OPC_FilterValue, 23, 31, 0, // Skip to: 8112
/* 8081 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 8084 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 8098
/* 8088 */    MCD_OPC_CheckField, 16, 5, 0, 254, 4, // Skip to: 9372
/* 8094 */    MCD_OPC_Decode, 240, 8, 99, // Opcode: XSCVSXDDP
/* 8098 */    MCD_OPC_FilterValue, 1, 246, 4, // Skip to: 9372
/* 8102 */    MCD_OPC_CheckField, 16, 5, 0, 240, 4, // Skip to: 9372
/* 8108 */    MCD_OPC_Decode, 251, 8, 99, // Opcode: XSNEGDP
/* 8112 */    MCD_OPC_FilterValue, 24, 31, 0, // Skip to: 8147
/* 8116 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 8119 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 8133
/* 8123 */    MCD_OPC_CheckField, 16, 5, 0, 219, 4, // Skip to: 9372
/* 8129 */    MCD_OPC_Decode, 165, 9, 101, // Opcode: XVCVSPUXDS
/* 8133 */    MCD_OPC_FilterValue, 1, 211, 4, // Skip to: 9372
/* 8137 */    MCD_OPC_CheckField, 16, 5, 0, 205, 4, // Skip to: 9372
/* 8143 */    MCD_OPC_Decode, 157, 9, 101, // Opcode: XVCVDPSP
/* 8147 */    MCD_OPC_FilterValue, 25, 31, 0, // Skip to: 8182
/* 8151 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 8154 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 8168
/* 8158 */    MCD_OPC_CheckField, 16, 5, 0, 184, 4, // Skip to: 9372
/* 8164 */    MCD_OPC_Decode, 163, 9, 101, // Opcode: XVCVSPSXDS
/* 8168 */    MCD_OPC_FilterValue, 1, 176, 4, // Skip to: 9372
/* 8172 */    MCD_OPC_CheckField, 16, 5, 0, 170, 4, // Skip to: 9372
/* 8178 */    MCD_OPC_Decode, 140, 9, 101, // Opcode: XVABSSP
/* 8182 */    MCD_OPC_FilterValue, 26, 31, 0, // Skip to: 8217
/* 8186 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 8189 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 8203
/* 8193 */    MCD_OPC_CheckField, 16, 5, 0, 149, 4, // Skip to: 9372
/* 8199 */    MCD_OPC_Decode, 172, 9, 101, // Opcode: XVCVUXDSP
/* 8203 */    MCD_OPC_FilterValue, 1, 141, 4, // Skip to: 9372
/* 8207 */    MCD_OPC_CheckField, 16, 5, 0, 135, 4, // Skip to: 9372
/* 8213 */    MCD_OPC_Decode, 192, 9, 101, // Opcode: XVNABSSP
/* 8217 */    MCD_OPC_FilterValue, 27, 31, 0, // Skip to: 8252
/* 8221 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 8224 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 8238
/* 8228 */    MCD_OPC_CheckField, 16, 5, 0, 114, 4, // Skip to: 9372
/* 8234 */    MCD_OPC_Decode, 168, 9, 101, // Opcode: XVCVSXDSP
/* 8238 */    MCD_OPC_FilterValue, 1, 106, 4, // Skip to: 9372
/* 8242 */    MCD_OPC_CheckField, 16, 5, 0, 100, 4, // Skip to: 9372
/* 8248 */    MCD_OPC_Decode, 194, 9, 101, // Opcode: XVNEGSP
/* 8252 */    MCD_OPC_FilterValue, 28, 31, 0, // Skip to: 8287
/* 8256 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 8259 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 8273
/* 8263 */    MCD_OPC_CheckField, 16, 5, 0, 79, 4, // Skip to: 9372
/* 8269 */    MCD_OPC_Decode, 160, 9, 101, // Opcode: XVCVDPUXDS
/* 8273 */    MCD_OPC_FilterValue, 1, 71, 4, // Skip to: 9372
/* 8277 */    MCD_OPC_CheckField, 16, 5, 0, 65, 4, // Skip to: 9372
/* 8283 */    MCD_OPC_Decode, 162, 9, 101, // Opcode: XVCVSPDP
/* 8287 */    MCD_OPC_FilterValue, 29, 31, 0, // Skip to: 8322
/* 8291 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 8294 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 8308
/* 8298 */    MCD_OPC_CheckField, 16, 5, 0, 44, 4, // Skip to: 9372
/* 8304 */    MCD_OPC_Decode, 158, 9, 101, // Opcode: XVCVDPSXDS
/* 8308 */    MCD_OPC_FilterValue, 1, 36, 4, // Skip to: 9372
/* 8312 */    MCD_OPC_CheckField, 16, 5, 0, 30, 4, // Skip to: 9372
/* 8318 */    MCD_OPC_Decode, 139, 9, 101, // Opcode: XVABSDP
/* 8322 */    MCD_OPC_FilterValue, 30, 31, 0, // Skip to: 8357
/* 8326 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 8329 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 8343
/* 8333 */    MCD_OPC_CheckField, 16, 5, 0, 9, 4, // Skip to: 9372
/* 8339 */    MCD_OPC_Decode, 171, 9, 101, // Opcode: XVCVUXDDP
/* 8343 */    MCD_OPC_FilterValue, 1, 1, 4, // Skip to: 9372
/* 8347 */    MCD_OPC_CheckField, 16, 5, 0, 251, 3, // Skip to: 9372
/* 8353 */    MCD_OPC_Decode, 191, 9, 101, // Opcode: XVNABSDP
/* 8357 */    MCD_OPC_FilterValue, 31, 243, 3, // Skip to: 9372
/* 8361 */    MCD_OPC_ExtractField, 2, 2,  // Inst{3-2} ...
/* 8364 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 8378
/* 8368 */    MCD_OPC_CheckField, 16, 5, 0, 230, 3, // Skip to: 9372
/* 8374 */    MCD_OPC_Decode, 167, 9, 101, // Opcode: XVCVSXDDP
/* 8378 */    MCD_OPC_FilterValue, 1, 222, 3, // Skip to: 9372
/* 8382 */    MCD_OPC_CheckField, 16, 5, 0, 216, 3, // Skip to: 9372
/* 8388 */    MCD_OPC_Decode, 193, 9, 101, // Opcode: XVNEGDP
/* 8392 */    MCD_OPC_FilterValue, 3, 208, 3, // Skip to: 9372
/* 8396 */    MCD_OPC_Decode, 234, 9, 104, // Opcode: XXSEL
/* 8400 */    MCD_OPC_FilterValue, 62, 19, 0, // Skip to: 8423
/* 8404 */    MCD_OPC_ExtractField, 0, 2,  // Inst{1-0} ...
/* 8407 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 8415
/* 8411 */    MCD_OPC_Decode, 205, 6, 86, // Opcode: STD
/* 8415 */    MCD_OPC_FilterValue, 1, 185, 3, // Skip to: 9372
/* 8419 */    MCD_OPC_Decode, 208, 6, 86, // Opcode: STDU
/* 8423 */    MCD_OPC_FilterValue, 63, 177, 3, // Skip to: 9372
/* 8427 */    MCD_OPC_ExtractField, 0, 6,  // Inst{5-0} ...
/* 8430 */    MCD_OPC_FilterValue, 0, 16, 0, // Skip to: 8450
/* 8434 */    MCD_OPC_CheckField, 21, 2, 0, 164, 3, // Skip to: 9372
/* 8440 */    MCD_OPC_CheckField, 6, 5, 0, 158, 3, // Skip to: 9372
/* 8446 */    MCD_OPC_Decode, 225, 3, 105, // Opcode: FCMPUS
/* 8450 */    MCD_OPC_FilterValue, 12, 19, 0, // Skip to: 8473
/* 8454 */    MCD_OPC_ExtractField, 6, 15,  // Inst{20-6} ...
/* 8457 */    MCD_OPC_FilterValue, 1, 4, 0, // Skip to: 8465
/* 8461 */    MCD_OPC_Decode, 187, 5, 76, // Opcode: MTFSB1
/* 8465 */    MCD_OPC_FilterValue, 2, 135, 3, // Skip to: 9372
/* 8469 */    MCD_OPC_Decode, 186, 5, 76, // Opcode: MTFSB0
/* 8473 */    MCD_OPC_FilterValue, 14, 37, 0, // Skip to: 8514
/* 8477 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 8480 */    MCD_OPC_FilterValue, 18, 10, 0, // Skip to: 8494
/* 8484 */    MCD_OPC_CheckField, 11, 10, 0, 114, 3, // Skip to: 9372
/* 8490 */    MCD_OPC_Decode, 164, 5, 106, // Opcode: MFFS
/* 8494 */    MCD_OPC_FilterValue, 22, 106, 3, // Skip to: 9372
/* 8498 */    MCD_OPC_CheckField, 25, 1, 0, 100, 3, // Skip to: 9372
/* 8504 */    MCD_OPC_CheckField, 16, 1, 0, 94, 3, // Skip to: 9372
/* 8510 */    MCD_OPC_Decode, 188, 5, 107, // Opcode: MTFSF
/* 8514 */    MCD_OPC_FilterValue, 16, 123, 0, // Skip to: 8641
/* 8518 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 8521 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 8529
/* 8525 */    MCD_OPC_Decode, 228, 3, 88, // Opcode: FCPSGNS
/* 8529 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 8543
/* 8533 */    MCD_OPC_CheckField, 16, 5, 0, 65, 3, // Skip to: 9372
/* 8539 */    MCD_OPC_Decode, 138, 4, 89, // Opcode: FNEGS
/* 8543 */    MCD_OPC_FilterValue, 2, 10, 0, // Skip to: 8557
/* 8547 */    MCD_OPC_CheckField, 16, 5, 0, 51, 3, // Skip to: 9372
/* 8553 */    MCD_OPC_Decode, 250, 3, 89, // Opcode: FMR
/* 8557 */    MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 8571
/* 8561 */    MCD_OPC_CheckField, 16, 5, 0, 37, 3, // Skip to: 9372
/* 8567 */    MCD_OPC_Decode, 134, 4, 89, // Opcode: FNABSS
/* 8571 */    MCD_OPC_FilterValue, 8, 10, 0, // Skip to: 8585
/* 8575 */    MCD_OPC_CheckField, 16, 5, 0, 23, 3, // Skip to: 9372
/* 8581 */    MCD_OPC_Decode, 209, 3, 89, // Opcode: FABSS
/* 8585 */    MCD_OPC_FilterValue, 12, 10, 0, // Skip to: 8599
/* 8589 */    MCD_OPC_CheckField, 16, 5, 0, 9, 3, // Skip to: 9372
/* 8595 */    MCD_OPC_Decode, 158, 4, 89, // Opcode: FRINS
/* 8599 */    MCD_OPC_FilterValue, 13, 10, 0, // Skip to: 8613
/* 8603 */    MCD_OPC_CheckField, 16, 5, 0, 251, 2, // Skip to: 9372
/* 8609 */    MCD_OPC_Decode, 166, 4, 89, // Opcode: FRIZS
/* 8613 */    MCD_OPC_FilterValue, 14, 10, 0, // Skip to: 8627
/* 8617 */    MCD_OPC_CheckField, 16, 5, 0, 237, 2, // Skip to: 9372
/* 8623 */    MCD_OPC_Decode, 162, 4, 89, // Opcode: FRIPS
/* 8627 */    MCD_OPC_FilterValue, 15, 229, 2, // Skip to: 9372
/* 8631 */    MCD_OPC_CheckField, 16, 5, 0, 223, 2, // Skip to: 9372
/* 8637 */    MCD_OPC_Decode, 154, 4, 89, // Opcode: FRIMS
/* 8641 */    MCD_OPC_FilterValue, 17, 123, 0, // Skip to: 8768
/* 8645 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 8648 */    MCD_OPC_FilterValue, 0, 4, 0, // Skip to: 8656
/* 8652 */    MCD_OPC_Decode, 229, 3, 88, // Opcode: FCPSGNSo
/* 8656 */    MCD_OPC_FilterValue, 1, 10, 0, // Skip to: 8670
/* 8660 */    MCD_OPC_CheckField, 16, 5, 0, 194, 2, // Skip to: 9372
/* 8666 */    MCD_OPC_Decode, 139, 4, 89, // Opcode: FNEGSo
/* 8670 */    MCD_OPC_FilterValue, 2, 10, 0, // Skip to: 8684
/* 8674 */    MCD_OPC_CheckField, 16, 5, 0, 180, 2, // Skip to: 9372
/* 8680 */    MCD_OPC_Decode, 251, 3, 89, // Opcode: FMRo
/* 8684 */    MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 8698
/* 8688 */    MCD_OPC_CheckField, 16, 5, 0, 166, 2, // Skip to: 9372
/* 8694 */    MCD_OPC_Decode, 135, 4, 89, // Opcode: FNABSSo
/* 8698 */    MCD_OPC_FilterValue, 8, 10, 0, // Skip to: 8712
/* 8702 */    MCD_OPC_CheckField, 16, 5, 0, 152, 2, // Skip to: 9372
/* 8708 */    MCD_OPC_Decode, 210, 3, 89, // Opcode: FABSSo
/* 8712 */    MCD_OPC_FilterValue, 12, 10, 0, // Skip to: 8726
/* 8716 */    MCD_OPC_CheckField, 16, 5, 0, 138, 2, // Skip to: 9372
/* 8722 */    MCD_OPC_Decode, 159, 4, 89, // Opcode: FRINSo
/* 8726 */    MCD_OPC_FilterValue, 13, 10, 0, // Skip to: 8740
/* 8730 */    MCD_OPC_CheckField, 16, 5, 0, 124, 2, // Skip to: 9372
/* 8736 */    MCD_OPC_Decode, 167, 4, 89, // Opcode: FRIZSo
/* 8740 */    MCD_OPC_FilterValue, 14, 10, 0, // Skip to: 8754
/* 8744 */    MCD_OPC_CheckField, 16, 5, 0, 110, 2, // Skip to: 9372
/* 8750 */    MCD_OPC_Decode, 163, 4, 89, // Opcode: FRIPSo
/* 8754 */    MCD_OPC_FilterValue, 15, 102, 2, // Skip to: 9372
/* 8758 */    MCD_OPC_CheckField, 16, 5, 0, 96, 2, // Skip to: 9372
/* 8764 */    MCD_OPC_Decode, 155, 4, 89, // Opcode: FRIMSo
/* 8768 */    MCD_OPC_FilterValue, 24, 16, 0, // Skip to: 8788
/* 8772 */    MCD_OPC_CheckField, 16, 5, 0, 82, 2, // Skip to: 9372
/* 8778 */    MCD_OPC_CheckField, 6, 5, 0, 76, 2, // Skip to: 9372
/* 8784 */    MCD_OPC_Decode, 168, 4, 87, // Opcode: FRSP
/* 8788 */    MCD_OPC_FilterValue, 25, 16, 0, // Skip to: 8808
/* 8792 */    MCD_OPC_CheckField, 16, 5, 0, 62, 2, // Skip to: 9372
/* 8798 */    MCD_OPC_CheckField, 6, 5, 0, 56, 2, // Skip to: 9372
/* 8804 */    MCD_OPC_Decode, 169, 4, 87, // Opcode: FRSPo
/* 8808 */    MCD_OPC_FilterValue, 28, 59, 0, // Skip to: 8871
/* 8812 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 8815 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 8829
/* 8819 */    MCD_OPC_CheckField, 16, 5, 0, 35, 2, // Skip to: 9372
/* 8825 */    MCD_OPC_Decode, 236, 3, 108, // Opcode: FCTIW
/* 8829 */    MCD_OPC_FilterValue, 25, 10, 0, // Skip to: 8843
/* 8833 */    MCD_OPC_CheckField, 16, 5, 0, 21, 2, // Skip to: 9372
/* 8839 */    MCD_OPC_Decode, 230, 3, 108, // Opcode: FCTID
/* 8843 */    MCD_OPC_FilterValue, 26, 10, 0, // Skip to: 8857
/* 8847 */    MCD_OPC_CheckField, 16, 5, 0, 7, 2, // Skip to: 9372
/* 8853 */    MCD_OPC_Decode, 216, 3, 108, // Opcode: FCFID
/* 8857 */    MCD_OPC_FilterValue, 30, 255, 1, // Skip to: 9372
/* 8861 */    MCD_OPC_CheckField, 16, 5, 0, 249, 1, // Skip to: 9372
/* 8867 */    MCD_OPC_Decode, 219, 3, 108, // Opcode: FCFIDU
/* 8871 */    MCD_OPC_FilterValue, 29, 59, 0, // Skip to: 8934
/* 8875 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 8878 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 8892
/* 8882 */    MCD_OPC_CheckField, 16, 5, 0, 228, 1, // Skip to: 9372
/* 8888 */    MCD_OPC_Decode, 241, 3, 108, // Opcode: FCTIWo
/* 8892 */    MCD_OPC_FilterValue, 25, 10, 0, // Skip to: 8906
/* 8896 */    MCD_OPC_CheckField, 16, 5, 0, 214, 1, // Skip to: 9372
/* 8902 */    MCD_OPC_Decode, 235, 3, 108, // Opcode: FCTIDo
/* 8906 */    MCD_OPC_FilterValue, 26, 10, 0, // Skip to: 8920
/* 8910 */    MCD_OPC_CheckField, 16, 5, 0, 200, 1, // Skip to: 9372
/* 8916 */    MCD_OPC_Decode, 223, 3, 108, // Opcode: FCFIDo
/* 8920 */    MCD_OPC_FilterValue, 30, 192, 1, // Skip to: 9372
/* 8924 */    MCD_OPC_CheckField, 16, 5, 0, 186, 1, // Skip to: 9372
/* 8930 */    MCD_OPC_Decode, 222, 3, 108, // Opcode: FCFIDUo
/* 8934 */    MCD_OPC_FilterValue, 30, 59, 0, // Skip to: 8997
/* 8938 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 8941 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 8955
/* 8945 */    MCD_OPC_CheckField, 16, 5, 0, 165, 1, // Skip to: 9372
/* 8951 */    MCD_OPC_Decode, 239, 3, 108, // Opcode: FCTIWZ
/* 8955 */    MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 8969
/* 8959 */    MCD_OPC_CheckField, 16, 5, 0, 151, 1, // Skip to: 9372
/* 8965 */    MCD_OPC_Decode, 237, 3, 108, // Opcode: FCTIWUZ
/* 8969 */    MCD_OPC_FilterValue, 25, 10, 0, // Skip to: 8983
/* 8973 */    MCD_OPC_CheckField, 16, 5, 0, 137, 1, // Skip to: 9372
/* 8979 */    MCD_OPC_Decode, 233, 3, 108, // Opcode: FCTIDZ
/* 8983 */    MCD_OPC_FilterValue, 29, 129, 1, // Skip to: 9372
/* 8987 */    MCD_OPC_CheckField, 16, 5, 0, 123, 1, // Skip to: 9372
/* 8993 */    MCD_OPC_Decode, 231, 3, 108, // Opcode: FCTIDUZ
/* 8997 */    MCD_OPC_FilterValue, 31, 59, 0, // Skip to: 9060
/* 9001 */    MCD_OPC_ExtractField, 6, 5,  // Inst{10-6} ...
/* 9004 */    MCD_OPC_FilterValue, 0, 10, 0, // Skip to: 9018
/* 9008 */    MCD_OPC_CheckField, 16, 5, 0, 102, 1, // Skip to: 9372
/* 9014 */    MCD_OPC_Decode, 240, 3, 108, // Opcode: FCTIWZo
/* 9018 */    MCD_OPC_FilterValue, 4, 10, 0, // Skip to: 9032
/* 9022 */    MCD_OPC_CheckField, 16, 5, 0, 88, 1, // Skip to: 9372
/* 9028 */    MCD_OPC_Decode, 238, 3, 108, // Opcode: FCTIWUZo
/* 9032 */    MCD_OPC_FilterValue, 25, 10, 0, // Skip to: 9046
/* 9036 */    MCD_OPC_CheckField, 16, 5, 0, 74, 1, // Skip to: 9372
/* 9042 */    MCD_OPC_Decode, 234, 3, 108, // Opcode: FCTIDZo
/* 9046 */    MCD_OPC_FilterValue, 29, 66, 1, // Skip to: 9372
/* 9050 */    MCD_OPC_CheckField, 16, 5, 0, 60, 1, // Skip to: 9372
/* 9056 */    MCD_OPC_Decode, 232, 3, 108, // Opcode: FCTIDUZo
/* 9060 */    MCD_OPC_FilterValue, 36, 10, 0, // Skip to: 9074
/* 9064 */    MCD_OPC_CheckField, 6, 5, 0, 46, 1, // Skip to: 9372
/* 9070 */    MCD_OPC_Decode, 242, 3, 109, // Opcode: FDIV
/* 9074 */    MCD_OPC_FilterValue, 37, 10, 0, // Skip to: 9088
/* 9078 */    MCD_OPC_CheckField, 6, 5, 0, 32, 1, // Skip to: 9372
/* 9084 */    MCD_OPC_Decode, 245, 3, 109, // Opcode: FDIVo
/* 9088 */    MCD_OPC_FilterValue, 40, 10, 0, // Skip to: 9102
/* 9092 */    MCD_OPC_CheckField, 6, 5, 0, 18, 1, // Skip to: 9372
/* 9098 */    MCD_OPC_Decode, 182, 4, 109, // Opcode: FSUB
/* 9102 */    MCD_OPC_FilterValue, 41, 10, 0, // Skip to: 9116
/* 9106 */    MCD_OPC_CheckField, 6, 5, 0, 4, 1, // Skip to: 9372
/* 9112 */    MCD_OPC_Decode, 185, 4, 109, // Opcode: FSUBo
/* 9116 */    MCD_OPC_FilterValue, 42, 10, 0, // Skip to: 9130
/* 9120 */    MCD_OPC_CheckField, 6, 5, 0, 246, 0, // Skip to: 9372
/* 9126 */    MCD_OPC_Decode, 211, 3, 109, // Opcode: FADD
/* 9130 */    MCD_OPC_FilterValue, 43, 10, 0, // Skip to: 9144
/* 9134 */    MCD_OPC_CheckField, 6, 5, 0, 232, 0, // Skip to: 9372
/* 9140 */    MCD_OPC_Decode, 214, 3, 109, // Opcode: FADDo
/* 9144 */    MCD_OPC_FilterValue, 44, 16, 0, // Skip to: 9164
/* 9148 */    MCD_OPC_CheckField, 16, 5, 0, 218, 0, // Skip to: 9372
/* 9154 */    MCD_OPC_CheckField, 6, 5, 0, 212, 0, // Skip to: 9372
/* 9160 */    MCD_OPC_Decode, 178, 4, 108, // Opcode: FSQRT
/* 9164 */    MCD_OPC_FilterValue, 45, 16, 0, // Skip to: 9184
/* 9168 */    MCD_OPC_CheckField, 16, 5, 0, 198, 0, // Skip to: 9372
/* 9174 */    MCD_OPC_CheckField, 6, 5, 0, 192, 0, // Skip to: 9372
/* 9180 */    MCD_OPC_Decode, 181, 4, 108, // Opcode: FSQRTo
/* 9184 */    MCD_OPC_FilterValue, 46, 4, 0, // Skip to: 9192
/* 9188 */    MCD_OPC_Decode, 176, 4, 110, // Opcode: FSELS
/* 9192 */    MCD_OPC_FilterValue, 47, 4, 0, // Skip to: 9200
/* 9196 */    MCD_OPC_Decode, 177, 4, 110, // Opcode: FSELSo
/* 9200 */    MCD_OPC_FilterValue, 48, 16, 0, // Skip to: 9220
/* 9204 */    MCD_OPC_CheckField, 16, 5, 0, 162, 0, // Skip to: 9372
/* 9210 */    MCD_OPC_CheckField, 6, 5, 0, 156, 0, // Skip to: 9372
/* 9216 */    MCD_OPC_Decode, 148, 4, 108, // Opcode: FRE
/* 9220 */    MCD_OPC_FilterValue, 49, 16, 0, // Skip to: 9240
/* 9224 */    MCD_OPC_CheckField, 16, 5, 0, 142, 0, // Skip to: 9372
/* 9230 */    MCD_OPC_CheckField, 6, 5, 0, 136, 0, // Skip to: 9372
/* 9236 */    MCD_OPC_Decode, 151, 4, 108, // Opcode: FREo
/* 9240 */    MCD_OPC_FilterValue, 50, 10, 0, // Skip to: 9254
/* 9244 */    MCD_OPC_CheckField, 11, 5, 0, 122, 0, // Skip to: 9372
/* 9250 */    MCD_OPC_Decode, 128, 4, 111, // Opcode: FMUL
/* 9254 */    MCD_OPC_FilterValue, 51, 10, 0, // Skip to: 9268
/* 9258 */    MCD_OPC_CheckField, 11, 5, 0, 108, 0, // Skip to: 9372
/* 9264 */    MCD_OPC_Decode, 131, 4, 111, // Opcode: FMULo
/* 9268 */    MCD_OPC_FilterValue, 52, 16, 0, // Skip to: 9288
/* 9272 */    MCD_OPC_CheckField, 16, 5, 0, 94, 0, // Skip to: 9372
/* 9278 */    MCD_OPC_CheckField, 6, 5, 0, 88, 0, // Skip to: 9372
/* 9284 */    MCD_OPC_Decode, 170, 4, 108, // Opcode: FRSQRTE
/* 9288 */    MCD_OPC_FilterValue, 53, 16, 0, // Skip to: 9308
/* 9292 */    MCD_OPC_CheckField, 16, 5, 0, 74, 0, // Skip to: 9372
/* 9298 */    MCD_OPC_CheckField, 6, 5, 0, 68, 0, // Skip to: 9372
/* 9304 */    MCD_OPC_Decode, 173, 4, 108, // Opcode: FRSQRTEo
/* 9308 */    MCD_OPC_FilterValue, 56, 4, 0, // Skip to: 9316
/* 9312 */    MCD_OPC_Decode, 252, 3, 112, // Opcode: FMSUB
/* 9316 */    MCD_OPC_FilterValue, 57, 4, 0, // Skip to: 9324
/* 9320 */    MCD_OPC_Decode, 255, 3, 112, // Opcode: FMSUBo
/* 9324 */    MCD_OPC_FilterValue, 58, 4, 0, // Skip to: 9332
/* 9328 */    MCD_OPC_Decode, 246, 3, 112, // Opcode: FMADD
/* 9332 */    MCD_OPC_FilterValue, 59, 4, 0, // Skip to: 9340
/* 9336 */    MCD_OPC_Decode, 249, 3, 112, // Opcode: FMADDo
/* 9340 */    MCD_OPC_FilterValue, 60, 4, 0, // Skip to: 9348
/* 9344 */    MCD_OPC_Decode, 144, 4, 112, // Opcode: FNMSUB
/* 9348 */    MCD_OPC_FilterValue, 61, 4, 0, // Skip to: 9356
/* 9352 */    MCD_OPC_Decode, 147, 4, 112, // Opcode: FNMSUBo
/* 9356 */    MCD_OPC_FilterValue, 62, 4, 0, // Skip to: 9364
/* 9360 */    MCD_OPC_Decode, 140, 4, 112, // Opcode: FNMADD
/* 9364 */    MCD_OPC_FilterValue, 63, 4, 0, // Skip to: 9372
/* 9368 */    MCD_OPC_Decode, 143, 4, 112, // Opcode: FNMADDo
/* 9372 */    MCD_OPC_Fail,
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
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 36: \
    tmp = fieldname(insn, 15, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 37: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 11, 5) << 5); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 38: \
    tmp = fieldname(insn, 21, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 39: \
    tmp = fieldname(insn, 21, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 40: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeVRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 41: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 42: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 43: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 44: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 45: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 46: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeVSFRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 47: \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 1) << 5); \
    tmp |= (fieldname(insn, 21, 5) << 0); \
    if (DecodeVSFRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 48: \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 1) << 5); \
    tmp |= (fieldname(insn, 21, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 49: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRC_NOR0RegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeCRBITRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 50: \
    tmp = fieldname(insn, 12, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 51: \
    tmp = fieldname(insn, 12, 8); \
    if (decodeCRBitMOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 52: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 12, 8); \
    if (decodeCRBitMOperand(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 53: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 54: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 4); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 55: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 56: \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 57: \
    tmp = 0; \
    tmp |= (fieldname(insn, 11, 5) << 5); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 58: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 1); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 59: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 60: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 61: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 62: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 63: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 64: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 65: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 66: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 67: \
    tmp = fieldname(insn, 21, 2); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 68: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 69: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 70: \
    tmp = fieldname(insn, 21, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 71: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 72: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 73: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 74: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodePointerLikeRegClass1(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodePointerLikeRegClass0(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 75: \
    tmp = fieldname(insn, 21, 2); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 76: \
    tmp = fieldname(insn, 21, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 77: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 78: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 5) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 79: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 80: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 81: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 82: \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 1, 1) << 5); \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    if (decodeUImmOperand(MI, tmp, Address, Decoder, 6) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 83: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeGPRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 21); \
    if (decodeMemRIOperands(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 84: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 21); \
    if (decodeMemRIOperands(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 85: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 0, 21); \
    if (decodeMemRIOperands(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 86: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeG8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 2, 19); \
    if (decodeMemRIXOperands(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 87: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 88: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 89: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 90: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 91: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 92: \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 1) << 5); \
    tmp |= (fieldname(insn, 21, 5) << 0); \
    if (DecodeVSFRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 2, 1) << 5); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    if (DecodeVSFRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 1, 1) << 5); \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    if (DecodeVSFRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 93: \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 1) << 5); \
    tmp |= (fieldname(insn, 21, 5) << 0); \
    if (DecodeVSFRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 1) << 5); \
    tmp |= (fieldname(insn, 21, 5) << 0); \
    if (DecodeVSFRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 2, 1) << 5); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    if (DecodeVSFRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 1, 1) << 5); \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    if (DecodeVSFRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 94: \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 1) << 5); \
    tmp |= (fieldname(insn, 21, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 2, 1) << 5); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 1, 1) << 5); \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 95: \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 1) << 5); \
    tmp |= (fieldname(insn, 21, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 1) << 5); \
    tmp |= (fieldname(insn, 21, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 2, 1) << 5); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 1, 1) << 5); \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 96: \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 1) << 5); \
    tmp |= (fieldname(insn, 21, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 2, 1) << 5); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 1, 1) << 5); \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 8, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 97: \
    tmp = fieldname(insn, 23, 3); \
    if (DecodeCRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 2, 1) << 5); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    if (DecodeVSFRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 1, 1) << 5); \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    if (DecodeVSFRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 98: \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 1) << 5); \
    tmp |= (fieldname(insn, 21, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 1, 1) << 5); \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 2); \
    MCOperand_CreateImm0(MI, tmp); \
    return S; \
  case 99: \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 1) << 5); \
    tmp |= (fieldname(insn, 21, 5) << 0); \
    if (DecodeVSFRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 1, 1) << 5); \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    if (DecodeVSFRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 100: \
    tmp = fieldname(insn, 23, 3); \
    if (DecodeCRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 1, 1) << 5); \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    if (DecodeVSFRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 101: \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 1) << 5); \
    tmp |= (fieldname(insn, 21, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 1, 1) << 5); \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 102: \
    tmp = fieldname(insn, 23, 3); \
    if (DecodeCRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 1, 1) << 5); \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 103: \
    tmp = fieldname(insn, 23, 3); \
    if (DecodeCRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 2, 1) << 5); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 1, 1) << 5); \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 104: \
    tmp = 0; \
    tmp |= (fieldname(insn, 0, 1) << 5); \
    tmp |= (fieldname(insn, 21, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 2, 1) << 5); \
    tmp |= (fieldname(insn, 16, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 1, 1) << 5); \
    tmp |= (fieldname(insn, 11, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = 0; \
    tmp |= (fieldname(insn, 3, 1) << 5); \
    tmp |= (fieldname(insn, 6, 5) << 0); \
    if (DecodeVSRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 105: \
    tmp = fieldname(insn, 23, 3); \
    if (DecodeCRRCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 106: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 107: \
    tmp = fieldname(insn, 17, 8); \
    MCOperand_CreateImm0(MI, tmp); \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 108: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 109: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 110: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 11, 5); \
    if (DecodeF4RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 111: \
    tmp = fieldname(insn, 21, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 16, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    tmp = fieldname(insn, 6, 5); \
    if (DecodeF8RCRegisterClass(MI, tmp, Address, Decoder) == MCDisassembler_Fail) return MCDisassembler_Fail; \
    return S; \
  case 112: \
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
      Opc = (unsigned)decodeULEB128(++Ptr, &Len); \
      Ptr += Len; \
      DecodeIdx = (unsigned)decodeULEB128(Ptr, &Len); \
      Ptr += Len; \
      MCInst_setOpcode(MI, Opc); \
      return decoder(S, DecodeIdx, insn, MI, Address, MI); \
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
