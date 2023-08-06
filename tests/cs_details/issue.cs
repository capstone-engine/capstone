!# issue 0 ARM operand groups 0x90,0xe8,0x0e,0x00 == ldm.w r0, {r1, r2, r3} ;
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0x90,0xe8,0x0e,0x00 == ldm.w r0, {r1, r2, r3} ; op_count: 4 ; operands[0].type: REG = r0 ; operands[0].access: READ ; operands[1].type: REG = r1 ; operands[1].access: WRITE ; operands[2].type: REG = r2 ; operands[2].access: WRITE ; operands[3].type: REG = r3 ; operands[3].access: WRITE ; Registers read: r0 ; Registers modified: r1 r2 r3 ; Groups: IsThumb2

!# issue 0 ARM operand groups 0x0e,0xc8 == ldm r0!, {r1, r2, r3} ;
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0x0e,0xc8 == ldm r0!, {r1, r2, r3}  ; op_count: 4 ; operands[0].type: REG = r0 ; operands[0].access: READ | WRITE ; operands[1].type: REG = r1 ; operands[1].access: WRITE ; operands[2].type: REG = r2 ; operands[2].access: WRITE ; operands[3].type: REG = r3 ; operands[3].access: WRITE ; Write-back: True ; Registers read: r0 ; Registers modified: r0 r1 r2 r3 ; Groups: IsThumb

!# issue 0 ARM operand groups 0x00,0x2a,0xf7,0xee == vmov.f32 s5, #1.000000e+00 ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x00,0x2a,0xf7,0xee == vmov.f32 s5, #1.000000e+00 ; op_count: 2 ; operands[0].type: REG = s5 ; operands[0].access: WRITE ; operands[1].type: FP = 1.000000 ; Registers modified: s5 ; Groups: HasVFP3

!# issue 0 ARM operand groups 0x0f,0x00,0x71,0xe3 == cmn r1, #15 ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x0f,0x00,0x71,0xe3 == cmn r1, #0xf ; op_count: 2 ; operands[0].type: REG = r1 ; operands[0].access: READ ; operands[1].type: IMM = 0xf ; operands[1].access: READ ; Update-flags: True ; Registers read: r1 ; Registers modified: cpsr ; Groups: IsARM

!# issue 0 ARM operand groups 0x03,0x20,0xb0,0xe1 == movs r2, r3 ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x03,0x20,0xb0,0xe1 == movs r2, r3 ;  op_count: 2 ; operands[0].type: REG = r2 ; operands[0].access: WRITE ; operands[1].type: REG = r3 ; operands[1].access: READ ; Update-flags: True ; Registers read: r3 ; Registers modified: cpsr r2 ; Groups: IsARM

!# issue 0 ARM operand groups 0xfd,0x8f == ldrh r5, [r7, #62] ;
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0xfd,0x8f == ldrh r5, [r7, #0x3e] ; op_count: 2 ; operands[0].type: REG = r5 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = r7 ; operands[1].mem.disp: 0x3e ; operands[1].access: READ ; Registers read: r7 ; Registers modified: r5 ; Groups: IsThumb

!# issue 0 ARM operand groups 0x61,0xb6 == cpsie f ;
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0x61,0xb6 == cpsie f ; CPSI-mode: 2 ; CPSI-flag: 1 ; Groups: IsThumb

!# issue 0 ARM operand groups 0x18,0xf8,0x03,0x1e == ldrbt r1, [r8, #3] ;
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0x18,0xf8,0x03,0x1e == ldrbt r1, [r8, #3] ; op_count: 2 ; operands[0].type: REG = r1 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = r8 ; operands[1].mem.disp: 0x3 ; operands[1].access: READ ; Registers read: r8 ; Registers modified: r1 ; Groups: IsThumb2

!# issue 0 ARM operand groups 0xb0,0xf8,0x01,0xf1 == pldw [r0, #257] ;
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0xb0,0xf8,0x01,0xf1 == pldw [r0, #0x101] ; op_count: 1 ; operands[0].type: MEM ; operands[0].mem.base: REG = r0 ; operands[0].mem.disp: 0x101 ; operands[0].access: READ ; Registers read: r0 ; Groups: IsThumb2 HasV7 HasMP

!# issue 0 ARM operand groups 0xd3,0xe8,0x08,0xf0 == tbb [r3, r8] ;
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0xd3,0xe8,0x08,0xf0 == tbb [r3, r8] ; op_count: 1 ; operands[0].type: MEM ; operands[0].mem.base: REG = r3 ; operands[0].mem.index: REG = r8 ; operands[0].access: READ ; Registers read: r3 r8 ; Groups: jump IsThumb2

!# issue 0 ARM operand groups 0xd3,0xe8,0x18,0xf0 == tbh [r3, r8, lsl #1] ;
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0xd3,0xe8,0x18,0xf0 == tbh [r3, r8, lsl #1] ;  op_count: 1 ; operands[0].type: MEM ; operands[0].mem.base: REG = r3 ; operands[0].mem.index: REG = r8 ; operands[0].mem.lshift: 0x1 ; operands[0].access: READ ; Shift: 2 = 1 ; Registers read: r3 r8 ; Groups: jump IsThumb2

!# issue 0 ARM operand groups 0xaf,0xf3,0x43,0x85 == cpsie i, #3 ;
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0xaf,0xf3,0x43,0x85 == cpsie i, #3 ; cpsie i, #3 ; op_count: 1 ; operands[0].type: IMM = 0x3 ; operands[0].access: READ ; CPSI-mode: 2 ; CPSI-flag: 2 ; Groups: IsThumb2 IsNotMClass

!# issue 0 ARM operand groups 0xbf,0xf3,0x6f,0x8f == isb sy ;
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0xbf,0xf3,0x6f,0x8f == isb sy ; isb sy ; Memory-barrier: 15 ; Groups: IsThumb HasDB

!# issue 0 ARM operand groups 0x59,0xea,0x7b,0x89 == csel r9, r9, r11, vc ;
!# CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_V8, CS_OPT_DETAIL
0x59,0xea,0x7b,0x89 == csel r9, r9, r11, vc ; op_count: 3 ; operands[0].type: REG = r9 ; operands[0].access: WRITE ; operands[1].type: REG = r9 ; operands[1].access: READ ; operands[2].type: REG = r11 ; operands[2].access: READ ; Code condition: 7 ; Registers read: cpsr r9 r11 ; Registers modified: r9 ; Groups: HasV8_1MMainline

!# issue 0 ARM operand groups 0xbf,0xf3,0x56,0x8f == dmb nshst ;
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0xbf,0xf3,0x56,0x8f == dmb nshst ; dmb nshst ; Memory-barrier: 6 ; Groups: IsThumb HasDB

!# issue 0 ARM operand groups 0x31,0xfa,0x02,0xf2 == lsrs.w r2, r1, r2 ;
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0x31,0xfa,0x02,0xf2 == lsrs.w r2, r1, r2 ;  op_count: 3 ; operands[0].type: REG = r2 ; operands[0].access: WRITE ; operands[1].type: REG = r1 ; operands[1].access: READ ; operands[2].type: REG = r2 ; operands[2].access: READ ; Update-flags: True ; Registers read: r1 r2 ; Registers modified: cpsr r2 ; Groups: IsThumb2

!# issue 0 ARM operand groups 0x5f,0xf0,0x0c,0x01 == movseq.w r1, #12 ;
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0x08,0xbf == it eq ; Code condition: 0 ; Predicate Mask: 0x1 ; Registers modified: itstate ; Groups: IsThumb2
0x5f,0xf0,0x0c,0x01 == movseq.w r1, #0xc ; op_count: 2 ; operands[0].type: REG = r1 ; operands[0].access: WRITE ; operands[1].type: IMM = 0xc ; operands[1].access: READ ; Code condition: 0 ; Update-flags: True ; Registers modified: cpsr r1 ; Groups: IsThumb2

!# issue 0 ARM operand groups 0x52,0xe8,0x01,0x1f == ldrex r1, [r2, #4] ;
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0x52,0xe8,0x01,0x1f == ldrex r1, [r2, #4] ; op_count: 2 ; operands[0].type: REG = r1 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = r2 ; operands[1].mem.disp: 0x4 ; operands[1].access: READ ; Registers read: r2 ; Registers modified: r1 ; Groups: IsThumb HasV8MBaseline

!# issue 0 ARM operand groups 0xdf,0xec,0x1d,0x1a == vscclrmhi {s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23, s24, s25, s26, s27, s28, s29, s30, s31, vpr} ;
!# CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_V8, CS_OPT_DETAIL
0x88,0xbf == it hi ; Code condition: 8 ; Predicate Mask: 0x1 ; Groups: IsThumb2
0xdf,0xec,0x1d,0x1a == vscclrmhi {s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23, s24, s25, s26, s27, s28, s29, s30, s31, vpr} ; op_count: 30 ; operands[0].type: REG = s3 ; operands[0].access: WRITE ; operands[1].type: REG = s4 ; operands[1].access: WRITE ; operands[2].type: REG = s5 ; operands[2].access: WRITE ; operands[3].type: REG = s6 ; operands[3].access: WRITE ; operands[4].type: REG = s7 ; operands[4].access: WRITE ; operands[5].type: REG = s8 ; operands[5].access: WRITE ; operands[6].type: REG = s9 ; operands[6].access: WRITE ; operands[7].type: REG = s10 ; operands[7].access: WRITE ; operands[8].type: REG = s11 ; operands[8].access: WRITE ; operands[9].type: REG = s12 ; operands[9].access: WRITE ; operands[10].type: REG = s13 ; operands[10].access: WRITE ; operands[11].type: REG = s14 ; operands[11].access: WRITE ; operands[12].type: REG = s15 ; operands[12].access: WRITE ; operands[13].type: REG = s16 ; operands[13].access: WRITE ; operands[14].type: REG = s17 ; operands[14].access: WRITE ; operands[15].type: REG = s18 ; operands[15].access: WRITE ; operands[16].type: REG = s19 ; operands[16].access: WRITE ; operands[17].type: REG = s20 ; operands[17].access: WRITE ; operands[18].type: REG = s21 ; operands[18].access: WRITE ; operands[19].type: REG = s22 ; operands[19].access: WRITE ; operands[20].type: REG = s23 ; operands[20].access: WRITE ; operands[21].type: REG = s24 ; operands[21].access: WRITE ; operands[22].type: REG = s25 ; operands[22].access: WRITE ; operands[23].type: REG = s26 ; operands[23].access: WRITE ; operands[24].type: REG = s27 ; operands[24].access: WRITE ; operands[25].type: REG = s28 ; operands[25].access: WRITE ; operands[26].type: REG = s29 ; operands[26].access: WRITE ; operands[27].type: REG = s30 ; operands[27].access: WRITE ; operands[28].type: REG = s31 ; operands[28].access: WRITE ; operands[29].type: REG = vpr ; operands[29].access: WRITE ; Code condition: 8 ; Registers modified: s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19 s20 s21 s22 s23 s24 s25 s26 s27 s28 s29 s30 s31 vpr ; Groups: HasV8_1MMainline Has8MSecExt

!# issue 0 ARM operand groups 0x9f,0xec,0x06,0x5b == vscclrm {d5, d6, d7, vpr} ;
!# CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_V8, CS_OPT_DETAIL
0x9f,0xec,0x06,0x5b == vscclrm {d5, d6, d7, vpr} ; op_count: 4 ; operands[0].type: REG = d5 ; operands[0].access: WRITE ; operands[1].type: REG = d6 ; operands[1].access: WRITE ; operands[2].type: REG = d7 ; operands[2].access: WRITE ; operands[3].type: REG = vpr ; operands[3].access: WRITE ; Registers modified: d5 d6 d7 vpr ; Groups: HasV8_1MMainline Has8MSecExt

!# issue 0 ARM operand groups 0xbc,0xfd,0x7f,0xaf == vldrh.u32 q5, [r4, #254]! ;
!# CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_V8 | CS_MODE_MCLASS, CS_OPT_DETAIL
0xbc,0xfd,0x7f,0xaf == vldrh.u32 q5, [r4, #0xfe]! ; op_count: 2 ; operands[0].type: REG = q5 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = r4 ; operands[1].mem.disp: 0xfe ; operands[1].access: READ ; Write-back: True ; Registers read: r4 ; Registers modified: r4 q5 ; Groups: HasMVEInt

!# issue 0 ARM operand groups 0x80,0xfc,0x80,0x1e == vst20.16 {q0, q1}, [r0] ;
!# CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS, CS_OPT_DETAIL
0x80,0xfc,0x80,0x1e == vst20.16 {q0, q1}, [r0] ; op_count: 3 ; operands[0].type: REG = q0 ; operands[0].access: READ ; operands[1].type: REG = q1 ; operands[1].access: READ ; operands[2].type: MEM ; operands[2].mem.base: REG = r0 ; operands[2].access: WRITE ; Registers read: q0 q1 r0 ; Groups: HasMVEInt

!# issue 0 ARM operand groups 0x98,0xfc,0x4e,0x08 == vcadd.f32 q0, q4, q7, #90 ;
!# CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS, CS_OPT_DETAIL
0x98,0xfc,0x4e,0x08 == vcadd.f32 q0, q4, q7, #90 ; op_count: 4 ; operands[0].type: REG = q0 ; operands[0].access: READ | WRITE ; operands[1].type: REG = q4 ; operands[1].access: READ ; operands[2].type: REG = q7 ; operands[2].access: READ ; operands[3].type: IMM = 0x5a ; operands[3].access: READ ; Registers read: q0 q4 q7 ; Registers modified: q0 ; Groups: HasMVEFloat

!# issue 0 ARM operand groups 0x94,0xfd,0x46,0x48 == vcadd.f32 q2, q2, q3, #270 ;
!# CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_V8, CS_OPT_DETAIL
0x94,0xfd,0x46,0x48 == vcadd.f32 q2, q2, q3, #270 ; op_count: 4 ; operands[0].type: REG = q2 ; operands[0].access: WRITE ; operands[1].type: REG = q2 ; operands[1].access: READ ; operands[2].type: REG = q3 ; operands[2].access: READ ; operands[3].type: IMM = 0x10e ; operands[3].access: READ ; Registers read: q2 q3 ; Registers modified: q2 ; Groups: HasNEON HasV8_3a

!# issue 0 ARM operand groups 0x9d,0xec,0x82,0x6e == vldrb.s16 q3, [sp, q1] ;
!# CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS, CS_OPT_DETAIL
0x9d,0xec,0x82,0x6e == vldrb.s16 q3, [sp, q1] ; op_count: 2 ; operands[0].type: REG = q3 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = r13 ; operands[1].mem.index: REG = q1 ; operands[1].access: READ ; Registers read: r13 q1 ; Registers modified: q3 ; Groups: HasMVEInt

!# issue 0 ARM operand groups 0x90,0xec,0x12,0x6f == vldrh.s32 q3, [r0, q1] ;
!# CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS, CS_OPT_DETAIL
0x90,0xec,0x12,0x6f == vldrh.s32 q3, [r0, q1] ; op_count: 2 ; operands[0].type: REG = q3 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = r0 ; operands[1].mem.index: REG = q1 ; operands[1].access: READ ; Registers read: r0 q1 ; Registers modified: q3 ; Groups: HasMVEInt

!# issue 0 ARM operand groups 0x5f,0xea,0x2d,0x83 == sqrshrl lr, r3, #64, r8 ;
!# CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_V8 | CS_MODE_MCLASS, CS_OPT_DETAIL
0x5f,0xea,0x2d,0x83 == sqrshrl lr, r3, #0x40, r8 ; op_count: 4 ; operands[0].type: REG = r14 ; operands[0].access: READ | WRITE ; operands[1].type: REG = r3 ; operands[1].access: READ | WRITE ; operands[2].type: IMM = 0x40 ; operands[2].access: READ ; operands[3].type: REG = r8 ; operands[3].access: READ ; Write-back: True ; Registers read: r14 r3 r8 ; Registers modified: r14 r3 ; Groups: HasV8_1MMainline HasMVEInt

!# issue 0 ARM operand groups 0x82,0xfd,0x21,0xff == vstrd.64 q7, [q1, #264] ;
!# CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS, CS_OPT_DETAIL
0x82,0xfd,0x21,0xff == vstrd.64 q7, [q1, #0x108] ; op_count: 2 ; operands[0].type: REG = q7 ; operands[0].access: READ ; operands[1].type: MEM ; operands[1].mem.base: REG = q1 ; operands[1].mem.disp: 0x108 ; operands[1].access: WRITE ; Registers read: q7 q1 ; Groups: HasMVEInt

!# issue 0 ARM operand groups 0x06,0x16,0x72,0xe6 == ldrbt r1, [r2], -r6, lsl #12 ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x06,0x16,0x72,0xe6 == ldrbt r1, [r2], -r6, lsl #12 ; op_count: 2 ; operands[0].type: REG = r1 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = r2 ; operands[1].mem.index: REG = r6 ; operands[1].access: READ ; Shift: 2 = 12 ; Subtracted: True ; Write-back: True ; Registers read: r2 r6 ; Registers modified: r2 r1 ; Groups: IsARM

!# issue 0 ARM operand groups 0xf6,0x50,0x33,0xe1 == ldrsh r5, [r3, -r6]! ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0xf6,0x50,0x33,0xe1 == ldrsh r5, [r3, -r6]! ; op_count: 2 ; operands[0].type: REG = r5 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = r3 ; operands[1].mem.index: REG = r6 ; operands[1].access: READ ; Subtracted: True ; Write-back: True ; Registers read: r3 r6 ; Registers modified: r3 r5 ; Groups: IsARM

!# issue 0 ARM operand groups 0x1e,0x19,0x7a,0xfd == ldc2l p9, c1, [r10, #-120]! ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x1e,0x19,0x7a,0xfd == ldc2l p9, c1, [r10, #-0x78]! ; op_count: 3 ; operands[0].type: P-IMM = 9 ; operands[0].access: READ ; operands[1].type: C-IMM = 1 ; operands[1].access: READ ; operands[2].type: MEM ; operands[2].mem.base: REG = r10 ; operands[2].mem.disp: 0x78 ; operands[2].access: READ ; Registers read: r10 ; Registers modified: r10 ; Groups: IsARM PreV8

!# issue 0 ARM operand groups 0x12,0x31,0x7c,0xfc == ldc2l p1, c3, [r12], #-72 ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x12,0x31,0x7c,0xfc == ldc2l p1, c3, [r12], #-0x48 ; op_count: 3 ; operands[0].type: P-IMM = 1 ; operands[0].access: READ ; operands[1].type: C-IMM = 3 ; operands[1].access: READ ; operands[2].type: MEM ; operands[2].mem.base: REG = r12 ; operands[2].access: READ ; operands[2].mem.disp: 0x48 ; Subtracted: True ; Registers read: r12 ; Groups: IsARM PreV8

!# issue 0 ARM operand groups 0xa4,0xf9,0x6d,0x0e == vld3.16 {d0[], d2[], d4[]}, [r4]! ;
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0xa4,0xf9,0x6d,0x0e == vld3.16 {d0[], d2[], d4[]}, [r4]! ; op_count: 4 ; operands[0].type: REG = d0 ; operands[0].access: WRITE ; operands[1].type: REG = d2 ; operands[1].access: WRITE ; operands[2].type: REG = d4 ; operands[2].access: WRITE ; operands[3].type: MEM ; operands[3].mem.index: REG = r4 ; operands[3].access: READ ; Write-back: True ; Registers read: r4 ; Registers modified: r4 d0 d2 d4

!# issue 0 ARM operand groups 0x0d,0x50,0x66,0xe4 == strbt r5, [r6], #-13 ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x0d,0x50,0x66,0xe4 == strbt r5, [r6], #-0xd ; op_count: 2 ; operands[0].type: REG = r5 ; operands[0].access: READ ; operands[1].type: MEM ; operands[1].mem.base: REG = r6 ; operands[1].access: WRITE ; operands[1].mem.disp: 0xd ; Subtracted: True ; Write-back: True ; Registers read: r5 r6 ; Registers modified: r6 ; Groups: IsARM

!# issue 0 ARM operand groups 0x00,0x10,0x4f,0xe2 == sub r1, pc, #0 ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x00,0x10,0x4f,0xe2 == sub r1, pc, #0 ; op_count: 3 ; operands[0].type: REG = r1 ; operands[0].access: WRITE ; operands[1].type: REG = r15 ; operands[1].access: READ ; operands[2].type: IMM = 0x0 ; operands[2].access: READ ; Registers read: r15 ; Registers modified: r1 ; Groups: IsARM

!# issue 0 ARM operand groups 0x9f,0x51,0xd3,0xe7 == bfc r5, #3, #17 ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x9f,0x51,0xd3,0xe7 == bfc r5, #3, #0x11 ; op_count: 3 ; operands[0].type: REG = r5 ; operands[0].access: READ | WRITE ; operands[1].type: IMM = 0x3 ; operands[1].access: READ ; operands[2].type: IMM = 0x11 ; operands[2].access: READ ; Write-back: True ; Registers read: r5 ; Registers modified: r5 ; Groups: IsARM HasV6T2

!# issue 0 ARM operand groups 0xd8,0xe8,0xff,0x67 == ldaexd r6, r7, [r8] ;
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0xd8,0xe8,0xff,0x67 == ldaexd r6, r7, [r8] ; op_count: 3 ; operands[0].type: REG = r6 ; operands[0].access: WRITE ; operands[1].type: REG = r7 ; operands[1].access: WRITE ; operands[2].type: MEM ; operands[2].mem.base: REG = r8 ; operands[2].access: READ ; Registers read: r8 ; Registers modified: r6 r7 ; Groups: IsThumb HasAcquireRelease HasV7Clrex IsNotMClass

!# issue 0 ARM operand groups 0x30,0x0f,0xa6,0xe6 == ssat16 r0, #7, r0 ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x30,0x0f,0xa6,0xe6 == ssat16 r0, #7, r0 ; op_count: 3 ; operands[0].type: REG = r0 ; operands[0].access: WRITE ; operands[1].type: IMM = 0x7 ; operands[1].access: READ ; operands[2].type: REG = r0 ; operands[2].access: READ ; Registers read: r0 ; Registers modified: r0 ; Groups: IsARM HasV6

!# issue 0 ARM operand groups 0x9a,0x8f,0xa0,0xe6 == ssat r8, #1, r10, lsl #31 ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x9a,0x8f,0xa0,0xe6 == ssat r8, #1, r10, lsl #0x1f ; op_count: 3 ; operands[0].type: REG = r8 ; operands[0].access: WRITE ; operands[1].type: IMM = 0x1 ; operands[1].access: READ ; operands[2].type: REG = r10 ; operands[2].access: READ ; Shift: 2 = 31 ; Registers read: r10 ; Registers modified: r8 ; Groups: IsARM HasV6

!# issue 0 ARM operand groups 0x40,0x1b,0xf5,0xee == vcmp.f64 d17, #0 ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x40,0x1b,0xf5,0xee == vcmp.f64 d17, #0 ; op_count: 2 ; operands[0].type: REG = d17 ; operands[0].access: READ ; operands[1].type: IMM = 0x0 ; operands[1].access: READ ; Update-flags: True ; Registers read: d17 ; Registers modified: fpscr_nzcv ; Groups: HasVFP2 HasDPVFP

!# issue 0 ARM operand groups 0x05,0xf0,0x2f,0xe3 == msr CPSR_fsxc, #5 ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x05,0xf0,0x2f,0xe3 == msr cpsr_fsxc, #5 ; op_count: 2 ; operands[0].type: CPSR = fsxc ; operands[0].type: MASK = 15 ; operands[0].access: WRITE ; operands[1].type: IMM = 0x5 ; operands[1].access: READ ; Update-flags: True ; Registers modified: cpsr ; Groups: IsARM

!# issue 0 ARM operand groups 0xa4,0xf9,0xed,0x0b == vld4.32 {d0[1], d2[1], d4[1], d6[1]}, [r4:128]! ;
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0xa4,0xf9,0xed,0x0b == vld4.32 {d0[1], d2[1], d4[1], d6[1]}, [r4:0x80]! ; op_count: 5 ; operands[0].type: REG = d0 ; operands[0].neon_lane = 1 ; operands[0].access: READ | WRITE ; operands[1].type: REG = d2 ; operands[1].neon_lane = 1 ; operands[1].access: READ | WRITE ; operands[2].type: REG = d4 ; operands[2].neon_lane = 1 ; operands[2].access: READ | WRITE ; operands[3].type: REG = d6 ; operands[3].neon_lane = 1 ; operands[3].access: READ | WRITE ; operands[4].type: MEM ; operands[4].mem.index: REG = r4 ; operands[4].mem.disp: 0x80 ; operands[4].access: READ ; Write-back: True ; Registers read: d0 d2 d4 d6 r4 ; Registers modified: r4 d0 d2 d4 d6

!# issue 0 ARM operand groups 0x42,0x03,0xb0,0xf3 == aesd.8 q0, q1 ;
!# CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_V8, CS_OPT_DETAIL
0x42,0x03,0xb0,0xf3 == aesd.8 q0, q1 ; op_count: 2 ; operands[0].type: REG = q0 ; operands[0].access: READ | WRITE ; operands[1].type: REG = q1 ; operands[1].access: READ ; Write-back: True ; Registers read: q0 q1 ; Registers modified: q0 ; Groups: HasV8 HasAES

!# issue 0 ARM operand groups 0x11,0x57,0x54,0xfc == mrrc2 p7, #1, r5, r4, c1 ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x11,0x57,0x54,0xfc == mrrc2 p7, #1, r5, r4, c1 ; op_count: 5 ; operands[0].type: P-IMM = 7 ; operands[0].access: READ ; operands[1].type: IMM = 0x1 ; operands[1].access: READ ; operands[2].type: REG = r5 ; operands[2].access: WRITE ; operands[3].type: REG = r4 ; operands[3].access: WRITE ; operands[4].type: C-IMM = 1 ; operands[4].access: READ ; Registers modified: r5 r4 ; Groups: IsARM PreV8

!# issue 0 ARM operand groups 0xd3,0x2f,0x82,0xe6 == pkhtb r2, r2, r3, asr #31 ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0xd3,0x2f,0x82,0xe6 == pkhtb r2, r2, r3, asr #0x1f ; op_count: 3 ; operands[0].type: REG = r2 ; operands[0].access: WRITE ; operands[1].type: REG = r2 ; operands[1].access: READ ; operands[2].type: REG = r3 ; operands[2].access: READ ; Shift: 1 = 31 ; Registers read: r2 r3 ; Registers modified: r2 ; Groups: IsARM HasV6

!# issue 0 ARM operand groups 0x93,0x27,0x82,0xe6 == pkhbt r2, r2, r3, lsl #15 ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x93,0x27,0x82,0xe6 == pkhbt r2, r2, r3, lsl #0xf ; op_count: 3 ; operands[0].type: REG = r2 ; operands[0].access: WRITE ; operands[1].type: REG = r2 ; operands[1].access: READ ; operands[2].type: REG = r3 ; operands[2].access: READ ; Shift: 2 = 15 ; Registers read: r2 r3 ; Registers modified: r2 ; Groups: IsARM HasV6

!# issue 0 ARM operand groups 0xb4,0x10,0xf0,0xe0 == ldrht r1, [r0], #4 ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0xb4,0x10,0xf0,0xe0 == ldrht r1, [r0], #4 ; op_count: 2 ; operands[0].type: REG = r1 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = r0 ; operands[1].access: READ ; operands[1].mem.disp: 0x4 ; Write-back: True ; Registers read: r0 ; Registers modified: r0 r1 ; Groups: IsARM

!# issue 0 ARM operand groups 0x2f,0xfa,0xa1,0xf3 == sxtb16 r3, r1, ror #16 ;
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0x2f,0xfa,0xa1,0xf3 == sxtb16 r3, r1, ror #16 ; op_count: 2 ; operands[0].type: REG = r3 ; operands[0].access: WRITE ; operands[1].type: REG = r1 ; operands[1].access: READ ; Shift: 4 = 16 ; Registers read: r1 ; Registers modified: r3 ; Groups: HasDSP IsThumb2

!# issue 0 ARM operand groups 0x00,0x02,0x01,0xf1 == setend be ;
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x00,0x02,0x01,0xf1 == setend be ; op_count: 1 ; operands[0].type: SETEND = be ; Groups: IsARM

!# issue 0 ARM operand groups 0xd0,0xe8,0xaf,0x0f == lda r0, [r0]
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0xd0,0xe8,0xaf,0x0f == lda r0, [r0] ; op_count: 2 ; operands[0].type: REG = r0 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = r0 ; operands[1].access: READ ; Registers read: r0 ; Registers modified: r0 ; Groups: IsThumb HasAcquireRelease

!# issue 0 ARM operand groups 0xef,0xf3,0x11,0x85 == ldrhi pc, [r1, #-0x3ef]
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0xef,0xf3,0x11,0x85 == ldrhi pc, [r1, #-0x3ef] ; op_count: 2 ; operands[0].type: REG = r15 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = r1 ; operands[1].mem.disp: 0x3ef ; operands[1].access: READ ; Code condition: 8 ; Registers read: cpsr r1 ; Registers modified: r15 ; Groups: IsARM

