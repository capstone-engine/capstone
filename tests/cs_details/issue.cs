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
0xa4,0xf9,0x6d,0x0e == vld3.16 {d0[], d2[], d4[]}, [r4]! ; op_count: 4 ; operands[0].type: REG = d0 ; operands[0].access: WRITE ; operands[1].type: REG = d2 ; operands[1].access: WRITE ; operands[2].type: REG = d4 ; operands[2].access: WRITE ; operands[3].type: MEM ; operands[3].mem.base: REG = r4 ; operands[3].access: READ | WRITE ; Write-back: True ; Registers read: r4 ; Registers modified: r4 d0 d2 d4

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
0xa4,0xf9,0xed,0x0b == vld4.32 {d0[1], d2[1], d4[1], d6[1]}, [r4:0x80]! ; op_count: 5 ; operands[0].type: REG = d0 ; operands[0].neon_lane = 1 ; operands[0].access: READ | WRITE ; operands[1].type: REG = d2 ; operands[1].neon_lane = 1 ; operands[1].access: READ | WRITE ; operands[2].type: REG = d4 ; operands[2].neon_lane = 1 ; operands[2].access: READ | WRITE ; operands[3].type: REG = d6 ; operands[3].neon_lane = 1 ; operands[3].access: READ | WRITE ; operands[4].type: MEM ; operands[4].mem.base: REG = r4 ; operands[4].mem.align: 0x80 ; operands[4].access: READ | WRITE ; Write-back: True ; Registers read: d0 d2 d4 d6 r4 ; Registers modified: r4 d0 d2 d4 d6

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
0xef,0xf3,0x11,0x85 == ldrhi pc, [r1, #-0x3ef] ; op_count: 2 ; operands[0].type: REG = r15 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = r1 ; operands[1].mem.disp: 0x3ef ; operands[1].access: READ ; Code condition: 8 ; Registers read: cpsr r1 ; Registers modified: r15 ; Groups: IsARM jump

!# issue 0 RISCV operand groups 0x37,0x34,0x00,0x00 == lui s0, 3
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x37,0x34,0x00,0x00 == lui s0, 3 ; op_count: 2 ; operands[0].type: REG = s0 ; operands[0].access: WRITE ; operands[1].type: IMM = 0x3 ; operands[1].access: READ

!# issue 0 RISCV operand groups 0x97,0x82,0x00,0x00 == auipc t0, 8
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x97,0x82,0x00,0x00 == auipc t0, 8 ; op_count: 2 ; operands[0].type: REG = t0 ; operands[0].access: WRITE ; operands[1].type: IMM = 0x8 ; operands[1].access: READ

!# issue 0 RISCV operand groups 0xef,0x00,0x80,0x00 == jal 8
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xef,0x00,0x80,0x00 == jal 8 ; op_count: 1 ; operands[0].type: IMM = 0x8 ; operands[0].access: READ ; Groups: call

!# issue 0 RISCV operand groups 0xef,0xf0,0x1f,0xff == jal -0x10
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xef,0xf0,0x1f,0xff == jal -0x10 ; op_count: 1 ; operands[0].type: IMM = 0xfffffff0 ; operands[0].access: READ ; Groups: call

!# issue 0 RISCV operand groups 0xe7,0x00,0x45,0x00 == jalr ra, a0, 4
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xe7,0x00,0x45,0x00 == jalr ra, a0, 4 ; op_count: 3 ; operands[0].type: REG = ra ; operands[0].access: WRITE ; operands[1].type: REG = a0 ; operands[1].access: READ ; operands[2].type: IMM = 0x4 ; operands[2].access: READ ; Groups: call

!# issue 0 RISCV operand groups 0xe7,0x00,0xc0,0xff == jalr ra, zero, -4
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xe7,0x00,0xc0,0xff == jalr ra, zero, -4 ; op_count: 3 ; operands[0].type: REG = ra ; operands[0].access: WRITE ; operands[1].type: REG = zero ; operands[1].access: READ ; operands[2].type: IMM = 0xfffffffc ; operands[2].access: READ ; Groups: call

!# issue 0 RISCV operand groups 0x63,0x05,0x41,0x00 == beq sp, tp, 0xa
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x63,0x05,0x41,0x00 == beq sp, tp, 0xa ; op_count: 3 ; operands[0].type: REG = sp ; operands[0].access: READ ; operands[1].type: REG = tp ; operands[1].access: READ ; operands[2].type: IMM = 0xa ; operands[2].access: READ ; Groups: branch_relative jump

!# issue 0 RISCV operand groups 0xe3,0x9d,0x61,0xfe == bne gp, t1, -6
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xe3,0x9d,0x61,0xfe == bne gp, t1, -6 ; op_count: 3 ; operands[0].type: REG = gp ; operands[0].access: READ ; operands[1].type: REG = t1 ; operands[1].access: READ ; operands[2].type: IMM = 0xfffffffa ; operands[2].access: READ ; Groups: branch_relative jump

!# issue 0 RISCV operand groups 0x63,0xca,0x93,0x00 == blt t2, s1, 0x14
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x63,0xca,0x93,0x00 == blt t2, s1, 0x14 ; op_count: 3 ; operands[0].type: REG = t2 ; operands[0].access: READ ; operands[1].type: REG = s1 ; operands[1].access: READ ; operands[2].type: IMM = 0x14 ; operands[2].access: READ ; Groups: branch_relative jump

!# issue 0 RISCV operand groups 0x63,0x53,0xb5,0x00 == bge a0, a1, 6
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x63,0x53,0xb5,0x00 == bge a0, a1, 6 ; op_count: 3 ; operands[0].type: REG = a0 ; operands[0].access: READ ; operands[1].type: REG = a1 ; operands[1].access: READ ; operands[2].type: IMM = 0x6 ; operands[2].access: READ ; Groups: branch_relative jump

!# issue 0 RISCV operand groups 0x63,0x65,0xd6,0x00 == bltu a2, a3, 0xa
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x63,0x65,0xd6,0x00 == bltu a2, a3, 0xa ; op_count: 3 ; operands[0].type: REG = a2 ; operands[0].access: READ ; operands[1].type: REG = a3 ; operands[1].access: READ ; operands[2].type: IMM = 0xa ; operands[2].access: READ ; Groups: branch_relative jump

!# issue 0 RISCV operand groups 0x63,0x76,0xf7,0x00 == bgeu a4, a5, 0xc
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x63,0x76,0xf7,0x00 == bgeu a4, a5, 0xc ; op_count: 3 ; operands[0].type: REG = a4 ; operands[0].access: READ ; operands[1].type: REG = a5 ; operands[1].access: READ ; operands[2].type: IMM = 0xc ; operands[2].access: READ ; Groups: branch_relative jump

!# issue 0 RISCV operand groups 0x03,0x88,0x18,0x00 == lb a6, 1(a7)
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x03,0x88,0x18,0x00 == lb a6, 1(a7) ; op_count: 2 ; operands[0].type: REG = a6 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = a7 ; operands[1].mem.disp: 0x1 ; operands[1].access: READ

!# issue 0 RISCV operand groups 0x03,0x99,0x49,0x00 == lh s2, 4(s3)
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x03,0x99,0x49,0x00 == lh s2, 4(s3) ; op_count: 2 ; operands[0].type: REG = s2 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = s3 ; operands[1].mem.disp: 0x4 ; operands[1].access: READ

!# issue 0 RISCV operand groups 0x03,0xaa,0x6a,0x00 == lw s4, 6(s5)
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x03,0xaa,0x6a,0x00 == lw s4, 6(s5) ; op_count: 2 ; operands[0].type: REG = s4 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = s5 ; operands[1].mem.disp: 0x6 ; operands[1].access: READ

!# issue 0 RISCV operand groups 0x03,0xcb,0x2b,0x01 == lbu s6, 0x12(s7)
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x03,0xcb,0x2b,0x01 == lbu s6, 0x12(s7) ; op_count: 2 ; operands[0].type: REG = s6 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = s7 ; operands[1].mem.disp: 0x12 ; operands[1].access: READ

!# issue 0 RISCV operand groups 0x03,0xdc,0x8c,0x01 == lhu s8, 0x18(s9)
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x03,0xdc,0x8c,0x01 == lhu s8, 0x18(s9) ; op_count: 2 ; operands[0].type: REG = s8 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = s9 ; operands[1].mem.disp: 0x18 ; operands[1].access: READ

!# issue 0 RISCV operand groups 0x23,0x86,0xad,0x03 == sb s10, 0x2c(s11)
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x23,0x86,0xad,0x03 == sb s10, 0x2c(s11) ; op_count: 2 ; operands[0].type: REG = s10 ; operands[0].access: READ ; operands[1].type: MEM ; operands[1].mem.base: REG = s11 ; operands[1].mem.disp: 0x2c ; operands[1].access: WRITE

!# issue 0 RISCV operand groups 0x23,0x9a,0xce,0x03 == sh t3, 0x34(t4)
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x23,0x9a,0xce,0x03 == sh t3, 0x34(t4) ; op_count: 2 ; operands[0].type: REG = t3 ; operands[0].access: READ ; operands[1].type: MEM ; operands[1].mem.base: REG = t4 ; operands[1].mem.disp: 0x34 ; operands[1].access: WRITE

!# issue 0 RISCV operand groups 0x23,0x8f,0xef,0x01 == sb t5, 0x1e(t6)
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x23,0x8f,0xef,0x01 == sb t5, 0x1e(t6) ; op_count: 2 ; operands[0].type: REG = t5 ; operands[0].access: READ ; operands[1].type: MEM ; operands[1].mem.base: REG = t6 ; operands[1].mem.disp: 0x1e ; operands[1].access: WRITE

!# issue 0 RISCV operand groups 0x93,0x00,0xe0,0x00 == addi ra, zero, 0xe
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x93,0x00,0xe0,0x00 == addi ra, zero, 0xe ; op_count: 3 ; operands[0].type: REG = ra ; operands[0].access: WRITE ; operands[1].type: REG = zero ; operands[1].access: READ ; operands[2].type: IMM = 0xe ; operands[2].access: READ

!# issue 0 RISCV operand groups 0x13,0xa1,0x01,0x01 == slti sp, gp, 0x10
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x13,0xa1,0x01,0x01 == slti sp, gp, 0x10 ; op_count: 3 ; operands[0].type: REG = sp ; operands[0].access: WRITE ; operands[1].type: REG = gp ; operands[1].access: READ ; operands[2].type: IMM = 0x10 ; operands[2].access: READ

!# issue 0 RISCV operand groups 0x13,0xb2,0x02,0x7d == sltiu tp, t0, 0x7d0
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x13,0xb2,0x02,0x7d == sltiu tp, t0, 0x7d0 ; op_count: 3 ; operands[0].type: REG = tp ; operands[0].access: WRITE ; operands[1].type: REG = t0 ; operands[1].access: READ ; operands[2].type: IMM = 0x7d0 ; operands[2].access: READ

!# issue 0 RISCV operand groups 0x13,0xc3,0x03,0xdd == xori t1, t2, -0x230
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x13,0xc3,0x03,0xdd == xori t1, t2, -0x230 ; op_count: 3 ; operands[0].type: REG = t1 ; operands[0].access: WRITE ; operands[1].type: REG = t2 ; operands[1].access: READ ; operands[2].type: IMM = 0xfffffdd0 ; operands[2].access: READ

!# issue 0 RISCV operand groups 0x13,0xe4,0xc4,0x12 == ori s0, s1, 0x12c
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x13,0xe4,0xc4,0x12 == ori s0, s1, 0x12c ; op_count: 3 ; operands[0].type: REG = s0 ; operands[0].access: WRITE ; operands[1].type: REG = s1 ; operands[1].access: READ ; operands[2].type: IMM = 0x12c ; operands[2].access: READ

!# issue 0 RISCV operand groups 0x13,0xf5,0x85,0x0c == andi a0, a1, 0xc8
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x13,0xf5,0x85,0x0c == andi a0, a1, 0xc8 ; op_count: 3 ; operands[0].type: REG = a0 ; operands[0].access: WRITE ; operands[1].type: REG = a1 ; operands[1].access: READ ; operands[2].type: IMM = 0xc8 ; operands[2].access: READ

!# issue 0 RISCV operand groups 0x13,0x96,0xe6,0x01 == slli a2, a3, 0x1e
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x13,0x96,0xe6,0x01 == slli a2, a3, 0x1e ; op_count: 3 ; operands[0].type: REG = a2 ; operands[0].access: WRITE ; operands[1].type: REG = a3 ; operands[1].access: READ ; operands[2].type: IMM = 0x1e ; operands[2].access: READ

!# issue 0 RISCV operand groups 0x13,0xd7,0x97,0x01 == srli a4, a5, 0x19
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x13,0xd7,0x97,0x01 == srli a4, a5, 0x19 ; op_count: 3 ; operands[0].type: REG = a4 ; operands[0].access: WRITE ; operands[1].type: REG = a5 ; operands[1].access: READ ; operands[2].type: IMM = 0x19 ; operands[2].access: READ

!# issue 0 RISCV operand groups 0x13,0xd8,0xf8,0x40 == srai a6, a7, 0xf
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x13,0xd8,0xf8,0x40 == srai a6, a7, 0xf ; op_count: 3 ; operands[0].type: REG = a6 ; operands[0].access: WRITE ; operands[1].type: REG = a7 ; operands[1].access: READ ; operands[2].type: IMM = 0xf ; operands[2].access: READ

!# issue 0 RISCV operand groups 0x33,0x89,0x49,0x01 == add s2, s3, s4
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x33,0x89,0x49,0x01 == add s2, s3, s4 ; op_count: 3 ; operands[0].type: REG = s2 ; operands[0].access: WRITE ; operands[1].type: REG = s3 ; operands[1].access: READ ; operands[2].type: REG = s4 ; operands[2].access: READ

!# issue 0 RISCV operand groups 0xb3,0x0a,0x7b,0x41 == sub s5, s6, s7
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xb3,0x0a,0x7b,0x41 == sub s5, s6, s7 ; op_count: 3 ; operands[0].type: REG = s5 ; operands[0].access: WRITE ; operands[1].type: REG = s6 ; operands[1].access: READ ; operands[2].type: REG = s7 ; operands[2].access: READ

!# issue 0 RISCV operand groups 0x33,0xac,0xac,0x01 == slt s8, s9, s10
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x33,0xac,0xac,0x01 == slt s8, s9, s10 ; op_count: 3 ; operands[0].type: REG = s8 ; operands[0].access: WRITE ; operands[1].type: REG = s9 ; operands[1].access: READ ; operands[2].type: REG = s10 ; operands[2].access: READ

!# issue 0 RISCV operand groups 0xb3,0x3d,0xde,0x01 == sltu s11, t3, t4
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xb3,0x3d,0xde,0x01 == sltu s11, t3, t4 ; op_count: 3 ; operands[0].type: REG = s11 ; operands[0].access: WRITE ; operands[1].type: REG = t3 ; operands[1].access: READ ; operands[2].type: REG = t4 ; operands[2].access: READ

!# issue 0 RISCV operand groups 0x33,0xd2,0x62,0x40 == sra tp, t0, t1
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x33,0xd2,0x62,0x40 == sra tp, t0, t1 ; op_count: 3 ; operands[0].type: REG = tp ; operands[0].access: WRITE ; operands[1].type: REG = t0 ; operands[1].access: READ ; operands[2].type: REG = t1 ; operands[2].access: READ

!# issue 0 RISCV operand groups 0xb3,0x43,0x94,0x00 == xor t2, s0, s1
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xb3,0x43,0x94,0x00 == xor t2, s0, s1 ; op_count: 3 ; operands[0].type: REG = t2 ; operands[0].access: WRITE ; operands[1].type: REG = s0 ; operands[1].access: READ ; operands[2].type: REG = s1 ; operands[2].access: READ

!# issue 0 RISCV operand groups 0x33,0xe5,0xc5,0x00 == or a0, a1, a2
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x33,0xe5,0xc5,0x00 == or a0, a1, a2 ; op_count: 3 ; operands[0].type: REG = a0 ; operands[0].access: WRITE ; operands[1].type: REG = a1 ; operands[1].access: READ ; operands[2].type: REG = a2 ; operands[2].access: READ

!# issue 0 RISCV operand groups 0xb3,0x76,0xf7,0x00 == and a3, a4, a5
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xb3,0x76,0xf7,0x00 == and a3, a4, a5 ; op_count: 3 ; operands[0].type: REG = a3 ; operands[0].access: WRITE ; operands[1].type: REG = a4 ; operands[1].access: READ ; operands[2].type: REG = a5 ; operands[2].access: READ

!# issue 0 RISCV operand groups 0xb3,0x54,0x39,0x01 == srl s1, s2, s3
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xb3,0x54,0x39,0x01 == srl s1, s2, s3 ; op_count: 3 ; operands[0].type: REG = s1 ; operands[0].access: WRITE ; operands[1].type: REG = s2 ; operands[1].access: READ ; operands[2].type: REG = s3 ; operands[2].access: READ

!# issue 0 RISCV operand groups 0xb3,0x50,0x31,0x00 == srl ra, sp, gp
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xb3,0x50,0x31,0x00 == srl ra, sp, gp ; op_count: 3 ; operands[0].type: REG = ra ; operands[0].access: WRITE ; operands[1].type: REG = sp ; operands[1].access: READ ; operands[2].type: REG = gp ; operands[2].access: READ

!# issue 0 RISCV operand groups 0x33,0x9f,0x0f,0x00 == sll t5, t6, zero
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x33,0x9f,0x0f,0x00 == sll t5, t6, zero ; op_count: 3 ; operands[0].type: REG = t5 ; operands[0].access: WRITE ; operands[1].type: REG = t6 ; operands[1].access: READ ; operands[2].type: REG = zero ; operands[2].access: READ

!# issue 0 RISCV operand groups 0x73,0x15,0x04,0xb0 == csrrw a0, mcycle, s0
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x73,0x15,0x04,0xb0 == csrrw a0, mcycle, s0 ; op_count: 2 ; operands[0].type: REG = a0 ; operands[0].access: WRITE ; operands[1].type: REG = s0 ; operands[1].access: READ

!# issue 0 RISCV operand groups 0xf3,0x56,0x00,0x10 == csrrwi a3, sstatus, 0
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xf3,0x56,0x00,0x10 == csrrwi a3, sstatus, 0 ; op_count: 2 ; operands[0].type: REG = a3 ; operands[0].access: WRITE ; operands[1].type: IMM = 0x0 ; operands[1].access: READ

!# issue 0 RISCV operand groups 0x33,0x05,0x7b,0x03 == mul a0, s6, s7
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x33,0x05,0x7b,0x03 == mul a0, s6, s7 ; op_count: 3 ; operands[0].type: REG = a0 ; operands[0].access: WRITE ; operands[1].type: REG = s6 ; operands[1].access: READ ; operands[2].type: REG = s7 ; operands[2].access: READ ; Groups: hasStdExtM

!# issue 0 RISCV operand groups 0xb3,0x45,0x9c,0x03 == div a1, s8, s9
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xb3,0x45,0x9c,0x03 == div a1, s8, s9 ; op_count: 3 ; operands[0].type: REG = a1 ; operands[0].access: WRITE ; operands[1].type: REG = s8 ; operands[1].access: READ ; operands[2].type: REG = s9 ; operands[2].access: READ ; Groups: hasStdExtM

!# issue 0 RISCV operand groups 0x33,0x66,0xbd,0x03 == rem a2, s10, s11
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x33,0x66,0xbd,0x03 == rem a2, s10, s11 ; op_count: 3 ; operands[0].type: REG = a2 ; operands[0].access: WRITE ; operands[1].type: REG = s10 ; operands[1].access: READ ; operands[2].type: REG = s11 ; operands[2].access: READ ; Groups: hasStdExtM

!# issue 0 RISCV operand groups 0x2f,0xa4,0x02,0x10 == lr.w s0, (t0)
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x2f,0xa4,0x02,0x10 == lr.w s0, (t0) ; op_count: 2 ; operands[0].type: REG = s0 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = t0 ; operands[1].access: READ ; Groups: hasStdExtA

!# issue 0 RISCV operand groups 0xaf,0x23,0x65,0x18 == sc.w t2, t1, (a0)
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xaf,0x23,0x65,0x18 == sc.w t2, t1, (a0) ; op_count: 3 ; operands[0].type: REG = t2 ; operands[0].access: WRITE ; operands[1].type: REG = t1 ; operands[1].access: READ ; operands[2].type: MEM ; operands[2].mem.base: REG = a0 ; operands[2].access: WRITE ; Groups: hasStdExtA

!# issue 0 RISCV operand groups 0x2f,0x27,0x2f,0x01 == amoadd.w a4, s2, (t5)
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x2f,0x27,0x2f,0x01 == amoadd.w a4, s2, (t5) ; op_count: 3 ; operands[0].type: REG = a4 ; operands[0].access: WRITE ; operands[1].type: REG = s2 ; operands[1].access: READ ; operands[2].type: MEM ; operands[2].mem.base: REG = t5 ; operands[2].access: READ | WRITE ; Groups: hasStdExtA

!# issue 0 RISCV operand groups 0x43,0xf0,0x20,0x18 == fmadd.s ft0, ft1, ft2, ft3
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x43,0xf0,0x20,0x18 == fmadd.s ft0, ft1, ft2, ft3 ; op_count: 4 ; operands[0].type: REG = ft0 ; operands[0].access: WRITE ; operands[1].type: REG = ft1 ; operands[1].access: READ ; operands[2].type: REG = ft2 ; operands[2].access: READ ; operands[3].type: REG = ft3 ; operands[3].access: READ ; Groups: hasStdExtF

!# issue 0 RISCV operand groups 0xd3,0x72,0x73,0x00 == fadd.s ft5, ft6, ft7
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xd3,0x72,0x73,0x00 == fadd.s ft5, ft6, ft7 ; op_count: 3 ; operands[0].type: REG = ft5 ; operands[0].access: WRITE ; operands[1].type: REG = ft6 ; operands[1].access: READ ; operands[2].type: REG = ft7 ; operands[2].access: READ ; Groups: hasStdExtF

!# issue 0 RISCV operand groups 0x53,0xf4,0x04,0x58 == fsqrt.s fs0, fs1
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x53,0xf4,0x04,0x58 == fsqrt.s fs0, fs1 ; op_count: 2 ; operands[0].type: REG = fs0 ; operands[0].access: WRITE ; operands[1].type: REG = fs1 ; operands[1].access: READ ; Groups: hasStdExtF

!# issue 0 RISCV operand groups 0x53,0x85,0xc5,0x28 == fmin.s fa0, fa1, fa2
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x53,0x85,0xc5,0x28 == fmin.s fa0, fa1, fa2 ; op_count: 3 ; operands[0].type: REG = fa0 ; operands[0].access: WRITE ; operands[1].type: REG = fa1 ; operands[1].access: READ ; operands[2].type: REG = fa2 ; operands[2].access: READ ; Groups: hasStdExtF

!# issue 0 RISCV operand groups 0x53,0x2e,0xde,0xa1 == feq.s t3, ft8, ft9
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x53,0x2e,0xde,0xa1 == feq.s t3, ft8, ft9 ; op_count: 3 ; operands[0].type: REG = t3 ; operands[0].access: WRITE ; operands[1].type: REG = ft8 ; operands[1].access: READ ; operands[2].type: REG = ft9 ; operands[2].access: READ ; Groups: hasStdExtF

!# issue 0 RISCV operand groups 0xd3,0x84,0x05,0xf0 == fmv.w.x fs1, a1
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xd3,0x84,0x05,0xf0 == fmv.w.x fs1, a1 ; op_count: 2 ; operands[0].type: REG = fs1 ; operands[0].access: WRITE ; operands[1].type: REG = a1 ; operands[1].access: READ ; Groups: hasStdExtF

!# issue 0 RISCV operand groups 0x53,0x06,0x05,0xe0 == fmv.x.w a2, fa0
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x53,0x06,0x05,0xe0 == fmv.x.w a2, fa0 ; op_count: 2 ; operands[0].type: REG = a2 ; operands[0].access: WRITE ; operands[1].type: REG = fa0 ; operands[1].access: READ ; Groups: hasStdExtF

!# issue 0 RISCV operand groups 0x53,0x75,0x00,0xc0 == fcvt.w.s a0, ft0
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x53,0x75,0x00,0xc0 == fcvt.w.s a0, ft0 ; op_count: 2 ; operands[0].type: REG = a0 ; operands[0].access: WRITE ; operands[1].type: REG = ft0 ; operands[1].access: READ ; Groups: hasStdExtF

!# issue 0 RISCV operand groups 0xd3,0xf0,0x05,0xd0 == fcvt.s.w ft1, a1
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xd3,0xf0,0x05,0xd0 == fcvt.s.w ft1, a1 ; op_count: 2 ; operands[0].type: REG = ft1 ; operands[0].access: WRITE ; operands[1].type: REG = a1 ; operands[1].access: READ ; Groups: hasStdExtF

!# issue 0 RISCV operand groups 0xd3,0x15,0x08,0xe0 == fclass.s a1, fa6
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xd3,0x15,0x08,0xe0 == fclass.s a1, fa6 ; op_count: 2 ; operands[0].type: REG = a1 ; operands[0].access: WRITE ; operands[1].type: REG = fa6 ; operands[1].access: READ ; Groups: hasStdExtF

!# issue 0 RISCV operand groups 0x87,0xaa,0x75,0x00 == flw fs5, 7(a1)
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x87,0xaa,0x75,0x00 == flw fs5, 7(a1) ; op_count: 2 ; operands[0].type: REG = fs5 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = a1 ; operands[1].mem.disp: 0x7 ; operands[1].access: READ ; Groups: hasStdExtF

!# issue 0 RISCV operand groups 0x27,0x27,0x66,0x01 == fsw fs6, 0xe(a2)
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x27,0x27,0x66,0x01 == fsw fs6, 0xe(a2) ; op_count: 2 ; operands[0].type: REG = fs6 ; operands[0].access: READ ; operands[1].type: MEM ; operands[1].mem.base: REG = a2 ; operands[1].mem.disp: 0xe ; operands[1].access: WRITE ; Groups: hasStdExtF

!# issue 0 RISCV operand groups 0x43,0xf0,0x20,0x1a == fmadd.d ft0, ft1, ft2, ft3
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x43,0xf0,0x20,0x1a == fmadd.d ft0, ft1, ft2, ft3 ; op_count: 4 ; operands[0].type: REG = ft0 ; operands[0].access: WRITE ; operands[1].type: REG = ft1 ; operands[1].access: READ ; operands[2].type: REG = ft2 ; operands[2].access: READ ; operands[3].type: REG = ft3 ; operands[3].access: READ ; Groups: hasStdExtD

!# issue 0 RISCV operand groups 0xd3,0x72,0x73,0x02 == fadd.d ft5, ft6, ft7
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xd3,0x72,0x73,0x02 == fadd.d ft5, ft6, ft7 ; op_count: 3 ; operands[0].type: REG = ft5 ; operands[0].access: WRITE ; operands[1].type: REG = ft6 ; operands[1].access: READ ; operands[2].type: REG = ft7 ; operands[2].access: READ ; Groups: hasStdExtD

!# issue 0 RISCV operand groups 0x53,0xf4,0x04,0x5a == fsqrt.d fs0, fs1
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x53,0xf4,0x04,0x5a == fsqrt.d fs0, fs1 ; op_count: 2 ; operands[0].type: REG = fs0 ; operands[0].access: WRITE ; operands[1].type: REG = fs1 ; operands[1].access: READ ; Groups: hasStdExtD

!# issue 0 RISCV operand groups 0x53,0x85,0xc5,0x2a == fmin.d fa0, fa1, fa2
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x53,0x85,0xc5,0x2a == fmin.d fa0, fa1, fa2 ; op_count: 3 ; operands[0].type: REG = fa0 ; operands[0].access: WRITE ; operands[1].type: REG = fa1 ; operands[1].access: READ ; operands[2].type: REG = fa2 ; operands[2].access: READ ; Groups: hasStdExtD

!# issue 0 RISCV operand groups 0x53,0x2e,0xde,0xa3 == feq.d t3, ft8, ft9
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x53,0x2e,0xde,0xa3 == feq.d t3, ft8, ft9 ; op_count: 3 ; operands[0].type: REG = t3 ; operands[0].access: WRITE ; operands[1].type: REG = ft8 ; operands[1].access: READ ; operands[2].type: REG = ft9 ; operands[2].access: READ ; Groups: hasStdExtD

!# issue 0 RISCV operand groups 0x13,0x04,0xa8,0x7a == addi s0, a6, 0x7aa
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0x13,0x04,0xa8,0x7a == addi s0, a6, 0x7aa ; op_count: 3 ; operands[0].type: REG = s0 ; operands[0].access: WRITE ; operands[1].type: REG = a6 ; operands[1].access: READ ; operands[2].type: IMM = 0x7aa ; operands[2].access: READ

!# issue 0 RISCV operand groups 0xbb,0x07,0x9c,0x02 == mulw a5, s8, s1
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0xbb,0x07,0x9c,0x02 == mulw a5, s8, s1 ; op_count: 3 ; operands[0].type: REG = a5 ; operands[0].access: WRITE ; operands[1].type: REG = s8 ; operands[1].access: READ ; operands[2].type: REG = s1 ; operands[2].access: READ ; Groups: hasStdExtM isrv64

!# issue 0 RISCV operand groups 0xbb,0x40,0x5d,0x02 == divw ra, s10, t0
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0xbb,0x40,0x5d,0x02 == divw ra, s10, t0 ; op_count: 3 ; operands[0].type: REG = ra ; operands[0].access: WRITE ; operands[1].type: REG = s10 ; operands[1].access: READ ; operands[2].type: REG = t0 ; operands[2].access: READ ; Groups: hasStdExtM isrv64

!# issue 0 RISCV operand groups 0x3b,0x63,0xb7,0x03 == remw t1, a4, s11
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0x3b,0x63,0xb7,0x03 == remw t1, a4, s11 ; op_count: 3 ; operands[0].type: REG = t1 ; operands[0].access: WRITE ; operands[1].type: REG = a4 ; operands[1].access: READ ; operands[2].type: REG = s11 ; operands[2].access: READ ; Groups: hasStdExtM isrv64

!# issue 0 RISCV operand groups 0x2f,0xb4,0x02,0x10 == lr.d s0, (t0)
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0x2f,0xb4,0x02,0x10 == lr.d s0, (t0) ; op_count: 2 ; operands[0].type: REG = s0 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = t0 ; operands[1].access: READ ; Groups: hasStdExtA isrv64

!# issue 0 RISCV operand groups 0xaf,0x33,0x65,0x18 == sc.d t2, t1, (a0)
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0xaf,0x33,0x65,0x18 == sc.d t2, t1, (a0) ; op_count: 3 ; operands[0].type: REG = t2 ; operands[0].access: WRITE ; operands[1].type: REG = t1 ; operands[1].access: READ ; operands[2].type: MEM ; operands[2].mem.base: REG = a0 ; operands[2].access: WRITE ; Groups: hasStdExtA isrv64

!# issue 0 RISCV operand groups 0x2f,0x37,0x2f,0x01 == amoadd.d a4, s2, (t5)
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0x2f,0x37,0x2f,0x01 == amoadd.d a4, s2, (t5) ; op_count: 3 ; operands[0].type: REG = a4 ; operands[0].access: WRITE ; operands[1].type: REG = s2 ; operands[1].access: READ ; operands[2].type: MEM ; operands[2].mem.base: REG = t5 ; operands[2].access: READ | WRITE ; Groups: hasStdExtA isrv64

!# issue 0 RISCV operand groups 0x53,0x75,0x20,0xc0 == fcvt.l.s a0, ft0
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0x53,0x75,0x20,0xc0 == fcvt.l.s a0, ft0 ; op_count: 2 ; operands[0].type: REG = a0 ; operands[0].access: WRITE ; operands[1].type: REG = ft0 ; operands[1].access: READ ; Groups: hasStdExtF isrv64

!# issue 0 RISCV operand groups 0xd3,0xf0,0x25,0xd0 == fcvt.s.l ft1, a1
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0xd3,0xf0,0x25,0xd0 == fcvt.s.l ft1, a1 ; op_count: 2 ; operands[0].type: REG = ft1 ; operands[0].access: WRITE ; operands[1].type: REG = a1 ; operands[1].access: READ ; Groups: hasStdExtF isrv64

!# issue 0 RISCV operand groups 0xd3,0x84,0x05,0xf2 == fmv.d.x fs1, a1
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0xd3,0x84,0x05,0xf2 == fmv.d.x fs1, a1 ; op_count: 2 ; operands[0].type: REG = fs1 ; operands[0].access: WRITE ; operands[1].type: REG = a1 ; operands[1].access: READ ; Groups: hasStdExtD isrv64

!# issue 0 RISCV operand groups 0x53,0x06,0x05,0xe2 == fmv.x.d a2, fa0
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0x53,0x06,0x05,0xe2 == fmv.x.d a2, fa0 ; op_count: 2 ; operands[0].type: REG = a2 ; operands[0].access: WRITE ; operands[1].type: REG = fa0 ; operands[1].access: READ ; Groups: hasStdExtD isrv64

!# issue 0 RISCV operand groups 0x53,0x75,0x00,0xc2 == fcvt.w.d a0, ft0
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0x53,0x75,0x00,0xc2 == fcvt.w.d a0, ft0 ; op_count: 2 ; operands[0].type: REG = a0 ; operands[0].access: WRITE ; operands[1].type: REG = ft0 ; operands[1].access: READ ; Groups: hasStdExtD

!# issue 0 RISCV operand groups 0xd3,0x80,0x05,0xd2 == fcvt.d.w ft1, a1
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0xd3,0x80,0x05,0xd2 == fcvt.d.w ft1, a1 ; op_count: 2 ; operands[0].type: REG = ft1 ; operands[0].access: WRITE ; operands[1].type: REG = a1 ; operands[1].access: READ ; Groups: hasStdExtD

!# issue 0 RISCV operand groups 0xd3,0x15,0x08,0xe2 == fclass.d a1, fa6
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0xd3,0x15,0x08,0xe2 == fclass.d a1, fa6 ; op_count: 2 ; operands[0].type: REG = a1 ; operands[0].access: WRITE ; operands[1].type: REG = fa6 ; operands[1].access: READ ; Groups: hasStdExtD

!# issue 0 RISCV operand groups 0x87,0xba,0x75,0x00 == fld fs5, 7(a1)
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0x87,0xba,0x75,0x00 == fld fs5, 7(a1) ; op_count: 2 ; operands[0].type: REG = fs5 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = a1 ; operands[1].mem.disp: 0x7 ; operands[1].access: READ ; Groups: hasStdExtD

!# issue 0 RISCV operand groups 0x27,0x37,0x66,0x01 == fsd fs6, 0xe(a2)
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0x27,0x37,0x66,0x01 == fsd fs6, 0xe(a2) ; op_count: 2 ; operands[0].type: REG = fs6 ; operands[0].access: READ ; operands[1].type: MEM ; operands[1].mem.base: REG = a2 ; operands[1].mem.disp: 0xe ; operands[1].access: WRITE ; Groups: hasStdExtD

!# issue 0 RISCV operand groups 0xe8,0x1f == c.addi4spn a0, sp, 0x3fc
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0xe8,0x1f == c.addi4spn a0, sp, 0x3fc ; op_count: 3 ; operands[0].type: REG = a0 ; operands[0].access: WRITE ; operands[1].type: REG = sp ; operands[1].access: READ ; operands[2].type: IMM = 0x3fc ; operands[2].access: READ ; Groups: hasStdExtC

!# issue 0 RISCV operand groups 0x7d,0x61 == c.addi16sp sp, 0x1f0
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0x7d,0x61 == c.addi16sp sp, 0x1f0 ; op_count: 2 ; operands[0].type: REG = sp ; operands[0].access: READ | WRITE ; operands[1].type: IMM = 0x1f0 ; operands[1].access: READ ; Groups: hasStdExtC

!# issue 0 RISCV operand groups 0x80,0x25 == c.fld fs0, 8(a1)
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0x80,0x25 == c.fld fs0, 8(a1) ; op_count: 2 ; operands[0].type: REG = fs0 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = a1 ; operands[1].mem.disp: 0x8 ; operands[1].access: READ ; Groups: hasStdExtC hasStdExtD

!# issue 0 RISCV operand groups 0x00,0x46 == c.lw s0, 8(a2)
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0x00,0x46 == c.lw s0, 8(a2) ; op_count: 2 ; operands[0].type: REG = s0 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = a2 ; operands[1].mem.disp: 0x8 ; operands[1].access: READ ; Groups: hasStdExtC

!# issue 0 RISCV operand groups 0x88,0xa2 == c.fsd fa0, 0(a3)
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0x88,0xa2 == c.fsd fa0, 0(a3) ; op_count: 2 ; operands[0].type: REG = fa0 ; operands[0].access: READ ; operands[1].type: MEM ; operands[1].mem.base: REG = a3 ; operands[1].access: WRITE ; Groups: hasStdExtC hasStdExtD

!# issue 0 RISCV operand groups 0x04,0xcb == c.sw s1, 0x10(a4)
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0x04,0xcb == c.sw s1, 0x10(a4) ; op_count: 2 ; operands[0].type: REG = s1 ; operands[0].access: READ ; operands[1].type: MEM ; operands[1].mem.base: REG = a4 ; operands[1].mem.disp: 0x10 ; operands[1].access: WRITE ; Groups: hasStdExtC

!# issue 0 RISCV operand groups 0x55,0x13 == c.addi t1, -0xb
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0x55,0x13 == c.addi t1, -0xb ; op_count: 2 ; operands[0].type: REG = t1 ; operands[0].access: READ | WRITE ; operands[1].type: IMM = 0xfffffff5 ; operands[1].access: READ ; Groups: hasStdExtC

!# issue 0 RISCV operand groups 0xf2,0x93 == c.add t2, t3
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0xf2,0x93 == c.add t2, t3 ; op_count: 2 ; operands[0].type: REG = t2 ; operands[0].access: READ | WRITE ; operands[1].type: REG = t3 ; operands[1].access: READ ; Groups: hasStdExtC

!# issue 0 RISCV operand groups 0x5d,0x45 == c.li a0, 0x17
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0x5d,0x45 == c.li a0, 0x17 ; op_count: 2 ; operands[0].type: REG = a0 ; operands[0].access: WRITE ; operands[1].type: IMM = 0x17 ; operands[1].access: READ ; Groups: hasStdExtC

!# issue 0 RISCV operand groups 0x19,0x80 == c.srli s0, 6
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0x19,0x80 == c.srli s0, 6 ; op_count: 2 ; operands[0].type: REG = s0 ; operands[0].access: READ | WRITE ; operands[1].type: IMM = 0x6 ; operands[1].access: READ ; Groups: hasStdExtC

!# issue 0 RISCV operand groups 0x15,0x68 == c.lui a6, 5
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0x15,0x68 == c.lui a6, 5 ; op_count: 2 ; operands[0].type: REG = a6 ; operands[0].access: WRITE ; operands[1].type: IMM = 0x5 ; operands[1].access: READ ; Groups: hasStdExtC

!# issue 0 RISCV operand groups 0x2a,0xa4 == c.fsdsp fa0, 8(sp)
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0x2a,0xa4 == c.fsdsp fa0, 8(sp) ; op_count: 2 ; operands[0].type: REG = fa0 ; operands[0].access: READ ; operands[1].type: MEM ; operands[1].mem.base: REG = sp ; operands[1].mem.disp: 0x8 ; operands[1].access: WRITE ; Groups: hasStdExtC hasStdExtD

!# issue 0 RISCV operand groups 0x62,0x24 == c.fldsp fs0, 0x18(sp)
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0x62,0x24 == c.fldsp fs0, 0x18(sp) ; op_count: 2 ; operands[0].type: REG = fs0 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = sp ; operands[1].mem.disp: 0x18 ; operands[1].access: READ ; Groups: hasStdExtC hasStdExtD

!# issue 0 RISCV operand groups 0xa6,0xff == c.fswsp fs1, 0xfc(sp)
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0xa6,0xff == c.fswsp fs1, 0xfc(sp) ; op_count: 3 ; operands[0].type: REG = fs1 ; operands[0].access: READ ; operands[1].type: IMM = 0xfc ; operands[1].access: READ ; operands[2].type: REG = sp ; operands[2].access: WRITE ; Groups: hasStdExtC hasStdExtF isrv32

!# issue 0 RISCV operand groups 0x2a,0x65 == c.flwsp fa0, 0x88(sp)
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0x2a,0x65 == c.flwsp fa0, 0x88(sp) ; op_count: 3 ; operands[0].type: REG = fa0 ; operands[0].access: WRITE ; operands[1].type: IMM = 0x88 ; operands[1].access: READ ; operands[2].type: REG = sp ; operands[2].access: READ ; Groups: hasStdExtC hasStdExtF isrv32

!# issue 0 RISCV operand groups 0x76,0x86 == c.mv a2, t4
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0x76,0x86 == c.mv a2, t4 ; op_count: 2 ; operands[0].type: REG = a2 ; operands[0].access: WRITE ; operands[1].type: REG = t4 ; operands[1].access: READ ; Groups: hasStdExtC

!# issue 0 RISCV operand groups 0x65,0xdd == c.beqz a0, -8
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0x65,0xdd == c.beqz a0, -8 ; op_count: 2 ; operands[0].type: REG = a0 ; operands[0].access: READ ; operands[1].type: IMM = 0xfffffff8 ; operands[1].access: READ ; Groups: hasStdExtC branch_relative jump

!# issue 0 RISCV operand groups 0x01,0x00 == c.nop
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0x01,0x00 == c.nop ; Groups: hasStdExtC

!# issue 0 RISCV operand groups 0xfd,0xaf == c.j 0x7fe
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0xfd,0xaf == c.j 0x7fe ; op_count: 1 ; operands[0].type: IMM = 0x7fe ; operands[0].access: READ ; Groups: hasStdExtC jump

!# issue 0 RISCV operand groups 0x82,0x82 == c.jr t0
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0x82,0x82 == c.jr t0 ; op_count: 1 ; operands[0].type: REG = t0 ; operands[0].access: READ ; Groups: hasStdExtC jump

!# issue 0 RISCV operand groups 0x11,0x20 == c.jal 4
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0x11,0x20 == c.jal 4 ; op_count: 1 ; operands[0].type: IMM = 0x4 ; operands[0].access: READ ; Groups: hasStdExtC isrv32 call

!# issue 0 RISCV operand groups 0x82,0x94 == c.jalr s1
!# CS_ARCH_RISCV, CS_MODE_RISCVC, CS_OPT_DETAIL
0x82,0x94 == c.jalr s1 ; op_count: 1 ; operands[0].type: REG = s1 ; operands[0].access: READ ; Groups: hasStdExtC call

!# issue 2285 AArch64 operands
!# CS_ARCH_AARCH64, CS_MODE_ARM, CS_OPT_DETAIL
0xc0,0x08,0x9f,0xe0 == ld1w {za0h.s[w12, 0]}, p2/z, [x6] ; op_count: 3 ; operands[0].type: SME_MATRIX ; operands[0].sme.type: 2 ; operands[0].sme.tile: za0.s ; operands[0].sme.slice_reg: w12 ; operands[0].sme.slice_offset: 0 ; operands[0].sme.is_vertical: false ; operands[0].access: WRITE ; operands[0].vas: 0x20 ; operands[1].type: PREDICATE ; operands[1].pred.reg: p2 ; operands[1].access: READ ; operands[2].type: MEM ; operands[2].mem.base: REG = x6 ; operands[2].access: READ ; Registers read: w12 p2 x6 ; Registers modified: za0.s ; Groups: HasSME

!# issue 2285 AArch64 operands
!# CS_ARCH_AARCH64, CS_MODE_ARM, CS_OPT_DETAIL
0x41,0x31,0xa2,0xe0 == st1w {za0h.s[w13, 1]}, p4, [x10, x2, lsl #2] ; op_count: 3 ; operands[0].type: SME_MATRIX ; operands[0].sme.type: 2 ; operands[0].sme.tile: za0.s ; operands[0].sme.slice_reg: w13 ; operands[0].sme.slice_offset: 1 ; operands[0].sme.is_vertical: false ; operands[0].access: READ ; operands[0].vas: 0x20 ; operands[1].type: PREDICATE ; operands[1].pred.reg: p4 ; operands[1].access: READ ; operands[2].type: MEM ; operands[2].mem.base: REG = x10 ; operands[2].mem.index: REG = x2 ; operands[2].access: WRITE ; Shift: type = 1, value = 2 ; Registers read: za0.s w13 p4 x10 x2 ; Groups: HasSME

!# issue 2285 AArch64 operands
!# CS_ARCH_AARCH64, CS_MODE_ARM, CS_OPT_DETAIL
0x67,0x44,0x71,0x25 == psel p7, p1, p3.s[w13, 1] ; op_count: 3 ; operands[0].type: PREDICATE ; operands[0].pred.reg: p7 ; operands[0].access: WRITE ; operands[1].type: PREDICATE ; operands[1].pred.reg: p1 ; operands[1].access: READ ; operands[2].type: PREDICATE ; operands[2].pred.reg: p3 ; operands[2].pred.vec_select: w13 ; operands[2].pred.imm_index: 1 ; operands[2].access: READ ; operands[2].vas: 0x20 ; Registers read: p1 p3 w13 ; Registers modified: p7 ; Groups: HasSVE2p1_or_HasSME

!# issue 2285 AArch64 operands
!# CS_ARCH_AARCH64, CS_MODE_ARM, CS_OPT_DETAIL
0x7f,0x47,0x03,0xd5 == smstart ; Code-condition: 16 ; Groups: privilege

!# issue 2285 AArch64 operands
!# CS_ARCH_AARCH64, CS_MODE_ARM, CS_OPT_DETAIL
0x55,0x00,0x08,0xc0 == zero {za0.h} ; op_count: 1 ; operands[0].type: SME_MATRIX ; operands[0].sme.type: 1 ; operands[0].sme.tile: za0.h ; operands[0].access: WRITE ; operands[0].vas: 0x10 ; Code-condition: 16 ; Registers modified: za0.h ; Groups: HasSME

!# issue 2285 AArch64 operands
!# CS_ARCH_AARCH64, CS_MODE_ARM, CS_OPT_DETAIL
0x02,0xf8,0x55,0xc1 == sdot za.s[w11, 2, vgx4], { z0.h - z3.h }, z5.h[2] ; op_count: 6 ; operands[0].type: SME_MATRIX ; operands[0].sme.type: 2 ; operands[0].sme.tile: za ; operands[0].sme.slice_reg: w11 ; operands[0].sme.slice_offset: 2 ; operands[0].sme.is_vertical: false ; operands[0].access: READ | WRITE ; operands[0].vas: 0x20 ; operands[1].type: REG = z0 ; operands[1].is_list_member: true ; operands[1].access: READ ; operands[1].vas: 0x10 ; operands[2].type: REG = z1 ; operands[2].is_list_member: true ; operands[2].access: READ ; operands[2].vas: 0x10 ; operands[3].type: REG = z2 ; operands[3].is_list_member: true ; operands[3].access: READ ; operands[3].vas: 0x10 ; operands[4].type: REG = z3 ; operands[4].is_list_member: true ; operands[4].access: READ ; operands[4].vas: 0x10 ; operands[5].type: REG = z5 ; operands[5].access: READ ; operands[5].vas: 0x10 ; operands[5].vector_index: 2 ; Write-back: True ; Code-condition: 16 ; Registers read: za w11 z0 z1 z2 z3 z5 ; Registers modified: za ; Groups: HasSME2

!# issue 2285 AArch64 operands
!# CS_ARCH_AARCH64, CS_MODE_ARM, CS_OPT_DETAIL
0xa4,0x0e,0x06,0xc0 == movaz { z4.d - z7.d }, za.d[w8, 5, vgx4] ; op_count: 5 ; operands[0].type: REG = z4 ; operands[0].is_list_member: true ; operands[0].access: WRITE ; operands[0].vas: 0x40 ; operands[1].type: REG = z5 ; operands[1].is_list_member: true ; operands[1].access: WRITE ; operands[1].vas: 0x40 ; operands[2].type: REG = z6 ; operands[2].is_list_member: true ; operands[2].access: WRITE ; operands[2].vas: 0x40 ; operands[3].type: REG = z7 ; operands[3].is_list_member: true ; operands[3].access: WRITE ; operands[3].vas: 0x40 ; operands[4].type: SME_MATRIX ; operands[4].sme.type: 2 ; operands[4].sme.tile: za ; operands[4].sme.slice_reg: w8 ; operands[4].sme.slice_offset: 5 ; operands[4].sme.is_vertical: false ; operands[4].access: READ | WRITE ; operands[4].vas: 0x40 ; Write-back: True ; Code-condition: 16 ; Registers read: za w8 ; Registers modified: z4 z5 z6 z7 za ; Groups: HasSME2p1

!# issue 2285 AArch64 operands
!# CS_ARCH_AARCH64, CS_MODE_ARM, CS_OPT_DETAIL
0x80,0xa0,0x8d,0xc0 == luti2 { z0.s - z3.s }, zt0, z4[1] ; op_count: 6 ; operands[0].type: REG = z0 ; operands[0].is_list_member: true ; operands[0].access: WRITE ; operands[0].vas: 0x20 ; operands[1].type: REG = z1 ; operands[1].is_list_member: true ; operands[1].access: WRITE ; operands[1].vas: 0x20 ; operands[2].type: REG = z2 ; operands[2].is_list_member: true ; operands[2].access: WRITE ; operands[2].vas: 0x20 ; operands[3].type: REG = z3 ; operands[3].is_list_member: true ; operands[3].access: WRITE ; operands[3].vas: 0x20 ; operands[4].type: REG = zt0 ; operands[4].access: READ ; operands[5].type: REG = z4 ; operands[5].access: READ ; operands[5].vector_index: 1 ; Code-condition: 16 ; Registers read: zt0 z4 ; Registers modified: z0 z1 z2 z3 ; Groups: HasSME2

!# issue 2285 AArch64 operands
!# CS_ARCH_AARCH64, CS_MODE_ARM, CS_OPT_DETAIL
0x00,0xb1,0x10,0xc1 == fmla za.h[w9, 0, vgx4], { z8.h - z11.h }, z0.h[0] ; op_count: 6 ; operands[0].type: SME_MATRIX ; operands[0].sme.type: 2 ; operands[0].sme.tile: za ; operands[0].sme.slice_reg: w9 ; operands[0].sme.slice_offset: 0 ; operands[0].sme.is_vertical: false ; operands[0].access: READ | WRITE ; operands[0].vas: 0x10 ; operands[1].type: REG = z8 ; operands[1].is_list_member: true ; operands[1].access: READ ; operands[1].vas: 0x10 ; operands[2].type: REG = z9 ; operands[2].is_list_member: true ; operands[2].access: READ ; operands[2].vas: 0x10 ; operands[3].type: REG = z10 ; operands[3].is_list_member: true ; operands[3].access: READ ; operands[3].vas: 0x10 ; operands[4].type: REG = z11 ; operands[4].is_list_member: true ; operands[4].access: READ ; operands[4].vas: 0x10 ; operands[5].type: REG = z0 ; operands[5].access: READ ; operands[5].vas: 0x10 ; operands[5].vector_index: 0 ; Write-back: True ; Code-condition: 16 ; Registers read: za w9 z8 z9 z10 z11 z0 ; Registers modified: za ; Groups: HasSME2p1 HasSMEF16F16

!# issue 2285 AArch64 operands
!# CS_ARCH_AARCH64, CS_MODE_ARM, CS_OPT_DETAIL
0x05,0xd0,0x9b,0xc1 == fmlal za.s[w10, 2:3, vgx4], { z0.h - z3.h }, z11.h[1] ; op_count: 6 ; operands[0].type: SME_MATRIX ; operands[0].sme.type: 2 ; operands[0].sme.tile: za ; operands[0].sme.slice_reg: w10 ; operands[0].sme.slice_offset: 2:3 ; operands[0].sme.is_vertical: false ; operands[0].access: READ | WRITE ; operands[0].vas: 0x20 ; operands[1].type: REG = z0 ; operands[1].is_list_member: true ; operands[1].access: READ ; operands[1].vas: 0x10 ; operands[2].type: REG = z1 ; operands[2].is_list_member: true ; operands[2].access: READ ; operands[2].vas: 0x10 ; operands[3].type: REG = z2 ; operands[3].is_list_member: true ; operands[3].access: READ ; operands[3].vas: 0x10 ; operands[4].type: REG = z3 ; operands[4].is_list_member: true ; operands[4].access: READ ; operands[4].vas: 0x10 ; operands[5].type: REG = z11 ; operands[5].access: READ ; operands[5].vas: 0x10 ; operands[5].vector_index: 1 ; Write-back: True ; Code-condition: 16 ; Registers read: za w10 z0 z1 z2 z3 z11 ; Registers modified: za ; Groups: HasSME2

