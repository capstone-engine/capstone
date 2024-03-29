# CS_ARCH_ARM, CS_MODE_THUMB+CS_MODE_MCLASS, None
0xa8,0xee,0xce,0x0f = vshlc q0, lr, #8
0xa8,0xee,0x4c,0x0f = vmovlb.s8 q0, q6
0xa8,0xee,0x48,0x1f = vmovlt.s8 q0, q4
0x41,0xfe,0x00,0x0f = vpt.i8 eq, q0, q0
0xa8,0xee,0x48,0x1f = vmovltt.s8 q0, q4
0xa8,0xfe,0x40,0x0f = vmovlb.u8 q0, q0
0xa8,0xfe,0x44,0x1f = vmovlt.u8 q0, q2
0xb0,0xfe,0x40,0x2f = vmovlb.u16 q1, q0
0xb0,0xfe,0x44,0x1f = vmovlt.u16 q0, q2
0x31,0xee,0x05,0x0e = vshllb.s8 q0, q2, #8
0x31,0xee,0x0b,0x3e = vshllt.s8 q1, q5, #8
0xaf,0xee,0x40,0x0f = vshllb.s8 q0, q0, #7
0x31,0xfe,0x03,0x2e = vshllb.u8 q1, q1, #8
0x31,0xfe,0x01,0x1e = vshllt.u8 q0, q0, #8
0xab,0xfe,0x40,0x0f = vshllb.u8 q0, q0, #3
0x35,0xfe,0x0b,0x0e = vshllb.u16 q0, q5, #0x10
0x35,0xfe,0x07,0x1e = vshllt.u16 q0, q3, #0x10
0x35,0xee,0x01,0x1e = vshllt.s16 q0, q0, #0x10
0xbe,0xee,0x40,0x1f = vshllt.s16 q0, q0, #0xe
0xbb,0xee,0x40,0x1f = vshllt.s16 q0, q0, #0xb
0xb4,0xfe,0x44,0x0f = vshllb.u16 q0, q2, #4
0x8f,0xfe,0xc7,0x0f = vrshrnb.i16 q0, q3, #1
0x8b,0xfe,0xc5,0x1f = vrshrnt.i16 q0, q2, #5
0x98,0xfe,0xc9,0x0f = vrshrnb.i32 q0, q4, #8
0x99,0xfe,0xc5,0x1f = vrshrnt.i32 q0, q2, #7
0x8f,0xee,0xc5,0x2f = vshrnb.i16 q1, q2, #1
0x8f,0xee,0xc3,0x1f = vshrnt.i16 q0, q1, #1
0x94,0xee,0xc1,0x0f = vshrnb.i32 q0, q0, #0xc
0x9c,0xee,0xc5,0x1f = vshrnt.i32 q0, q2, #4
0x88,0xfe,0xc4,0x0f = vqrshrunb.s16 q0, q2, #8
0x8a,0xfe,0xc0,0x1f = vqrshrunt.s16 q0, q0, #6
0x98,0xfe,0xc2,0x1f = vqrshrunt.s32 q0, q1, #8
0x93,0xfe,0xce,0x0f = vqrshrunb.s32 q0, q7, #0xd
0x8b,0xee,0xce,0x0f = vqshrunb.s16 q0, q7, #5
0x89,0xee,0xc2,0x1f = vqshrunt.s16 q0, q1, #7
0x9c,0xee,0xcc,0x0f = vqshrunb.s32 q0, q6, #4
0x96,0xee,0xc4,0x1f = vqshrunt.s32 q0, q2, #0xa
0x88,0xee,0x4f,0x0f = vqrshrnb.s16 q0, q7, #8
0x8c,0xfe,0x47,0x3f = vqrshrnt.u16 q1, q3, #4
0x99,0xfe,0x43,0x0f = vqrshrnb.u32 q0, q1, #7
0x95,0xee,0x43,0x1f = vqrshrnt.s32 q0, q1, #0xb
0x8b,0xee,0x4c,0x0f = vqshrnb.s16 q0, q6, #5
0x8c,0xee,0x42,0x1f = vqshrnt.s16 q0, q1, #4
0x89,0xfe,0x46,0x0f = vqshrnb.u16 q0, q3, #7
0x88,0xfe,0x44,0x1f = vqshrnt.u16 q0, q2, #8
0x9d,0xee,0x48,0x3f = vqshrnt.s32 q1, q4, #3
0x92,0xfe,0x44,0x0f = vqshrnb.u32 q0, q2, #0xe
0x0c,0xef,0x4c,0xc4 = vshl.s8 q6, q6, q6
0x14,0xef,0x48,0x04 = vshl.s16 q0, q4, q2
0x2a,0xef,0x42,0x24 = vshl.s32 q1, q1, q5
0x04,0xff,0x4e,0x24 = vshl.u8 q1, q7, q2
0x10,0xff,0x48,0x04 = vshl.u16 q0, q4, q0
0x28,0xff,0x44,0x44 = vshl.u32 q2, q2, q4
0x0c,0xef,0x52,0x04 = vqshl.s8 q0, q1, q6
0x1e,0xef,0x56,0x84 = vqshl.s16 q4, q3, q7
0x2a,0xef,0x5a,0x04 = vqshl.s32 q0, q5, q5
0x0c,0xff,0x50,0x04 = vqshl.u8 q0, q0, q6
0x18,0xff,0x5a,0x04 = vqshl.u16 q0, q5, q4
0x28,0xff,0x50,0x24 = vqshl.u32 q1, q0, q4
0x02,0xef,0x5c,0x25 = vqrshl.s8 q1, q6, q1
0x1c,0xef,0x58,0x45 = vqrshl.s16 q2, q4, q6
0x2a,0xef,0x50,0x05 = vqrshl.s32 q0, q0, q5
0x02,0xff,0x54,0x05 = vqrshl.u8 q0, q2, q1
0x10,0xff,0x5c,0x25 = vqrshl.u16 q1, q6, q0
0x20,0xff,0x50,0x05 = vqrshl.u32 q0, q0, q0
0x08,0xef,0x4c,0x05 = vrshl.s8 q0, q6, q4
0x1e,0xef,0x48,0x25 = vrshl.s16 q1, q4, q7
0x28,0xef,0x48,0x25 = vrshl.s32 q1, q4, q4
0x0a,0xff,0x46,0x05 = vrshl.u8 q0, q3, q5
0x1a,0xff,0x4c,0xa5 = vrshl.u16 q5, q6, q5
0x26,0xff,0x4e,0x25 = vrshl.u32 q1, q7, q3
0x8d,0xff,0x54,0x04 = vsri.8 q0, q2, #3
0x9b,0xff,0x54,0x04 = vsri.16 q0, q2, #5
0xb1,0xff,0x52,0x04 = vsri.32 q0, q1, #0xf
0x8b,0xff,0x56,0x05 = vsli.8 q0, q3, #3
0x9c,0xff,0x52,0x05 = vsli.16 q0, q1, #0xc
0xa8,0xff,0x52,0x05 = vsli.32 q0, q1, #8
0x8e,0xef,0x58,0x07 = vqshl.s8 q0, q4, #6
0x8e,0xff,0x5c,0x07 = vqshl.u8 q0, q6, #6
0x95,0xef,0x54,0x27 = vqshl.s16 q1, q2, #5
0x93,0xff,0x5a,0x07 = vqshl.u16 q0, q5, #3
0xbd,0xef,0x56,0x27 = vqshl.s32 q1, q3, #0x1d
0xb3,0xff,0x54,0x07 = vqshl.u32 q0, q2, #0x13
0x88,0xff,0x52,0x06 = vqshlu.s8 q0, q1, #0
0x9c,0xff,0x52,0x46 = vqshlu.s16 q2, q1, #0xc
0xba,0xff,0x58,0x06 = vqshlu.s32 q0, q4, #0x1a
0x89,0xef,0x56,0x22 = vrshr.s8 q1, q3, #7
0x8e,0xff,0x56,0x22 = vrshr.u8 q1, q3, #2
0x96,0xef,0x52,0x02 = vrshr.s16 q0, q1, #0xa
0x94,0xff,0x5a,0x02 = vrshr.u16 q0, q5, #0xc
0xa9,0xef,0x5a,0x02 = vrshr.s32 q0, q5, #0x17
0xa2,0xff,0x52,0x02 = vrshr.u32 q0, q1, #0x1e
0x8c,0xef,0x5e,0x00 = vshr.s8 q0, q7, #4
0x8b,0xff,0x54,0x00 = vshr.u8 q0, q2, #5
0x90,0xef,0x56,0x00 = vshr.s16 q0, q3, #0x10
0x98,0xff,0x5c,0xe0 = vshr.u16 q7, q6, #8
0xa8,0xef,0x5c,0x00 = vshr.s32 q0, q6, #0x18
0xa2,0xff,0x5a,0x40 = vshr.u32 q2, q5, #0x1e
0x8e,0xef,0x5c,0x05 = vshl.i8 q0, q6, #6
0x9c,0xef,0x50,0x25 = vshl.i16 q1, q0, #0xc
0xba,0xef,0x54,0x45 = vshl.i32 q2, q2, #0x1a
0xa9,0xee,0x42,0x1f = vshllt.s8 q0, q1, #1
0x71,0xfe,0x4d,0x8f = vpste
0xb4,0xee,0x42,0x1f = vshlltt.s16 q0, q1, #4
0xb8,0xfe,0x42,0x0f = vshllbe.u16 q0, q1, #8
