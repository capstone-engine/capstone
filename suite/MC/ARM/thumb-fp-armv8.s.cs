# CS_ARCH_ARM, CS_MODE_THUMB+CS_MODE_V8, None
0xb2,0xee,0xe0,0x3b = vcvtt.f64.f16 d3, s1
0xf3,0xee,0xcc,0x2b = vcvtt.f16.f64 s5, d12
0xb2,0xee,0x60,0x3b = vcvtb.f64.f16 d3, s1
0xb3,0xee,0x41,0x2b = vcvtb.f16.f64 s4, d1
0xbc,0xfe,0xe1,0x1a = vcvta.s32.f32 s2, s3
0xbc,0xfe,0xc3,0x1b = vcvta.s32.f64 s2, d3
0xbd,0xfe,0xeb,0x3a = vcvtn.s32.f32 s6, s23
0xbd,0xfe,0xe7,0x3b = vcvtn.s32.f64 s6, d23
0xbe,0xfe,0xc2,0x0a = vcvtp.s32.f32 s0, s4
0xbe,0xfe,0xc4,0x0b = vcvtp.s32.f64 s0, d4
0xff,0xfe,0xc4,0x8a = vcvtm.s32.f32 s17, s8
0xff,0xfe,0xc8,0x8b = vcvtm.s32.f64 s17, d8
0xbc,0xfe,0x61,0x1a = vcvta.u32.f32 s2, s3
0xbc,0xfe,0x43,0x1b = vcvta.u32.f64 s2, d3
0xbd,0xfe,0x6b,0x3a = vcvtn.u32.f32 s6, s23
0xbd,0xfe,0x67,0x3b = vcvtn.u32.f64 s6, d23
0xbe,0xfe,0x42,0x0a = vcvtp.u32.f32 s0, s4
0xbe,0xfe,0x44,0x0b = vcvtp.u32.f64 s0, d4
0xff,0xfe,0x44,0x8a = vcvtm.u32.f32 s17, s8
0xff,0xfe,0x48,0x8b = vcvtm.u32.f64 s17, d8
0x20,0xfe,0xab,0x2a = vselge.f32 s4, s1, s23
0x6f,0xfe,0xa7,0xeb = vselge.f64 d30, d31, d23
0x30,0xfe,0x80,0x0a = vselgt.f32 s0, s1, s0
0x3a,0xfe,0x24,0x5b = vselgt.f64 d5, d10, d20
0x0e,0xfe,0x2b,0xfa = vseleq.f32 s30, s28, s23
0x04,0xfe,0x08,0x2b = vseleq.f64 d2, d4, d8
0x58,0xfe,0x07,0xaa = vselvs.f32 s21, s16, s14
0x11,0xfe,0x2f,0x0b = vselvs.f64 d0, d1, d31
0xc6,0xfe,0x00,0x2a = vmaxnm.f32 s5, s12, s0
0x86,0xfe,0xae,0x5b = vmaxnm.f64 d5, d22, d30
0x80,0xfe,0x46,0x0a = vminnm.f32 s0, s0, s12
0x86,0xfe,0x49,0x4b = vminnm.f64 d4, d6, d9
0xf6,0xee,0xcc,0x1a = vrintz.f32 s3, s24
0xb6,0xee,0x64,0x0a = vrintr.f32 s0, s9
0xb8,0xfe,0x44,0x3b = vrinta.f64 d3, d4
0xb8,0xfe,0x60,0x6a = vrinta.f32 s12, s1
0xb9,0xfe,0x44,0x3b = vrintn.f64 d3, d4
0xb9,0xfe,0x60,0x6a = vrintn.f32 s12, s1
0xba,0xfe,0x44,0x3b = vrintp.f64 d3, d4
0xba,0xfe,0x60,0x6a = vrintp.f32 s12, s1
0xbb,0xfe,0x44,0x3b = vrintm.f64 d3, d4
0xbb,0xfe,0x60,0x6a = vrintm.f32 s12, s1
