# CS_ARCH_ARM, CS_MODE_ARM, None
0x00,0x2a,0xb0,0xee = vmov.f32 s4, #2.000000e+00
0x00,0x2a,0xb7,0xee = vmov.f32 s4, #1.000000e+00
0x00,0x3b,0xb0,0xee = vmov.f64 d3, #2.000000e+00
0x00,0x3b,0xb7,0xee = vmov.f64 d3, #1.000000e+00
0x01,0x2a,0xf0,0x1e = vmovne.f32 s5, #2.125000e+00
0x00,0x2a,0xf2,0xce = vmovgt.f32 s5, #8.000000e+00
0x03,0x2b,0xb0,0xbe = vmovlt.f64 d2, #2.375000e+00
0x00,0x2b,0xb4,0xae = vmovge.f64 d2, #1.250000e-01
