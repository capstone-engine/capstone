# CS_ARCH_AARCH64, 0, None

0x20,0x9c,0x22,0x0e == mul v0.8b, v1.8b, v2.8b
0x20,0x9c,0x22,0x4e == mul v0.16b, v1.16b, v2.16b
0x20,0x9c,0x62,0x0e == mul v0.4h, v1.4h, v2.4h
0x20,0x9c,0x62,0x4e == mul v0.8h, v1.8h, v2.8h
0x20,0x9c,0xa2,0x0e == mul v0.2s, v1.2s, v2.2s
0x20,0x9c,0xa2,0x4e == mul v0.4s, v1.4s, v2.4s
0x20,0xdc,0x22,0x2e == fmul v0.2s, v1.2s, v2.2s
0x20,0xdc,0x22,0x6e == fmul v0.4s, v1.4s, v2.4s
0x20,0xdc,0x62,0x6e == fmul v0.2d, v1.2d, v2.2d
0x20,0xfc,0x22,0x2e == fdiv v0.2s, v1.2s, v2.2s
0x20,0xfc,0x22,0x6e == fdiv v0.4s, v1.4s, v2.4s
0x20,0xfc,0x62,0x6e == fdiv v0.2d, v1.2d, v2.2d
0xf1,0x9f,0x30,0x2e == pmul v17.8b, v31.8b, v16.8b
0x20,0x9c,0x22,0x6e == pmul v0.16b, v1.16b, v2.16b
0x22,0xb7,0x63,0x0e == sqdmulh v2.4h, v25.4h, v3.4h
0xac,0xb4,0x6d,0x4e == sqdmulh v12.8h, v5.8h, v13.8h
0x23,0xb4,0xbe,0x0e == sqdmulh v3.2s, v1.2s, v30.2s
0x22,0xb7,0x63,0x2e == sqrdmulh v2.4h, v25.4h, v3.4h
0xac,0xb4,0x6d,0x6e == sqrdmulh v12.8h, v5.8h, v13.8h
0x23,0xb4,0xbe,0x2e == sqrdmulh v3.2s, v1.2s, v30.2s
0xb5,0xdc,0x2d,0x0e == fmulx v21.2s, v5.2s, v13.2s
0x21,0xdf,0x23,0x4e == fmulx v1.4s, v25.4s, v3.4s
0xdf,0xde,0x62,0x4e == fmulx v31.2d, v22.2d, v2.2d
