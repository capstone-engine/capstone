# CS_ARCH_ARM64, 0, None
0x20,0x64,0x22,0x0e = smax v0.8b, v1.8b, v2.8b
0x20,0x64,0x22,0x4e = smax v0.16b, v1.16b, v2.16b
0x20,0x64,0x62,0x0e = smax v0.4h, v1.4h, v2.4h
0x20,0x64,0x62,0x4e = smax v0.8h, v1.8h, v2.8h
0x20,0x64,0xa2,0x0e = smax v0.2s, v1.2s, v2.2s
0x20,0x64,0xa2,0x4e = smax v0.4s, v1.4s, v2.4s
0x20,0x64,0x22,0x2e = umax v0.8b, v1.8b, v2.8b
0x20,0x64,0x22,0x6e = umax v0.16b, v1.16b, v2.16b
0x20,0x64,0x62,0x2e = umax v0.4h, v1.4h, v2.4h
0x20,0x64,0x62,0x6e = umax v0.8h, v1.8h, v2.8h
0x20,0x64,0xa2,0x2e = umax v0.2s, v1.2s, v2.2s
0x20,0x64,0xa2,0x6e = umax v0.4s, v1.4s, v2.4s
0x20,0x6c,0x22,0x0e = smin v0.8b, v1.8b, v2.8b
0x20,0x6c,0x22,0x4e = smin v0.16b, v1.16b, v2.16b
0x20,0x6c,0x62,0x0e = smin v0.4h, v1.4h, v2.4h
0x20,0x6c,0x62,0x4e = smin v0.8h, v1.8h, v2.8h
0x20,0x6c,0xa2,0x0e = smin v0.2s, v1.2s, v2.2s
0x20,0x6c,0xa2,0x4e = smin v0.4s, v1.4s, v2.4s
0x20,0x6c,0x22,0x2e = umin v0.8b, v1.8b, v2.8b
0x20,0x6c,0x22,0x6e = umin v0.16b, v1.16b, v2.16b
0x20,0x6c,0x62,0x2e = umin v0.4h, v1.4h, v2.4h
0x20,0x6c,0x62,0x6e = umin v0.8h, v1.8h, v2.8h
0x20,0x6c,0xa2,0x2e = umin v0.2s, v1.2s, v2.2s
0x20,0x6c,0xa2,0x6e = umin v0.4s, v1.4s, v2.4s
0x20,0x34,0x42,0x0e = fmax v0.4h, v1.4h, v2.4h
0x20,0x34,0x42,0x4e = fmax v0.8h, v1.8h, v2.8h
0x20,0xf4,0x22,0x0e = fmax v0.2s, v1.2s, v2.2s
0xff,0xf5,0x30,0x4e = fmax v31.4s, v15.4s, v16.4s
0x07,0xf5,0x79,0x4e = fmax v7.2d, v8.2d, v25.2d
0xea,0x35,0xd6,0x0e = fmin v10.4h, v15.4h, v22.4h
0xea,0x35,0xd6,0x4e = fmin v10.8h, v15.8h, v22.8h
0xea,0xf5,0xb6,0x0e = fmin v10.2s, v15.2s, v22.2s
0xa3,0xf4,0xa6,0x4e = fmin v3.4s, v5.4s, v6.4s
0xb1,0xf5,0xe2,0x4e = fmin v17.2d, v13.2d, v2.2d
0x20,0x04,0x42,0x0e = fmaxnm v0.4h, v1.4h, v2.4h
0x20,0x04,0x42,0x4e = fmaxnm v0.8h, v1.8h, v2.8h
0x20,0xc4,0x22,0x0e = fmaxnm v0.2s, v1.2s, v2.2s
0xff,0xc5,0x30,0x4e = fmaxnm v31.4s, v15.4s, v16.4s
0x07,0xc5,0x79,0x4e = fmaxnm v7.2d, v8.2d, v25.2d
0xea,0x05,0xd6,0x0e = fminnm v10.4h, v15.4h, v22.4h
0xea,0x05,0xd6,0x4e = fminnm v10.8h, v15.8h, v22.8h
0xea,0xc5,0xb6,0x0e = fminnm v10.2s, v15.2s, v22.2s
0xa3,0xc4,0xa6,0x4e = fminnm v3.4s, v5.4s, v6.4s
0xb1,0xc5,0xe2,0x4e = fminnm v17.2d, v13.2d, v2.2d
