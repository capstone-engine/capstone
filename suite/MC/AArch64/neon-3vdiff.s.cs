# CS_ARCH_AARCH64, 0, None
0x20,0x00,0x22,0x0e = saddl	v0.8h, v1.8b, v2.8b
0x20,0x00,0x62,0x0e = saddl	v0.4s, v1.4h, v2.4h
0x20,0x00,0xa2,0x0e = saddl	v0.2d, v1.2s, v2.2s
0x20,0x00,0x62,0x4e = saddl2	v0.4s, v1.8h, v2.8h
0x20,0x00,0x22,0x4e = saddl2	v0.8h, v1.16b, v2.16b
0x20,0x00,0xa2,0x4e = saddl2	v0.2d, v1.4s, v2.4s
0x20,0x00,0x22,0x2e = uaddl	v0.8h, v1.8b, v2.8b
0x20,0x00,0x62,0x2e = uaddl	v0.4s, v1.4h, v2.4h
0x20,0x00,0xa2,0x2e = uaddl	v0.2d, v1.2s, v2.2s
0x20,0x00,0x22,0x6e = uaddl2	v0.8h, v1.16b, v2.16b
0x20,0x00,0x62,0x6e = uaddl2	v0.4s, v1.8h, v2.8h
0x20,0x00,0xa2,0x6e = uaddl2	v0.2d, v1.4s, v2.4s
0x20,0x20,0x22,0x0e = ssubl	v0.8h, v1.8b, v2.8b
0x20,0x20,0x62,0x0e = ssubl	v0.4s, v1.4h, v2.4h
0x20,0x20,0xa2,0x0e = ssubl	v0.2d, v1.2s, v2.2s
0x20,0x20,0x22,0x4e = ssubl2	v0.8h, v1.16b, v2.16b
0x20,0x20,0x62,0x4e = ssubl2	v0.4s, v1.8h, v2.8h
0x20,0x20,0xa2,0x4e = ssubl2	v0.2d, v1.4s, v2.4s
0x20,0x20,0x22,0x2e = usubl	v0.8h, v1.8b, v2.8b
0x20,0x20,0x62,0x2e = usubl	v0.4s, v1.4h, v2.4h
0x20,0x20,0xa2,0x2e = usubl	v0.2d, v1.2s, v2.2s
0x20,0x20,0x22,0x6e = usubl2	v0.8h, v1.16b, v2.16b
0x20,0x20,0x62,0x6e = usubl2	v0.4s, v1.8h, v2.8h
0x20,0x20,0xa2,0x6e = usubl2	v0.2d, v1.4s, v2.4s
0x20,0x50,0x22,0x0e = sabal	v0.8h, v1.8b, v2.8b
0x20,0x50,0x62,0x0e = sabal	v0.4s, v1.4h, v2.4h
0x20,0x50,0xa2,0x0e = sabal	v0.2d, v1.2s, v2.2s
0x20,0x50,0x22,0x4e = sabal2	v0.8h, v1.16b, v2.16b
0x20,0x50,0x62,0x4e = sabal2	v0.4s, v1.8h, v2.8h
0x20,0x50,0xa2,0x4e = sabal2	v0.2d, v1.4s, v2.4s
0x20,0x50,0x22,0x2e = uabal	v0.8h, v1.8b, v2.8b
0x20,0x50,0x62,0x2e = uabal	v0.4s, v1.4h, v2.4h
0x20,0x50,0xa2,0x2e = uabal	v0.2d, v1.2s, v2.2s
0x20,0x50,0x22,0x6e = uabal2	v0.8h, v1.16b, v2.16b
0x20,0x50,0x62,0x6e = uabal2	v0.4s, v1.8h, v2.8h
0x20,0x50,0xa2,0x6e = uabal2	v0.2d, v1.4s, v2.4s
0x20,0x70,0x22,0x0e = sabdl	v0.8h, v1.8b, v2.8b
0x20,0x70,0x62,0x0e = sabdl	v0.4s, v1.4h, v2.4h
0x20,0x70,0xa2,0x0e = sabdl	v0.2d, v1.2s, v2.2s
0x20,0x70,0x22,0x4e = sabdl2	v0.8h, v1.16b, v2.16b
0x20,0x70,0x62,0x4e = sabdl2	v0.4s, v1.8h, v2.8h
0x20,0x70,0xa2,0x4e = sabdl2	v0.2d, v1.4s, v2.4s
0x20,0x70,0x22,0x2e = uabdl	v0.8h, v1.8b, v2.8b
0x20,0x70,0x62,0x2e = uabdl	v0.4s, v1.4h, v2.4h
0x20,0x70,0xa2,0x2e = uabdl	v0.2d, v1.2s, v2.2s
0x20,0x70,0x22,0x6e = uabdl2	v0.8h, v1.16b, v2.16b
0x20,0x70,0x62,0x6e = uabdl2	v0.4s, v1.8h, v2.8h
0x20,0x70,0xa2,0x6e = uabdl2	v0.2d, v1.4s, v2.4s
0x20,0x80,0x22,0x0e = smlal	v0.8h, v1.8b, v2.8b
0x20,0x80,0x62,0x0e = smlal	v0.4s, v1.4h, v2.4h
0x20,0x80,0xa2,0x0e = smlal	v0.2d, v1.2s, v2.2s
0x20,0x80,0x22,0x4e = smlal2	v0.8h, v1.16b, v2.16b
0x20,0x80,0x62,0x4e = smlal2	v0.4s, v1.8h, v2.8h
0x20,0x80,0xa2,0x4e = smlal2	v0.2d, v1.4s, v2.4s
0x20,0x80,0x22,0x2e = umlal	v0.8h, v1.8b, v2.8b
0x20,0x80,0x62,0x2e = umlal	v0.4s, v1.4h, v2.4h
0x20,0x80,0xa2,0x2e = umlal	v0.2d, v1.2s, v2.2s
0x20,0x80,0x22,0x6e = umlal2	v0.8h, v1.16b, v2.16b
0x20,0x80,0x62,0x6e = umlal2	v0.4s, v1.8h, v2.8h
0x20,0x80,0xa2,0x6e = umlal2	v0.2d, v1.4s, v2.4s
0x20,0xa0,0x22,0x0e = smlsl	v0.8h, v1.8b, v2.8b
0x20,0xa0,0x62,0x0e = smlsl	v0.4s, v1.4h, v2.4h
0x20,0xa0,0xa2,0x0e = smlsl	v0.2d, v1.2s, v2.2s
0x20,0xa0,0x22,0x4e = smlsl2	v0.8h, v1.16b, v2.16b
0x20,0xa0,0x62,0x4e = smlsl2	v0.4s, v1.8h, v2.8h
0x20,0xa0,0xa2,0x4e = smlsl2	v0.2d, v1.4s, v2.4s
0x20,0xa0,0x22,0x2e = umlsl	v0.8h, v1.8b, v2.8b
0x20,0xa0,0x62,0x2e = umlsl	v0.4s, v1.4h, v2.4h
0x20,0xa0,0xa2,0x2e = umlsl	v0.2d, v1.2s, v2.2s
0x20,0xa0,0x22,0x6e = umlsl2	v0.8h, v1.16b, v2.16b
0x20,0xa0,0x62,0x6e = umlsl2	v0.4s, v1.8h, v2.8h
0x20,0xa0,0xa2,0x6e = umlsl2	v0.2d, v1.4s, v2.4s
0x20,0xc0,0x22,0x0e = smull	v0.8h, v1.8b, v2.8b
0x20,0xc0,0x62,0x0e = smull	v0.4s, v1.4h, v2.4h
0x20,0xc0,0xa2,0x0e = smull	v0.2d, v1.2s, v2.2s
0x20,0xc0,0x22,0x4e = smull2	v0.8h, v1.16b, v2.16b
0x20,0xc0,0x62,0x4e = smull2	v0.4s, v1.8h, v2.8h
0x20,0xc0,0xa2,0x4e = smull2	v0.2d, v1.4s, v2.4s
0x20,0xc0,0x22,0x2e = umull	v0.8h, v1.8b, v2.8b
0x20,0xc0,0x62,0x2e = umull	v0.4s, v1.4h, v2.4h
0x20,0xc0,0xa2,0x2e = umull	v0.2d, v1.2s, v2.2s
0x20,0xc0,0x22,0x6e = umull2	v0.8h, v1.16b, v2.16b
0x20,0xc0,0x62,0x6e = umull2	v0.4s, v1.8h, v2.8h
0x20,0xc0,0xa2,0x6e = umull2	v0.2d, v1.4s, v2.4s
0x20,0x90,0x62,0x0e = sqdmlal	v0.4s, v1.4h, v2.4h
0x20,0x90,0xa2,0x0e = sqdmlal	v0.2d, v1.2s, v2.2s
0x20,0x90,0x62,0x4e = sqdmlal2	v0.4s, v1.8h, v2.8h
0x20,0x90,0xa2,0x4e = sqdmlal2	v0.2d, v1.4s, v2.4s
0x20,0xb0,0x62,0x0e = sqdmlsl	v0.4s, v1.4h, v2.4h
0x20,0xb0,0xa2,0x0e = sqdmlsl	v0.2d, v1.2s, v2.2s
0x20,0xb0,0x62,0x4e = sqdmlsl2	v0.4s, v1.8h, v2.8h
0x20,0xb0,0xa2,0x4e = sqdmlsl2	v0.2d, v1.4s, v2.4s
0x20,0xd0,0x62,0x0e = sqdmull	v0.4s, v1.4h, v2.4h
0x20,0xd0,0xa2,0x0e = sqdmull	v0.2d, v1.2s, v2.2s
0x20,0xd0,0x62,0x4e = sqdmull2	v0.4s, v1.8h, v2.8h
0x20,0xd0,0xa2,0x4e = sqdmull2	v0.2d, v1.4s, v2.4s
0x20,0xe0,0x22,0x0e = pmull	v0.8h, v1.8b, v2.8b
0x20,0xe0,0xe2,0x0e = pmull	v0.1q, v1.1d, v2.1d
0x20,0xe0,0x22,0x4e = pmull2	v0.8h, v1.16b, v2.16b
0x20,0xe0,0xe2,0x4e = pmull2	v0.1q, v1.2d, v2.2d
0x20,0x10,0x22,0x0e = saddw	v0.8h, v1.8h, v2.8b
0x20,0x10,0x62,0x0e = saddw	v0.4s, v1.4s, v2.4h
0x20,0x10,0xa2,0x0e = saddw	v0.2d, v1.2d, v2.2s
0x20,0x10,0x22,0x4e = saddw2	v0.8h, v1.8h, v2.16b
0x20,0x10,0x62,0x4e = saddw2	v0.4s, v1.4s, v2.8h
0x20,0x10,0xa2,0x4e = saddw2	v0.2d, v1.2d, v2.4s
0x20,0x10,0x22,0x2e = uaddw	v0.8h, v1.8h, v2.8b
0x20,0x10,0x62,0x2e = uaddw	v0.4s, v1.4s, v2.4h
0x20,0x10,0xa2,0x2e = uaddw	v0.2d, v1.2d, v2.2s
0x20,0x10,0x22,0x6e = uaddw2	v0.8h, v1.8h, v2.16b
0x20,0x10,0x62,0x6e = uaddw2	v0.4s, v1.4s, v2.8h
0x20,0x10,0xa2,0x6e = uaddw2	v0.2d, v1.2d, v2.4s
0x20,0x30,0x22,0x0e = ssubw	v0.8h, v1.8h, v2.8b
0x20,0x30,0x62,0x0e = ssubw	v0.4s, v1.4s, v2.4h
0x20,0x30,0xa2,0x0e = ssubw	v0.2d, v1.2d, v2.2s
0x20,0x30,0x22,0x4e = ssubw2	v0.8h, v1.8h, v2.16b
0x20,0x30,0x62,0x4e = ssubw2	v0.4s, v1.4s, v2.8h
0x20,0x30,0xa2,0x4e = ssubw2	v0.2d, v1.2d, v2.4s
0x20,0x30,0x22,0x2e = usubw	v0.8h, v1.8h, v2.8b
0x20,0x30,0x62,0x2e = usubw	v0.4s, v1.4s, v2.4h
0x20,0x30,0xa2,0x2e = usubw	v0.2d, v1.2d, v2.2s
0x20,0x30,0x22,0x6e = usubw2	v0.8h, v1.8h, v2.16b
0x20,0x30,0x62,0x6e = usubw2	v0.4s, v1.4s, v2.8h
0x20,0x30,0xa2,0x6e = usubw2	v0.2d, v1.2d, v2.4s
0x20,0x40,0x22,0x0e = addhn	v0.8b, v1.8h, v2.8h
0x20,0x40,0x62,0x0e = addhn	v0.4h, v1.4s, v2.4s
0x20,0x40,0xa2,0x0e = addhn	v0.2s, v1.2d, v2.2d
0x20,0x40,0x22,0x4e = addhn2	v0.16b, v1.8h, v2.8h
0x20,0x40,0x62,0x4e = addhn2	v0.8h, v1.4s, v2.4s
0x20,0x40,0xa2,0x4e = addhn2	v0.4s, v1.2d, v2.2d
0x20,0x40,0x22,0x2e = raddhn	v0.8b, v1.8h, v2.8h
0x20,0x40,0x62,0x2e = raddhn	v0.4h, v1.4s, v2.4s
0x20,0x40,0xa2,0x2e = raddhn	v0.2s, v1.2d, v2.2d
0x20,0x40,0x22,0x6e = raddhn2	v0.16b, v1.8h, v2.8h
0x20,0x40,0x62,0x6e = raddhn2	v0.8h, v1.4s, v2.4s
0x20,0x40,0xa2,0x6e = raddhn2	v0.4s, v1.2d, v2.2d
0x20,0x60,0x22,0x2e = rsubhn	v0.8b, v1.8h, v2.8h
0x20,0x60,0x62,0x2e = rsubhn	v0.4h, v1.4s, v2.4s
0x20,0x60,0xa2,0x2e = rsubhn	v0.2s, v1.2d, v2.2d
0x20,0x60,0x22,0x6e = rsubhn2	v0.16b, v1.8h, v2.8h
0x20,0x60,0x62,0x6e = rsubhn2	v0.8h, v1.4s, v2.4s
0x20,0x60,0xa2,0x6e = rsubhn2	v0.4s, v1.2d, v2.2d
