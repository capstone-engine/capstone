# CS_ARCH_AARCH64, 0, None
0x41,0x00,0x03,0x1a = adc	w1, w2, w3
0x41,0x00,0x03,0x9a = adc	x1, x2, x3
0x85,0x00,0x03,0x3a = adcs	w5, w4, w3
0x85,0x00,0x03,0xba = adcs	x5, x4, x3
0x41,0x00,0x03,0x5a = sbc	w1, w2, w3
0x41,0x00,0x03,0xda = sbc	x1, x2, x3
0x41,0x00,0x03,0x7a = sbcs	w1, w2, w3
0x41,0x00,0x03,0xfa = sbcs	x1, x2, x3
0x83,0x00,0x10,0x11 = add	w3, w4, #1024
0x83,0x00,0x10,0x11 = add	w3, w4, #1024
0x83,0x00,0x10,0x91 = add	x3, x4, #1024
0x83,0x00,0x10,0x91 = add	x3, x4, #1024
0x83,0x00,0x50,0x11 = add	w3, w4, #1024, lsl #12
0x83,0x00,0x50,0x11 = add	w3, w4, #1024, lsl #12
0x83,0x00,0x40,0x11 = add	w3, w4, #0, lsl #12
0x83,0x00,0x50,0x91 = add	x3, x4, #1024, lsl #12
0x83,0x00,0x50,0x91 = add	x3, x4, #1024, lsl #12
0x83,0x00,0x40,0x91 = add	x3, x4, #0, lsl #12
0xff,0x83,0x00,0x91 = add	sp, sp, #32
0x83,0x00,0x10,0x31 = adds	w3, w4, #1024
0x83,0x00,0x10,0x31 = adds	w3, w4, #1024
0x83,0x00,0x50,0x31 = adds	w3, w4, #1024, lsl #12
0x83,0x00,0x10,0xb1 = adds	x3, x4, #1024
0x83,0x00,0x10,0xb1 = adds	x3, x4, #1024
0x83,0x00,0x50,0xb1 = adds	x3, x4, #1024, lsl #12
0x83,0x00,0x10,0x51 = sub	w3, w4, #1024
0x83,0x00,0x10,0x51 = sub	w3, w4, #1024
0x83,0x00,0x50,0x51 = sub	w3, w4, #1024, lsl #12
0x83,0x00,0x10,0xd1 = sub	x3, x4, #1024
0x83,0x00,0x10,0xd1 = sub	x3, x4, #1024
0x83,0x00,0x50,0xd1 = sub	x3, x4, #1024, lsl #12
0xff,0x83,0x00,0xd1 = sub	sp, sp, #32
0x83,0x00,0x10,0x71 = subs	w3, w4, #1024
0x83,0x00,0x10,0x71 = subs	w3, w4, #1024
0x83,0x00,0x50,0x71 = subs	w3, w4, #1024, lsl #12
0x83,0x00,0x10,0xf1 = subs	x3, x4, #1024
0x83,0x00,0x10,0xf1 = subs	x3, x4, #1024
0x83,0x00,0x50,0xf1 = subs	x3, x4, #1024, lsl #12
0xac,0x01,0x0e,0x0b = add	w12, w13, w14
0xac,0x01,0x0e,0x8b = add	x12, x13, x14
0xac,0x31,0x0e,0x0b = add	w12, w13, w14, lsl #12
0xac,0x31,0x0e,0x8b = add	x12, x13, x14, lsl #12
0xac,0xa9,0x4e,0x8b = add	x12, x13, x14, lsr #42
0xac,0x9d,0x8e,0x8b = add	x12, x13, x14, asr #39
0xac,0x01,0x0e,0x4b = sub	w12, w13, w14
0xac,0x01,0x0e,0xcb = sub	x12, x13, x14
0xac,0x31,0x0e,0x4b = sub	w12, w13, w14, lsl #12
0xac,0x31,0x0e,0xcb = sub	x12, x13, x14, lsl #12
0xac,0xa9,0x4e,0xcb = sub	x12, x13, x14, lsr #42
0xac,0x9d,0x8e,0xcb = sub	x12, x13, x14, asr #39
0xac,0x01,0x0e,0x2b = adds	w12, w13, w14
0xac,0x01,0x0e,0xab = adds	x12, x13, x14
0xac,0x31,0x0e,0x2b = adds	w12, w13, w14, lsl #12
0xac,0x31,0x0e,0xab = adds	x12, x13, x14, lsl #12
0xac,0xa9,0x4e,0xab = adds	x12, x13, x14, lsr #42
0xac,0x9d,0x8e,0xab = adds	x12, x13, x14, asr #39
0xac,0x01,0x0e,0x6b = subs	w12, w13, w14
0xac,0x01,0x0e,0xeb = subs	x12, x13, x14
0xac,0x31,0x0e,0x6b = subs	w12, w13, w14, lsl #12
0xac,0x31,0x0e,0xeb = subs	x12, x13, x14, lsl #12
0xac,0xa9,0x4e,0xeb = subs	x12, x13, x14, lsr #42
0xac,0x9d,0x8e,0xeb = subs	x12, x13, x14, asr #39
0x42,0x00,0x02,0x8b = add	x2, x2, x2
0x41,0x00,0x23,0x0b = add	w1, w2, w3, uxtb
0x41,0x20,0x23,0x0b = add	w1, w2, w3, uxth
0x41,0x40,0x23,0x0b = add	w1, w2, w3, uxtw
0x41,0x60,0x23,0x0b = add	w1, w2, w3, uxtx
0x41,0x80,0x23,0x0b = add	w1, w2, w3, sxtb
0x41,0xa0,0x23,0x0b = add	w1, w2, w3, sxth
0x41,0xc0,0x23,0x0b = add	w1, w2, w3, sxtw
0x41,0xe0,0x23,0x0b = add	w1, w2, w3, sxtx
0x41,0x00,0x23,0x8b = add	x1, x2, w3, uxtb
0x41,0x20,0x23,0x8b = add	x1, x2, w3, uxth
0x41,0x40,0x23,0x8b = add	x1, x2, w3, uxtw
0x41,0x80,0x23,0x8b = add	x1, x2, w3, sxtb
0x41,0xa0,0x23,0x8b = add	x1, x2, w3, sxth
0x41,0xc0,0x23,0x8b = add	x1, x2, w3, sxtw
0xe1,0x43,0x23,0x0b = add	w1, wsp, w3
0xe1,0x43,0x23,0x0b = add	w1, wsp, w3
0xe2,0x47,0x23,0x0b = add	w2, wsp, w3, lsl #1
0x5f,0x60,0x23,0x8b = add	sp, x2, x3
0x5f,0x60,0x23,0x8b = add	sp, x2, x3
0x41,0x00,0x23,0x4b = sub	w1, w2, w3, uxtb
0x41,0x20,0x23,0x4b = sub	w1, w2, w3, uxth
0x41,0x40,0x23,0x4b = sub	w1, w2, w3, uxtw
0x41,0x60,0x23,0x4b = sub	w1, w2, w3, uxtx
0x41,0x80,0x23,0x4b = sub	w1, w2, w3, sxtb
0x41,0xa0,0x23,0x4b = sub	w1, w2, w3, sxth
0x41,0xc0,0x23,0x4b = sub	w1, w2, w3, sxtw
0x41,0xe0,0x23,0x4b = sub	w1, w2, w3, sxtx
0x41,0x00,0x23,0xcb = sub	x1, x2, w3, uxtb
0x41,0x20,0x23,0xcb = sub	x1, x2, w3, uxth
0x41,0x40,0x23,0xcb = sub	x1, x2, w3, uxtw
0x41,0x80,0x23,0xcb = sub	x1, x2, w3, sxtb
0x41,0xa0,0x23,0xcb = sub	x1, x2, w3, sxth
0x41,0xc0,0x23,0xcb = sub	x1, x2, w3, sxtw
0xe1,0x43,0x23,0x4b = sub	w1, wsp, w3
0xe1,0x43,0x23,0x4b = sub	w1, wsp, w3
0x5f,0x60,0x23,0xcb = sub	sp, x2, x3
0x5f,0x60,0x23,0xcb = sub	sp, x2, x3
0x7f,0x70,0x27,0xcb = sub	sp, x3, x7, lsl #4
0x41,0x00,0x23,0x2b = adds	w1, w2, w3, uxtb
0x41,0x20,0x23,0x2b = adds	w1, w2, w3, uxth
0x41,0x40,0x23,0x2b = adds	w1, w2, w3, uxtw
0x41,0x60,0x23,0x2b = adds	w1, w2, w3, uxtx
0x41,0x80,0x23,0x2b = adds	w1, w2, w3, sxtb
0x41,0xa0,0x23,0x2b = adds	w1, w2, w3, sxth
0x41,0xc0,0x23,0x2b = adds	w1, w2, w3, sxtw
0x41,0xe0,0x23,0x2b = adds	w1, w2, w3, sxtx
0x41,0x00,0x23,0xab = adds	x1, x2, w3, uxtb
0x41,0x20,0x23,0xab = adds	x1, x2, w3, uxth
0x41,0x40,0x23,0xab = adds	x1, x2, w3, uxtw
0x41,0x60,0x23,0xab = adds	x1, x2, x3, uxtx
0x41,0x80,0x23,0xab = adds	x1, x2, w3, sxtb
0x41,0xa0,0x23,0xab = adds	x1, x2, w3, sxth
0x41,0xc0,0x23,0xab = adds	x1, x2, w3, sxtw
0x41,0xe0,0x23,0xab = adds	x1, x2, x3, sxtx
0xe1,0x43,0x23,0x2b = adds	w1, wsp, w3
0xe1,0x43,0x23,0x2b = adds	w1, wsp, w3
0xff,0x53,0x23,0x2b = cmn	wsp, w3, lsl #4
0x41,0x00,0x23,0x6b = subs	w1, w2, w3, uxtb
0x41,0x20,0x23,0x6b = subs	w1, w2, w3, uxth
0x41,0x40,0x23,0x6b = subs	w1, w2, w3, uxtw
0x41,0x60,0x23,0x6b = subs	w1, w2, w3, uxtx
0x41,0x80,0x23,0x6b = subs	w1, w2, w3, sxtb
0x41,0xa0,0x23,0x6b = subs	w1, w2, w3, sxth
0x41,0xc0,0x23,0x6b = subs	w1, w2, w3, sxtw
0x41,0xe0,0x23,0x6b = subs	w1, w2, w3, sxtx
0x41,0x00,0x23,0xeb = subs	x1, x2, w3, uxtb
0x41,0x20,0x23,0xeb = subs	x1, x2, w3, uxth
0x41,0x40,0x23,0xeb = subs	x1, x2, w3, uxtw
0x41,0x60,0x23,0xeb = subs	x1, x2, x3, uxtx
0x41,0x80,0x23,0xeb = subs	x1, x2, w3, sxtb
0x41,0xa0,0x23,0xeb = subs	x1, x2, w3, sxth
0x41,0xc0,0x23,0xeb = subs	x1, x2, w3, sxtw
0x41,0xe0,0x23,0xeb = subs	x1, x2, x3, sxtx
0xe1,0x43,0x23,0x6b = subs	w1, wsp, w3
0xe1,0x43,0x23,0x6b = subs	w1, wsp, w3
0xff,0x43,0x29,0x6b = cmp	wsp, w9
0xe3,0x6b,0x29,0xeb = subs	x3, sp, x9, lsl #2
0xff,0x43,0x28,0x6b = cmp	wsp, w8
0xff,0x43,0x28,0x6b = cmp	wsp, w8
0xff,0x43,0x28,0xeb = cmp	sp, w8, uxtw
0xff,0x43,0x28,0xeb = cmp	sp, w8, uxtw
0x3f,0x41,0x28,0x4b = sub	wsp, w9, w8
0xe1,0x43,0x28,0x4b = sub	w1, wsp, w8
0xff,0x43,0x28,0x4b = sub	wsp, wsp, w8
0x3f,0x41,0x28,0xcb = sub	sp, x9, w8, uxtw
0xe1,0x43,0x28,0xcb = sub	x1, sp, w8, uxtw
0xff,0x43,0x28,0xcb = sub	sp, sp, w8, uxtw
0xe1,0x43,0x28,0x6b = subs	w1, wsp, w8
0xe1,0x43,0x28,0xeb = subs	x1, sp, w8, uxtw
0x41,0x0c,0xc3,0x1a = sdiv	w1, w2, w3
0x41,0x0c,0xc3,0x9a = sdiv	x1, x2, x3
0x41,0x08,0xc3,0x1a = udiv	w1, w2, w3
0x41,0x08,0xc3,0x9a = udiv	x1, x2, x3
0x41,0x28,0xc3,0x1a = asr	w1, w2, w3
0x41,0x28,0xc3,0x9a = asr	x1, x2, x3
0x41,0x28,0xc3,0x1a = asr	w1, w2, w3
0x41,0x28,0xc3,0x9a = asr	x1, x2, x3
0x41,0x20,0xc3,0x1a = lsl	w1, w2, w3
0x41,0x20,0xc3,0x9a = lsl	x1, x2, x3
0x41,0x20,0xc3,0x1a = lsl	w1, w2, w3
0x41,0x20,0xc3,0x9a = lsl	x1, x2, x3
0x41,0x24,0xc3,0x1a = lsr	w1, w2, w3
0x41,0x24,0xc3,0x9a = lsr	x1, x2, x3
0x41,0x24,0xc3,0x1a = lsr	w1, w2, w3
0x41,0x24,0xc3,0x9a = lsr	x1, x2, x3
0x41,0x2c,0xc3,0x1a = ror	w1, w2, w3
0x41,0x2c,0xc3,0x9a = ror	x1, x2, x3
0x41,0x2c,0xc3,0x1a = ror	w1, w2, w3
0x41,0x2c,0xc3,0x9a = ror	x1, x2, x3
0x41,0x14,0xc0,0x5a = cls	w1, w2
0x41,0x14,0xc0,0xda = cls	x1, x2
0x41,0x10,0xc0,0x5a = clz	w1, w2
0x41,0x10,0xc0,0xda = clz	x1, x2
0x41,0x00,0xc0,0x5a = rbit	w1, w2
0x41,0x00,0xc0,0xda = rbit	x1, x2
0x41,0x08,0xc0,0x5a = rev	w1, w2
0x41,0x0c,0xc0,0xda = rev	x1, x2
0x41,0x04,0xc0,0x5a = rev16	w1, w2
0x41,0x04,0xc0,0xda = rev16	x1, x2
0x41,0x08,0xc0,0xda = rev32	x1, x2
0x41,0x10,0x03,0x1b = madd	w1, w2, w3, w4
0x41,0x10,0x03,0x9b = madd	x1, x2, x3, x4
0x41,0x90,0x03,0x1b = msub	w1, w2, w3, w4
0x41,0x90,0x03,0x9b = msub	x1, x2, x3, x4
0x41,0x10,0x23,0x9b = smaddl	x1, w2, w3, x4
0x41,0x90,0x23,0x9b = smsubl	x1, w2, w3, x4
0x41,0x10,0xa3,0x9b = umaddl	x1, w2, w3, x4
0x41,0x90,0xa3,0x9b = umsubl	x1, w2, w3, x4
0x41,0x7c,0x43,0x9b = smulh	x1, x2, x3
0x41,0x7c,0xc3,0x9b = umulh	x1, x2, x3
0x20,0x00,0x80,0x52 = mov	w0, #1
0x20,0x00,0x80,0xd2 = mov	x0, #1
0x20,0x00,0xa0,0x52 = mov	w0, #65536
0x20,0x00,0xa0,0xd2 = mov	x0, #65536
0x40,0x00,0x80,0x12 = mov	w0, #-3
0x40,0x00,0x80,0x92 = mov	x0, #-3
0x40,0x00,0xa0,0x12 = mov	w0, #-131073
0x40,0x00,0xa0,0x92 = mov	x0, #-131073
0x20,0x00,0x80,0x72 = movk	w0, #1
0x20,0x00,0x80,0xf2 = movk	x0, #1
0x20,0x00,0xa0,0x72 = movk	w0, #1, lsl #16
0x20,0x00,0xa0,0xf2 = movk	x0, #1, lsl #16
0x23,0x08,0x42,0x3a = ccmn	w1, #2, #3, eq
0x23,0x08,0x42,0xba = ccmn	x1, #2, #3, eq
0x23,0x08,0x42,0x7a = ccmp	w1, #2, #3, eq
0x23,0x08,0x42,0xfa = ccmp	x1, #2, #3, eq
0x23,0x00,0x42,0x3a = ccmn	w1, w2, #3, eq
0x23,0x00,0x42,0xba = ccmn	x1, x2, #3, eq
0x23,0x00,0x42,0x7a = ccmp	w1, w2, #3, eq
0x23,0x00,0x42,0xfa = ccmp	x1, x2, #3, eq
0x41,0x00,0x83,0x1a = csel	w1, w2, w3, eq
0x41,0x00,0x83,0x9a = csel	x1, x2, x3, eq
0x41,0x04,0x83,0x1a = csinc	w1, w2, w3, eq
0x41,0x04,0x83,0x9a = csinc	x1, x2, x3, eq
0x41,0x00,0x83,0x5a = csinv	w1, w2, w3, eq
0x41,0x00,0x83,0xda = csinv	x1, x2, x3, eq
0x41,0x04,0x83,0x5a = csneg	w1, w2, w3, eq
0x41,0x04,0x83,0xda = csneg	x1, x2, x3, eq
0xf0,0x00,0x9b,0x1a = csel	w16, w7, w27, eq
0xcf,0x10,0x9a,0x1a = csel	w15, w6, w26, ne
0xae,0x20,0x99,0x1a = csel	w14, w5, w25, hs
0x8d,0x20,0x98,0x1a = csel	w13, w4, w24, hs
0x6c,0x30,0x97,0x1a = csel	w12, w3, w23, lo
0x4b,0x30,0x96,0x1a = csel	w11, w2, w22, lo
0x2a,0x40,0x95,0x1a = csel	w10, w1, w21, mi
0x29,0x51,0x81,0x9a = csel	x9, x9, x1, pl
0x08,0x61,0x82,0x9a = csel	x8, x8, x2, vs
0xe7,0x70,0x83,0x9a = csel	x7, x7, x3, vc
0xe6,0x80,0x84,0x9a = csel	x6, x7, x4, hi
0xc5,0x90,0x85,0x9a = csel	x5, x6, x5, ls
0xa4,0xa0,0x86,0x9a = csel	x4, x5, x6, ge
0x83,0xb0,0x87,0x9a = csel	x3, x4, x7, lt
0x62,0xc0,0x88,0x9a = csel	x2, x3, x8, gt
0x41,0xd0,0x89,0x9a = csel	x1, x2, x9, le
0x2a,0xe0,0x94,0x9a = csel	x10, x1, x20, al
0x44,0x48,0x21,0x7e = uqxtn	b4, h2
0x62,0x48,0x61,0x7e = uqxtn	h2, s3
0x49,0x48,0xa1,0x7e = uqxtn	s9, d2
