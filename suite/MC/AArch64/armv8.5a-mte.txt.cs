# CS_ARCH_AARCH64, 0, None
0x20,0x10,0xdf,0x9a = irg	x0, x1
0x3f,0x10,0xdf,0x9a = irg	sp, x1
0xe0,0x13,0xdf,0x9a = irg	x0, sp
0x20,0x10,0xc2,0x9a = irg	x0, x1, x2
0x3f,0x10,0xc2,0x9a = irg	sp, x1, x2
0x20,0x10,0xdf,0x9a = irg	x0, x1
0x3f,0x10,0xdf,0x9a = irg	sp, x1
0xe0,0x13,0xdf,0x9a = irg	x0, sp
0x20,0x10,0xc2,0x9a = irg	x0, x1, x2
0x3f,0x10,0xc2,0x9a = irg	sp, x1, x2
0x20,0x04,0x80,0x91 = addg	x0, x1, #0, #1
0x5f,0x0c,0x82,0x91 = addg	sp, x2, #32, #3
0xe0,0x17,0x84,0x91 = addg	x0, sp, #64, #5
0x83,0x18,0xbf,0x91 = addg	x3, x4, #1008, #6
0xc5,0x3c,0x87,0x91 = addg	x5, x6, #112, #15
0x20,0x04,0x80,0xd1 = subg	x0, x1, #0, #1
0x5f,0x0c,0x82,0xd1 = subg	sp, x2, #32, #3
0xe0,0x17,0x84,0xd1 = subg	x0, sp, #64, #5
0x83,0x18,0xbf,0xd1 = subg	x3, x4, #1008, #6
0xc5,0x3c,0x87,0xd1 = subg	x5, x6, #112, #15
0x20,0x04,0x80,0x91 = addg	x0, x1, #0, #1
0x5f,0x0c,0x82,0x91 = addg	sp, x2, #32, #3
0xe0,0x17,0x84,0x91 = addg	x0, sp, #64, #5
0x83,0x18,0xbf,0x91 = addg	x3, x4, #1008, #6
0xc5,0x3c,0x87,0x91 = addg	x5, x6, #112, #15
0x20,0x04,0x80,0xd1 = subg	x0, x1, #0, #1
0x5f,0x0c,0x82,0xd1 = subg	sp, x2, #32, #3
0xe0,0x17,0x84,0xd1 = subg	x0, sp, #64, #5
0x83,0x18,0xbf,0xd1 = subg	x3, x4, #1008, #6
0xc5,0x3c,0x87,0xd1 = subg	x5, x6, #112, #15
0x20,0x14,0xc2,0x9a = gmi	x0, x1, x2
0xe3,0x17,0xc4,0x9a = gmi	x3, sp, x4
0x1f,0x14,0xde,0x9a = gmi	xzr, x0, x30
0x1e,0x14,0xdf,0x9a = gmi	x30, x0, xzr
0x20,0x14,0xc2,0x9a = gmi	x0, x1, x2
0xe3,0x17,0xc4,0x9a = gmi	x3, sp, x4
0x1f,0x14,0xde,0x9a = gmi	xzr, x0, x30
0x1e,0x14,0xdf,0x9a = gmi	x30, x0, xzr
0x20,0x00,0xc2,0x9a = subp	x0, x1, x2
0x20,0x00,0xc2,0xba = subps	x0, x1, x2
0xe0,0x03,0xdf,0x9a = subp	x0, sp, sp
0xe0,0x03,0xdf,0xba = subps	x0, sp, sp
0x1f,0x00,0xc1,0xba = subps	xzr, x0, x1
0xff,0x03,0xdf,0xba = subps	xzr, sp, sp
0x20,0x00,0xc2,0x9a = subp	x0, x1, x2
0x20,0x00,0xc2,0xba = subps	x0, x1, x2
0xe0,0x03,0xdf,0x9a = subp	x0, sp, sp
0xe0,0x03,0xdf,0xba = subps	x0, sp, sp
0x1f,0x00,0xc1,0xba = subps	xzr, x0, x1
0xff,0x03,0xdf,0xba = subps	xzr, sp, sp
0x20,0x08,0x30,0xd9 = stg	x0, [x1, #-4096]
0x41,0xf8,0x2f,0xd9 = stg	x1, [x2, #4080]
0xe2,0x1b,0x20,0xd9 = stg	x2, [sp, #16]
0x23,0x08,0x20,0xd9 = stg	x3, [x1]
0x3f,0x08,0x20,0xd9 = stg	sp, [x1]
0x20,0x08,0x30,0xd9 = stg	x0, [x1, #-4096]
0x41,0xf8,0x2f,0xd9 = stg	x1, [x2, #4080]
0xe2,0x1b,0x20,0xd9 = stg	x2, [sp, #16]
0x23,0x08,0x20,0xd9 = stg	x3, [x1]
0x3f,0x08,0x20,0xd9 = stg	sp, [x1]
0x20,0x08,0x70,0xd9 = stzg	x0, [x1, #-4096]
0x41,0xf8,0x6f,0xd9 = stzg	x1, [x2, #4080]
0xe2,0x1b,0x60,0xd9 = stzg	x2, [sp, #16]
0x23,0x08,0x60,0xd9 = stzg	x3, [x1]
0x3f,0x08,0x60,0xd9 = stzg	sp, [x1]
0x20,0x08,0x70,0xd9 = stzg	x0, [x1, #-4096]
0x41,0xf8,0x6f,0xd9 = stzg	x1, [x2, #4080]
0xe2,0x1b,0x60,0xd9 = stzg	x2, [sp, #16]
0x23,0x08,0x60,0xd9 = stzg	x3, [x1]
0x3f,0x08,0x60,0xd9 = stzg	sp, [x1]
0x20,0x0c,0x30,0xd9 = stg	x0, [x1, #-4096]!
0x41,0xfc,0x2f,0xd9 = stg	x1, [x2, #4080]!
0xe2,0x1f,0x20,0xd9 = stg	x2, [sp, #16]!
0xff,0x1f,0x20,0xd9 = stg	sp, [sp, #16]!
0x20,0x0c,0x30,0xd9 = stg	x0, [x1, #-4096]!
0x41,0xfc,0x2f,0xd9 = stg	x1, [x2, #4080]!
0xe2,0x1f,0x20,0xd9 = stg	x2, [sp, #16]!
0xff,0x1f,0x20,0xd9 = stg	sp, [sp, #16]!
0x20,0x0c,0x70,0xd9 = stzg	x0, [x1, #-4096]!
0x41,0xfc,0x6f,0xd9 = stzg	x1, [x2, #4080]!
0xe2,0x1f,0x60,0xd9 = stzg	x2, [sp, #16]!
0xff,0x1f,0x60,0xd9 = stzg	sp, [sp, #16]!
0x20,0x0c,0x70,0xd9 = stzg	x0, [x1, #-4096]!
0x41,0xfc,0x6f,0xd9 = stzg	x1, [x2, #4080]!
0xe2,0x1f,0x60,0xd9 = stzg	x2, [sp, #16]!
0xff,0x1f,0x60,0xd9 = stzg	sp, [sp, #16]!
0x20,0x04,0x30,0xd9 = stg	x0, [x1], #-4096
0x41,0xf4,0x2f,0xd9 = stg	x1, [x2], #4080
0xe2,0x17,0x20,0xd9 = stg	x2, [sp], #16
0xff,0x17,0x20,0xd9 = stg	sp, [sp], #16
0x20,0x04,0x30,0xd9 = stg	x0, [x1], #-4096
0x41,0xf4,0x2f,0xd9 = stg	x1, [x2], #4080
0xe2,0x17,0x20,0xd9 = stg	x2, [sp], #16
0xff,0x17,0x20,0xd9 = stg	sp, [sp], #16
0x20,0x04,0x70,0xd9 = stzg	x0, [x1], #-4096
0x41,0xf4,0x6f,0xd9 = stzg	x1, [x2], #4080
0xe2,0x17,0x60,0xd9 = stzg	x2, [sp], #16
0xff,0x17,0x60,0xd9 = stzg	sp, [sp], #16
0x20,0x04,0x70,0xd9 = stzg	x0, [x1], #-4096
0x41,0xf4,0x6f,0xd9 = stzg	x1, [x2], #4080
0xe2,0x17,0x60,0xd9 = stzg	x2, [sp], #16
0xff,0x17,0x60,0xd9 = stzg	sp, [sp], #16
0x20,0x08,0xb0,0xd9 = st2g	x0, [x1, #-4096]
0x41,0xf8,0xaf,0xd9 = st2g	x1, [x2, #4080]
0xe2,0x1b,0xa0,0xd9 = st2g	x2, [sp, #16]
0x23,0x08,0xa0,0xd9 = st2g	x3, [x1]
0x3f,0x08,0xa0,0xd9 = st2g	sp, [x1]
0x20,0x08,0xb0,0xd9 = st2g	x0, [x1, #-4096]
0x41,0xf8,0xaf,0xd9 = st2g	x1, [x2, #4080]
0xe2,0x1b,0xa0,0xd9 = st2g	x2, [sp, #16]
0x23,0x08,0xa0,0xd9 = st2g	x3, [x1]
0x3f,0x08,0xa0,0xd9 = st2g	sp, [x1]
0x20,0x08,0xf0,0xd9 = stz2g	x0, [x1, #-4096]
0x41,0xf8,0xef,0xd9 = stz2g	x1, [x2, #4080]
0xe2,0x1b,0xe0,0xd9 = stz2g	x2, [sp, #16]
0x23,0x08,0xe0,0xd9 = stz2g	x3, [x1]
0x3f,0x08,0xe0,0xd9 = stz2g	sp, [x1]
0x20,0x08,0xf0,0xd9 = stz2g	x0, [x1, #-4096]
0x41,0xf8,0xef,0xd9 = stz2g	x1, [x2, #4080]
0xe2,0x1b,0xe0,0xd9 = stz2g	x2, [sp, #16]
0x23,0x08,0xe0,0xd9 = stz2g	x3, [x1]
0x3f,0x08,0xe0,0xd9 = stz2g	sp, [x1]
0x20,0x0c,0xb0,0xd9 = st2g	x0, [x1, #-4096]!
0x41,0xfc,0xaf,0xd9 = st2g	x1, [x2, #4080]!
0xe2,0x1f,0xa0,0xd9 = st2g	x2, [sp, #16]!
0xff,0x1f,0xa0,0xd9 = st2g	sp, [sp, #16]!
0x20,0x0c,0xb0,0xd9 = st2g	x0, [x1, #-4096]!
0x41,0xfc,0xaf,0xd9 = st2g	x1, [x2, #4080]!
0xe2,0x1f,0xa0,0xd9 = st2g	x2, [sp, #16]!
0xff,0x1f,0xa0,0xd9 = st2g	sp, [sp, #16]!
0x20,0x0c,0xf0,0xd9 = stz2g	x0, [x1, #-4096]!
0x41,0xfc,0xef,0xd9 = stz2g	x1, [x2, #4080]!
0xe2,0x1f,0xe0,0xd9 = stz2g	x2, [sp, #16]!
0xff,0x1f,0xe0,0xd9 = stz2g	sp, [sp, #16]!
0x20,0x0c,0xf0,0xd9 = stz2g	x0, [x1, #-4096]!
0x41,0xfc,0xef,0xd9 = stz2g	x1, [x2, #4080]!
0xe2,0x1f,0xe0,0xd9 = stz2g	x2, [sp, #16]!
0xff,0x1f,0xe0,0xd9 = stz2g	sp, [sp, #16]!
0x20,0x04,0xb0,0xd9 = st2g	x0, [x1], #-4096
0x41,0xf4,0xaf,0xd9 = st2g	x1, [x2], #4080
0xe2,0x17,0xa0,0xd9 = st2g	x2, [sp], #16
0xff,0x17,0xa0,0xd9 = st2g	sp, [sp], #16
0x20,0x04,0xb0,0xd9 = st2g	x0, [x1], #-4096
0x41,0xf4,0xaf,0xd9 = st2g	x1, [x2], #4080
0xe2,0x17,0xa0,0xd9 = st2g	x2, [sp], #16
0xff,0x17,0xa0,0xd9 = st2g	sp, [sp], #16
0x20,0x04,0xf0,0xd9 = stz2g	x0, [x1], #-4096
0x41,0xf4,0xef,0xd9 = stz2g	x1, [x2], #4080
0xe2,0x17,0xe0,0xd9 = stz2g	x2, [sp], #16
0xff,0x17,0xe0,0xd9 = stz2g	sp, [sp], #16
0x20,0x04,0xf0,0xd9 = stz2g	x0, [x1], #-4096
0x41,0xf4,0xef,0xd9 = stz2g	x1, [x2], #4080
0xe2,0x17,0xe0,0xd9 = stz2g	x2, [sp], #16
0xff,0x17,0xe0,0xd9 = stz2g	sp, [sp], #16
0x40,0x04,0x20,0x69 = stgp	x0, x1, [x2, #-1024]
0x40,0x84,0x1f,0x69 = stgp	x0, x1, [x2, #1008]
0xe0,0x87,0x00,0x69 = stgp	x0, x1, [sp, #16]
0x5f,0x84,0x00,0x69 = stgp	xzr, x1, [x2, #16]
0x40,0xfc,0x00,0x69 = stgp	x0, xzr, [x2, #16]
0x40,0x7c,0x00,0x69 = stgp	x0, xzr, [x2]
0x40,0x04,0x20,0x69 = stgp	x0, x1, [x2, #-1024]
0x40,0x84,0x1f,0x69 = stgp	x0, x1, [x2, #1008]
0xe0,0x87,0x00,0x69 = stgp	x0, x1, [sp, #16]
0x5f,0x84,0x00,0x69 = stgp	xzr, x1, [x2, #16]
0x40,0xfc,0x00,0x69 = stgp	x0, xzr, [x2, #16]
0x40,0x7c,0x00,0x69 = stgp	x0, xzr, [x2]
0x40,0x04,0xa0,0x69 = stgp	x0, x1, [x2, #-1024]!
0x40,0x84,0x9f,0x69 = stgp	x0, x1, [x2, #1008]!
0xe0,0x87,0x80,0x69 = stgp	x0, x1, [sp, #16]!
0x5f,0x84,0x80,0x69 = stgp	xzr, x1, [x2, #16]!
0x40,0xfc,0x80,0x69 = stgp	x0, xzr, [x2, #16]!
0x40,0x04,0xa0,0x69 = stgp	x0, x1, [x2, #-1024]!
0x40,0x84,0x9f,0x69 = stgp	x0, x1, [x2, #1008]!
0xe0,0x87,0x80,0x69 = stgp	x0, x1, [sp, #16]!
0x5f,0x84,0x80,0x69 = stgp	xzr, x1, [x2, #16]!
0x40,0xfc,0x80,0x69 = stgp	x0, xzr, [x2, #16]!
0x40,0x04,0xa0,0x68 = stgp	x0, x1, [x2], #-1024
0x40,0x84,0x9f,0x68 = stgp	x0, x1, [x2], #1008
0xe0,0x87,0x80,0x68 = stgp	x0, x1, [sp], #16
0x5f,0x84,0x80,0x68 = stgp	xzr, x1, [x2], #16
0x40,0xfc,0x80,0x68 = stgp	x0, xzr, [x2], #16
0x40,0x04,0xa0,0x68 = stgp	x0, x1, [x2], #-1024
0x40,0x84,0x9f,0x68 = stgp	x0, x1, [x2], #1008
0xe0,0x87,0x80,0x68 = stgp	x0, x1, [sp], #16
0x5f,0x84,0x80,0x68 = stgp	xzr, x1, [x2], #16
0x40,0xfc,0x80,0x68 = stgp	x0, xzr, [x2], #16
0x20,0x00,0x60,0xd9 = ldg	x0, [x1]
0xe2,0x03,0x70,0xd9 = ldg	x2, [sp, #-4096]
0x83,0xf0,0x6f,0xd9 = ldg	x3, [x4, #4080]
0x20,0x00,0x60,0xd9 = ldg	x0, [x1]
0xe2,0x03,0x70,0xd9 = ldg	x2, [sp, #-4096]
0x83,0xf0,0x6f,0xd9 = ldg	x3, [x4, #4080]
0x20,0x00,0xe0,0xd9 = ldgm	x0, [x1]
0xe1,0x03,0xe0,0xd9 = ldgm	x1, [sp]
0x5f,0x00,0xe0,0xd9 = ldgm	xzr, [x2]
0x20,0x00,0xa0,0xd9 = stgm	x0, [x1]
0xe1,0x03,0xa0,0xd9 = stgm	x1, [sp]
0x5f,0x00,0xa0,0xd9 = stgm	xzr, [x2]
0x20,0x00,0x20,0xd9 = stzgm	x0, [x1]
0xe1,0x03,0x20,0xd9 = stzgm	x1, [sp]
0x5f,0x00,0x20,0xd9 = stzgm	xzr, [x2]
0x20,0x00,0xe0,0xd9 = ldgm	x0, [x1]
0xe1,0x03,0xe0,0xd9 = ldgm	x1, [sp]
0x5f,0x00,0xe0,0xd9 = ldgm	xzr, [x2]
0x20,0x00,0xa0,0xd9 = stgm	x0, [x1]
0xe1,0x03,0xa0,0xd9 = stgm	x1, [sp]
0x5f,0x00,0xa0,0xd9 = stgm	xzr, [x2]
0x20,0x00,0x20,0xd9 = stzgm	x0, [x1]
0xe1,0x03,0x20,0xd9 = stzgm	x1, [sp]
0x5f,0x00,0x20,0xd9 = stzgm	xzr, [x2]
0x60,0x76,0x08,0xd5 = dc	igvac, x0
0x81,0x76,0x08,0xd5 = dc	igsw, x1
0x82,0x7a,0x08,0xd5 = dc	cgsw, x2
0x83,0x7e,0x08,0xd5 = dc	cigsw, x3
0x64,0x7a,0x0b,0xd5 = dc	cgvac, x4
0x65,0x7c,0x0b,0xd5 = dc	cgvap, x5
0x66,0x7d,0x0b,0xd5 = dc	cgvadp, x6
0x67,0x7e,0x0b,0xd5 = dc	cigvac, x7
0x68,0x74,0x0b,0xd5 = dc	gva, x8
0xa9,0x76,0x08,0xd5 = dc	igdvac, x9
0xca,0x76,0x08,0xd5 = dc	igdsw, x10
0xcb,0x7a,0x08,0xd5 = dc	cgdsw, x11
0xcc,0x7e,0x08,0xd5 = dc	cigdsw, x12
0xad,0x7a,0x0b,0xd5 = dc	cgdvac, x13
0xae,0x7c,0x0b,0xd5 = dc	cgdvap, x14
0xaf,0x7d,0x0b,0xd5 = dc	cgdvadp, x15
0xb0,0x7e,0x0b,0xd5 = dc	cigdvac, x16
0x91,0x74,0x0b,0xd5 = dc	gzva, x17
0xe0,0x42,0x3b,0xd5 = mrs	x0, TCO
0xc1,0x10,0x38,0xd5 = mrs	x1, GCR_EL1
0xa2,0x10,0x38,0xd5 = mrs	x2, RGSR_EL1
0x03,0x56,0x38,0xd5 = mrs	x3, TFSR_EL1
0x04,0x56,0x3c,0xd5 = mrs	x4, TFSR_EL2
0x05,0x56,0x3e,0xd5 = mrs	x5, TFSR_EL3
0x06,0x56,0x3d,0xd5 = mrs	x6, TFSR_EL12
0x27,0x56,0x38,0xd5 = mrs	x7, TFSRE0_EL1
0x88,0x00,0x39,0xd5 = mrs	x8, GMID_EL1
0x9f,0x40,0x03,0xd5 = msr	TCO, #0
0xe0,0x42,0x1b,0xd5 = msr	TCO, x0
0xc1,0x10,0x18,0xd5 = msr	GCR_EL1, x1
0xa2,0x10,0x18,0xd5 = msr	RGSR_EL1, x2
0x03,0x56,0x18,0xd5 = msr	TFSR_EL1, x3
0x04,0x56,0x1c,0xd5 = msr	TFSR_EL2, x4
0x05,0x56,0x1e,0xd5 = msr	TFSR_EL3, x5
0x06,0x56,0x1d,0xd5 = msr	TFSR_EL12, x6
0x27,0x56,0x18,0xd5 = msr	TFSRE0_EL1, x7
0x88,0x00,0x19,0xd5 = msr	S3_1_C0_C0_4, x8