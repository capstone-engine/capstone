0x1000:	mov.w	r1, #0

0x1004:	pop.w	{r11, pc}

0x1008:	tbb	[r1, r0]

0x100c:	it	ne
	Code condition: 2

0x100e:	iteet	ge
	Code condition: 11

0x1010:	vdupne.8	d16, d11[1]
	Code condition: 2
	Vector-size: 8

0x1014:	msr	cpsr_fc, r6

0x1018:	msr	apsr_nzcvqg, r0

0x101c:	sxtb.w	r6, r9, ror #8

0x1020:	vaddw.u16	q8, q8, d18
	Vector-data: 10