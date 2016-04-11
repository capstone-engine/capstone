0x1000:	cmp	%g1, %g2
	op_count: 2
		operands[0].type: REG = g1
		operands[1].type: REG = g2

0x1004:	jmpl	%o1+8, %g2
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = o1
			operands[0].mem.disp: 0x8
		operands[1].type: REG = g2

0x1008:	restore	%g0, 1, %g2
	op_count: 3
		operands[0].type: REG = g0
		operands[1].type: IMM = 0x1
		operands[2].type: REG = g2

0x100c:	restore	

0x1010:	mov	1, %o0
	op_count: 2
		operands[0].type: IMM = 0x1
		operands[1].type: REG = o0

0x1014:	casx	[%i0], %l6, %o2
	op_count: 3
		operands[0].type: MEM
			operands[0].mem.base: REG = i0
		operands[1].type: REG = l6
		operands[2].type: REG = o2

0x1018:	sethi	0xa, %l0
	op_count: 2
		operands[0].type: IMM = 0xa
		operands[1].type: REG = l0

0x101c:	add	%g1, %g2, %g3
	op_count: 3
		operands[0].type: REG = g1
		operands[1].type: REG = g2
		operands[2].type: REG = g3

0x1020:	nop	

0x1024:	bne	0x1020
	op_count: 1
		operands[0].type: IMM = 0x1020
	Code condition: 265

0x1028:	ba	0x1024
	op_count: 1
		operands[0].type: IMM = 0x1024

0x102c:	add	%o0, %o1, %l0
	op_count: 3
		operands[0].type: REG = o0
		operands[1].type: REG = o1
		operands[2].type: REG = l0

0x1030:	fbg	0x102c
	op_count: 1
		operands[0].type: IMM = 0x102c
	Code condition: 278

0x1034:	st	%o2, [%g1]
	op_count: 2
		operands[0].type: REG = o2
		operands[1].type: MEM
			operands[1].mem.base: REG = g1

0x1038:	ldsb	[%i0+%l6], %o2
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = i0
			operands[0].mem.index: REG = l6
		operands[1].type: REG = o2

0x103c:	brnz,a,pn	%o2, 0x1048
	op_count: 2
		operands[0].type: REG = o2
		operands[1].type: IMM = 0x1048
	Hint code: 5