0x1000:	adb	%f0, 0
	op_count: 2
		operands[0].type: REG = f0
		operands[1].type: IMM = 0x0

0x1006:	a	%r0, 0xfff(%r15, %r1)
	op_count: 2
		operands[0].type: REG = 0
		operands[1].type: MEM
			operands[1].mem.base: REG = 1
			operands[1].mem.index: REG = 15
			operands[1].mem.disp: 0xfff

0x100a:	afi	%r0, -0x80000000
	op_count: 2
		operands[0].type: REG = 0
		operands[1].type: IMM = 0xffffffff80000000

0x1010:	br	%r7
	op_count: 1
		operands[0].type: REG = 7

0x1012:	xiy	0x7ffff(%r15), 0x2a
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = 15
			operands[0].mem.disp: 0x7ffff
		operands[1].type: IMM = 0x2a

0x1018:	xy	%r0, 0x7ffff(%r1, %r15)
	op_count: 2
		operands[0].type: REG = 0
		operands[1].type: MEM
			operands[1].mem.base: REG = 15
			operands[1].mem.index: REG = 1
			operands[1].mem.disp: 0x7ffff

0x101e:	stmg	%r0, %r0, 0(%r15)
	op_count: 3
		operands[0].type: REG = 0
		operands[1].type: REG = 0
		operands[2].type: MEM
			operands[2].mem.base: REG = 15

0x1024:	ear	%r7, %a8
	op_count: 2
		operands[0].type: REG = 7
		operands[1].type: ACREG = 8

0x1028:	clije	%r1, 0xc1, 0x1028
	op_count: 3
		operands[0].type: REG = 1
		operands[1].type: IMM = 0xc1
		operands[2].type: IMM = 0x1028