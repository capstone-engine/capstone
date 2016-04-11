0x1000:	lwz	r1, (0)
	op_count: 2
		operands[0].type: REG = r1
		operands[1].type: MEM
			operands[1].mem.base: REG = r0

0x1004:	lwz	r1, (r31)
	op_count: 2
		operands[0].type: REG = r1
		operands[1].type: MEM
			operands[1].mem.base: REG = r31

0x1008:	vpkpx	v2, v3, v4
	op_count: 3
		operands[0].type: REG = v2
		operands[1].type: REG = v3
		operands[2].type: REG = v4

0x100c:	stfs	f2, 0x80(r4)
	op_count: 2
		operands[0].type: REG = f2
		operands[1].type: MEM
			operands[1].mem.base: REG = r4
			operands[1].mem.disp: 0x80

0x1010:	crand	2, 3, 4
	op_count: 3
		operands[0].type: REG = r2
		operands[1].type: REG = r3
		operands[2].type: REG = r4

0x1014:	cmpwi	cr2, r3, 0x80
	op_count: 3
		operands[0].type: REG = cr2
		operands[1].type: REG = r3
		operands[2].type: IMM = 0x80

0x1018:	addc	r2, r3, r4
	op_count: 3
		operands[0].type: REG = r2
		operands[1].type: REG = r3
		operands[2].type: REG = r4

0x101c:	mulhd.	r2, r3, r4
	op_count: 3
		operands[0].type: REG = r2
		operands[1].type: REG = r3
		operands[2].type: REG = r4
	Update-CR0: True

0x1020:	bdnzlrl+	
	Branch hint: 1

0x1024:	bgelrl-	cr2
	op_count: 1
		operands[0].type: REG = cr2
	Branch code: 4
	Branch hint: 2

0x1028:	bne	0x103c
	op_count: 1
		operands[0].type: IMM = 0x103c
	Branch code: 68