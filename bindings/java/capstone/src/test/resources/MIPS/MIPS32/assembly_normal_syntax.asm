0x1000:	jal	0x40025c
	op_count: 1
		operands[0].type: IMM = 0x40025c

0x1004:	nop	

0x1008:	addiu	$v0, $zero, 0xc
	op_count: 3
		operands[0].type: REG = v0
		operands[1].type: REG = zero
		operands[2].type: IMM = 0xc

0x100c:	lw	$v0, ($sp)
	op_count: 2
		operands[0].type: REG = v0
		operands[1].type: MEM
			operands[1].mem.base: REG = sp

0x1010:	ori	$at, $at, 0x3456
	op_count: 3
		operands[0].type: REG = at
		operands[1].type: REG = at
		operands[2].type: IMM = 0x3456