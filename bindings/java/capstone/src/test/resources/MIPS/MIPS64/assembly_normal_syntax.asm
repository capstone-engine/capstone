0x1000:	ori	$at, $at, 0x3456
	op_count: 3
		operands[0].type: REG = at
		operands[1].type: REG = at
		operands[2].type: IMM = 0x3456

0x1004:	srl	$v0, $at, 0x1f
	op_count: 3
		operands[0].type: REG = v0
		operands[1].type: REG = at
		operands[2].type: IMM = 0x1f