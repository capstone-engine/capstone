0x1000:	push	rbp
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x55 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 8
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	op_count: 1
		operands[0].type: REG = rbp
		operands[0].size: 8

0x1001:	mov	rax, qword ptr [rip + 0x13b8]
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x8b 0x00 0x00 0x00 
	rex: 0x48
	addr_size: 8
	modrm: 0x5
	disp: 0x13b8
	sib: 0x0
	op_count: 2
		operands[0].type: REG = rax
		operands[0].size: 8
		operands[1].type: MEM
			operands[1].mem.base: REG = rip
			operands[1].mem.disp: 0x13b8
		operands[1].size: 8