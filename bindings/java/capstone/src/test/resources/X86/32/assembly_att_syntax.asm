0x1000:	leal	8(%edx, %esi), %ecx
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x8d 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x4c
	disp: 0x8
	sib: 0x32
		sib_base: edx
		sib_index: esi
		sib_scale: 1
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = edx
			operands[0].mem.index: REG = esi
			operands[0].mem.disp: 0x8
		operands[0].size: 4
		operands[1].type: REG = ecx
		operands[1].size: 4

0x1004:	addl	%ebx, %eax
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x01 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0xd8
	disp: 0x0
	sib: 0x0
	op_count: 2
		operands[0].type: REG = ebx
		operands[0].size: 4
		operands[1].type: REG = eax
		operands[1].size: 4

0x1006:	addl	$0x1234, %esi
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x81 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0xc6
	disp: 0x0
	sib: 0x0
	imm_count: 1
		imms[1]: 0x1234
	op_count: 2
		operands[0].type: IMM = 0x1234
		operands[0].size: 4
		operands[1].type: REG = esi
		operands[1].size: 4

0x100c:	addl	$0x123, %eax
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x05 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	imm_count: 1
		imms[1]: 0x123
	op_count: 2
		operands[0].type: IMM = 0x123
		operands[0].size: 4
		operands[1].type: REG = eax
		operands[1].size: 4

0x1011:	movl	%ss:0x123(%ecx, %edx, 4), %eax
	Prefix: 0x00 0x36 0x00 0x00 
	Opcode: 0x8b 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x84
	disp: 0x123
	sib: 0x91
		sib_base: ecx
		sib_index: edx
		sib_scale: 4
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.segment: REG = ss
			operands[0].mem.base: REG = ecx
			operands[0].mem.index: REG = edx
			operands[0].mem.scale: 4
			operands[0].mem.disp: 0x123
		operands[0].size: 4
		operands[1].type: REG = eax
		operands[1].size: 4

0x1019:	incl	%ecx
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x41 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	op_count: 1
		operands[0].type: REG = ecx
		operands[0].size: 4

0x101a:	leal	0x6789(%ecx, %edi), %eax
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x8d 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x84
	disp: 0x6789
	sib: 0x39
		sib_base: ecx
		sib_index: edi
		sib_scale: 1
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = ecx
			operands[0].mem.index: REG = edi
			operands[0].mem.disp: 0x6789
		operands[0].size: 4
		operands[1].type: REG = eax
		operands[1].size: 4

0x1021:	leal	0x6789(%edi), %eax
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x8d 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x87
	disp: 0x6789
	sib: 0x0
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = edi
			operands[0].mem.disp: 0x6789
		operands[0].size: 4
		operands[1].type: REG = eax
		operands[1].size: 4

0x1027:	movb	$0xc6, %ah
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0xb4 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	imm_count: 1
		imms[1]: 0xc6
	op_count: 2
		operands[0].type: IMM = 0xc6
		operands[0].size: 1
		operands[1].type: REG = ah
		operands[1].size: 1