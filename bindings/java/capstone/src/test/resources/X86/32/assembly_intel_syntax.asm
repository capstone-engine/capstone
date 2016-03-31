0x1000:	lea	ecx, dword ptr [edx + esi + 8]
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
		operands[0].type: REG = ecx
		operands[0].size: 4
		operands[1].type: MEM
			operands[1].mem.base: REG = edx
			operands[1].mem.index: REG = esi
			operands[1].mem.disp: 0x8
		operands[1].size: 4

0x1004:	add	eax, ebx
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x01 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0xd8
	disp: 0x0
	sib: 0x0
	op_count: 2
		operands[0].type: REG = eax
		operands[0].size: 4
		operands[1].type: REG = ebx
		operands[1].size: 4

0x1006:	add	esi, 0x1234
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
		operands[0].type: REG = esi
		operands[0].size: 4
		operands[1].type: IMM = 0x1234
		operands[1].size: 4

0x100c:	add	eax, 0x123
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
		operands[0].type: REG = eax
		operands[0].size: 4
		operands[1].type: IMM = 0x123
		operands[1].size: 4

0x1011:	mov	eax, dword ptr ss:[ecx + edx*4 + 0x123]
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
		operands[0].type: REG = eax
		operands[0].size: 4
		operands[1].type: MEM
			operands[1].mem.segment: REG = ss
			operands[1].mem.base: REG = ecx
			operands[1].mem.index: REG = edx
			operands[1].mem.scale: 4
			operands[1].mem.disp: 0x123
		operands[1].size: 4

0x1019:	inc	ecx
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

0x101a:	lea	eax, dword ptr [ecx + edi + 0x6789]
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
		operands[0].type: REG = eax
		operands[0].size: 4
		operands[1].type: MEM
			operands[1].mem.base: REG = ecx
			operands[1].mem.index: REG = edi
			operands[1].mem.disp: 0x6789
		operands[1].size: 4

0x1021:	lea	eax, dword ptr [edi + 0x6789]
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x8d 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x87
	disp: 0x6789
	sib: 0x0
	op_count: 2
		operands[0].type: REG = eax
		operands[0].size: 4
		operands[1].type: MEM
			operands[1].mem.base: REG = edi
			operands[1].mem.disp: 0x6789
		operands[1].size: 4

0x1027:	mov	ah, 0xc6
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
		operands[0].type: REG = ah
		operands[0].size: 1
		operands[1].type: IMM = 0xc6
		operands[1].size: 1