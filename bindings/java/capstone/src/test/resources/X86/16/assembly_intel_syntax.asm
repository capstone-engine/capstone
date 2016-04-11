0x1000:	lea	cx, word ptr [si + 0x32]
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x8d 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x4c
	disp: 0x32
	op_count: 2
		operands[0].type: REG = cx
		operands[0].size: 2
		operands[1].type: MEM
			operands[1].mem.base: REG = si
			operands[1].mem.disp: 0x32
		operands[1].size: 2

0x1003:	or	byte ptr [bx + di], al
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x08 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x1
	disp: 0x0
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = bx
			operands[0].mem.index: REG = di
		operands[0].size: 1
		operands[1].type: REG = al
		operands[1].size: 1

0x1005:	fadd	dword ptr [bx + di + 0x34c6]
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0xd8 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x81
	disp: 0x34c6
	op_count: 1
		operands[0].type: MEM
			operands[0].mem.base: REG = bx
			operands[0].mem.index: REG = di
			operands[0].mem.disp: 0x34c6
		operands[0].size: 4

0x1009:	adc	al, byte ptr [bx + si]
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x12 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x0
	disp: 0x0
	op_count: 2
		operands[0].type: REG = al
		operands[0].size: 1
		operands[1].type: MEM
			operands[1].mem.base: REG = bx
			operands[1].mem.index: REG = si
		operands[1].size: 1

0x100b:	add	byte ptr [di], al
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x00 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x5
	disp: 0x0
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = di
		operands[0].size: 1
		operands[1].type: REG = al
		operands[1].size: 1

0x100d:	and	ax, word ptr [bx + di]
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x23 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x1
	disp: 0x0
	op_count: 2
		operands[0].type: REG = ax
		operands[0].size: 2
		operands[1].type: MEM
			operands[1].mem.base: REG = bx
			operands[1].mem.index: REG = di
		operands[1].size: 2

0x100f:	add	byte ptr [bx + si], al
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x00 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x0
	disp: 0x0
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = bx
			operands[0].mem.index: REG = si
		operands[0].size: 1
		operands[1].type: REG = al
		operands[1].size: 1

0x1011:	mov	ax, word ptr ss:[si + 0x2391]
	Prefix: 0x00 0x36 0x00 0x00 
	Opcode: 0x8b 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x84
	disp: 0x2391
	op_count: 2
		operands[0].type: REG = ax
		operands[0].size: 2
		operands[1].type: MEM
			operands[1].mem.segment: REG = ss
			operands[1].mem.base: REG = si
			operands[1].mem.disp: 0x2391
		operands[1].size: 2

0x1016:	add	word ptr [bx + si], ax
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x01 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x0
	disp: 0x0
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = bx
			operands[0].mem.index: REG = si
		operands[0].size: 2
		operands[1].type: REG = ax
		operands[1].size: 2

0x1018:	add	byte ptr [bx + di - 0x73], al
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x00 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x41
	disp: 0xffffff8d
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = bx
			operands[0].mem.index: REG = di
			operands[0].mem.disp: 0xffffffffffffff8d
		operands[0].size: 1
		operands[1].type: REG = al
		operands[1].size: 1

0x101b:	test	byte ptr [bx + di], bh
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x84 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x39
	disp: 0x0
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = bx
			operands[0].mem.index: REG = di
		operands[0].size: 1
		operands[1].type: REG = bh
		operands[1].size: 1

0x101d:	mov	word ptr [bx], sp
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x89 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x67
	disp: 0x0
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = bx
		operands[0].size: 2
		operands[1].type: REG = sp
		operands[1].size: 2

0x1020:	add	byte ptr [di - 0x7679], cl
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0x00 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x8d
	disp: 0xffff8987
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = di
			operands[0].mem.disp: 0xffffffffffff8987
		operands[0].size: 1
		operands[1].type: REG = cl
		operands[1].size: 1

0x1024:	add	byte ptr [eax], al
	Prefix: 0x00 0x00 0x00 0x67 
	Opcode: 0x00 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = eax
		operands[0].size: 1
		operands[1].type: REG = al
		operands[1].size: 1

0x1027:	mov	ah, 0xc6
	Prefix: 0x00 0x00 0x00 0x00 
	Opcode: 0xb4 0x00 0x00 0x00 
	rex: 0x0
	addr_size: 2
	modrm: 0x0
	disp: 0x0
	imm_count: 1
		imms[1]: 0xc6
	op_count: 2
		operands[0].type: REG = ah
		operands[0].size: 1
		operands[1].type: IMM = 0xc6
		operands[1].size: 1