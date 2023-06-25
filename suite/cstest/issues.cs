!# issue 2062 repz Prefix
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
0xf3,0xc3 == repz ret ; Prefix:0xf3 0x00 0x00 0x00

!# issue 2007 RISCV64 instruction groups
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0x63,0x04,0x03,0x00 == beqz t1, 8 ; op_count: 2 ; operands[0].type: REG = t1 ; operands[1].type: IMM = 0x8 ; Groups: branch_relative jump

!# issue 2007 RISCV64 instruction groups
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0x73,0x00,0x00,0x00 == ecall ; Groups: int

!# issue 2007 RISCV64 instruction groups
!# CS_ARCH_RISCV, CS_MODE_RISCV64, CS_OPT_DETAIL
0xef,0x00,0x40,0x00 == jal 4 ; op_count: 1 ; operands[0].type: IMM = 0x4 ; Groups: call

!# issue 2007 RISCV32 instruction groups
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x63,0x04,0x03,0x00 == beqz t1, 8 ; op_count: 2 ; operands[0].type: REG = t1 ; operands[1].type: IMM = 0x8 ; Groups: branch_relative jump

!# issue 2007 RISCV32 instruction groups
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0x73,0x00,0x00,0x00 == ecall ; Groups: int

!# issue 2007 RISCV32 instruction groups
!# CS_ARCH_RISCV, CS_MODE_RISCV32, CS_OPT_DETAIL
0xef,0x00,0x40,0x00 == jal 4 ; op_count: 1 ; operands[0].type: IMM = 0x4 ; Groups: call

!# issue 2007 RISCV32 instruction groups
!# CS_ARCH_RISCV, CS_MODE_RISCV32 CS_MODE_RISCVC, CS_OPT_DETAIL
0x11,0x20 == c.jal 4 ; op_count: 1 ; operands[0].type: IMM = 0x4 ; Groups: hasStdExtC isrv32 call

!# issue 2007 RISCV32 instruction groups
!# CS_ARCH_RISCV, CS_MODE_RISCV32 CS_MODE_RISCVC, CS_OPT_DETAIL
0x91,0xc1 == c.beqz a1, 4 ; op_count: 2 ; operands[0].type: REG = a1 ; operands[1].type: IMM = 0x4 ; Groups: hasStdExtC branch_relative jump

!# issue 1997 notrack jmp
!# CS_ARCH_X86, CS_MODE_64, None
0x3e,0xff,0xe0 == notrack jmp rax

!# issue 1997 notrack call
!# CS_ARCH_X86, CS_MODE_64, None
0x3e,0xff,0xd0 == notrack call rax

!# issue 1924 SME Index instruction alias printing is not always valid
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x02,0x00,0x9f,0xe0 == ld1w	{za0h.s[w12, 2]}, p0/z, [x0] ; operands[0].type: REG = zas0 ; operands[0].index.base: REG = w12 ; operands[0].index.disp: 0x2 ; operands[1].type: REG = p0 ; operands[2].type: MEM ; operands[2].mem.base: REG = x0

!# issue 1912 PPC register name
!# CS_ARCH_PPC, CS_MODE_BIG_ENDIAN, None
0x2d,0x03,0x00,0x80 == cmpwi cr2, r3, 0x80

!# issue 1912 PPC no register name
!# CS_ARCH_PPC, CS_MODE_BIG_ENDIAN, CS_OPT_SYNTAX_NOREGNAME
0x2d,0x03,0x00,0x80 == cmpwi 2, 3, 0x80

!# issue 1902 PPC psq_st negative displacement
!# CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN | CS_MODE_PS, CS_OPT_DETAIL
0xf3,0xec,0x0f,0xf8 == psq_st f31, -8(r12), 0, 0 ; op_count: 4 ; operands[0].type: REG = f31 ; operands[1].type: MEM ; operands[1].mem.base: REG = r12 ; operands[1].mem.disp: 0xfffffff8 ; operands[2].type: IMM = 0x0 ; operands[3].type: IMM = 0x0

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x21,0x04,0x03,0x5e == mov b1, v1.b[1] ; operands[1].vas: 0x4 ; operands[1].vector_index: 1

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0xc0,0x1e,0x03,0x4e == mov v0.b[1], w22 ; operands[0].vas: 0x4 ; operands[0].vector_index: 1

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0xc0,0x1e,0x06,0x4e == mov v0.h[1], w22 ; operands[0].vas: 0x8 ; operands[0].vector_index: 1

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0xc0,0x1e,0x0c,0x4e == mov v0.s[1], w22 ; operands[0].vas: 0xb ; operands[0].vector_index: 1

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0xc0,0x1e,0x18,0x4e == mov v0.d[1], x22 ; operands[0].vas: 0xd ; operands[0].vector_index: 1

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x20,0x0c,0x03,0x6e == mov v0.b[1], v1.b[1] ; operands[0].vas: 0x4 ; operands[0].vector_index: 1 ; operands[1].vas: 0x4 ; operands[1].vector_index: 1

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x20,0x14,0x06,0x6e == mov v0.h[1], v1.h[1] ; operands[0].vas: 0x8 ; operands[0].vector_index: 1 ; operands[1].vas: 0x8 ; operands[1].vector_index: 1

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x20,0x24,0x0c,0x6e == mov v0.s[1], v1.s[1] ; operands[0].vas: 0xb ; operands[0].vector_index: 1 ; operands[1].vas: 0xb ; operands[1].vector_index: 1

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x20,0x44,0x18,0x6e == mov v0.d[1], v1.d[1] ; operands[0].vas: 0xd ; operands[0].vector_index: 1 ; operands[1].vas: 0xd ; operands[1].vector_index: 1

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x20,0x3c,0x0c,0x0e == mov w0, v1.s[1] ; operands[1].vas: 0xb ; operands[1].vector_index: 1

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x20,0x3c,0x0c,0x0e == mov w0, v1.s[1] ; operands[1].vas: 0xb ; operands[1].vector_index: 1

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x20,0x3c,0x18,0x4e == mov x0, v1.d[1] ; operands[1].vas: 0xd ; operands[1].vector_index: 1

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x20,0x3c,0x18,0x4e == mov x0, v1.d[1] ; operands[1].vas: 0xd ; operands[1].vector_index: 1

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x00,0xc0,0x50,0x05 == fmov z0.h, p0/m, #2.00000000 ; operands[0].vas: 0x8

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x00,0xc0,0x79,0x25 == fmov z0.h, #2.00000000 ; operands[0].vas: 0x8

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0xa1,0xca,0xf8,0x25 == mov z1.d, #0x55 ; operands[0].vas: 0xd

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x21,0x44,0x81,0x25 == mov p1.b, p1.b ; operands[0].vas: 0x4 ; operands[1].vas: 0x4

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x21,0x40,0x51,0x05 == mov z1.h, p1/m, #1 ; operands[0].vas: 0x8

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x21,0x00,0x51,0x05 == mov z1.h, p1/z, #1 ; operands[0].vas: 0x8

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x20,0xc0,0x38,0x25 == mov z0.b, #1 ; operands[0].vas: 0x4

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x71,0x4a,0x01,0x25 == mov p1.b, p2/m, p3.b ; operands[0].vas: 0x4 ; operands[2].vas: 0x4

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x61,0x48,0x03,0x25 == mov p1.b, p2/z, p3.b ; operands[0].vas: 0x4 ; operands[2].vas: 0x4

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x21,0xa8,0x28,0x05 == mov z1.b, p2/m, w1 ; operands[0].vas: 0x4

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x21,0x38,0x20,0x05 == mov z1.b, w1 ; operands[0].vas: 0x4

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x01,0x88,0x20,0x05 == mov z1.b, p2/m, b0 ; operands[0].vas: 0x4

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x00,0x20,0x21,0x05 == mov z0.b, b0 ; operands[0].vas: 0x4

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x00,0x20,0x23,0x05 == mov z0.b, z0.b[1] ; operands[0].vas: 0x4 ; operands[1].vas: 0x4 ; operands[1].vector_index: 1

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x20,0xc4,0x20,0x05 == mov z0.b, p1/m, z1.b ; operands[0].vas: 0x4 ; operands[2].vas: 0x4

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x20,0x30,0x61,0x04 == mov z0.d, z1.d ; operands[0].vas: 0xd ; operands[1].vas: 0xd

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x40,0x44,0x42,0x25 == movs p0.b, p1/z, p2.b ; operands[0].vas: 0x4 ; operands[2].vas: 0x4

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x20,0x44,0xc1,0x25 == movs p0.b, p1.b ; operands[0].vas: 0x4 ; operands[1].vas: 0x4

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x40,0x46,0x01,0x25 == not p0.b, p1/z, p2.b ; operands[0].vas: 0x4 ; operands[2].vas: 0x4

!# issue 1873 AArch64 missing VAS specifiers in aliased instructions
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x40,0x46,0x41,0x25 == nots p0.b, p1/z, p2.b ; operands[0].vas: 0x4 ; operands[2].vas: 0x4

!# issue 1856 AArch64 SYS instruction operands: tlbi 1 op
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x1f,0x83,0x08,0xd5 == tlbi vmalle1is ; op_count: 1 ; operands[0].type: SYS = 0x9a

!# issue 1856 AArch64 SYS instruction operands: tlbi 2 op
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x22,0x87,0x08,0xd5 == tlbi vae1, x2 ; op_count: 2 ; operands[0].type: SYS = 0x75

!# issue 1856 AArch64 SYS instruction operands: at
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0xc0,0x78,0x0c,0xd5 == at s12e0r, x0 ; op_count: 2 ; operands[0].type: SYS = 0xaf

!# issue 1856 AArch64 SYS instruction operands: dc
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x22,0x7b,0x0b,0xd5 == dc cvau, x2 ; op_count: 2 ; operands[0].type: SYS = 0xc5

!# issue 1856 AArch64 SYS instruction operands: ic
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x20,0x75,0x0b,0xd5 == ic ivau, x0 ; op_count: 2 ; operands[0].type: SYS = 0xd1

!# issue 1843 AArch64 missing VAS specifiers in aliased instructions: mov 16b
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x40,0x1e,0xb2,0x4e == mov v0.16b, v18.16b ; operands[0].type: REG = v0 ; operands[0].vas: 0x1 ; operands[1].type: REG = v18 ; operands[1].vas: 0x1

!# issue 1843 AArch64 missing VAS specifiers in aliased instructions: mov 8b
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x40,0x1e,0xb2,0x0e == mov v0.8b, v18.8b ; operands[0].type: REG = v0 ; operands[0].vas: 0x2 ; operands[1].type: REG = v18 ; operands[1].vas: 0x2

!# issue 1843 AArch64 missing VAS specifiers in aliased instructions: mvn 16b
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x40,0x5a,0x20,0x6e == mvn v0.16b, v18.16b ; operands[0].type: REG = v0 ; operands[0].vas: 0x1 ; operands[1].type: REG = v18 ; operands[1].vas: 0x1

!# issue 1843 AArch64 missing VAS specifiers in aliased instructions: mvn 8b
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x40,0x5a,0x20,0x2e == mvn v0.8b, v18.8b ; operands[0].type: REG = v0 ; operands[0].vas: 0x2 ; operands[1].type: REG = v18 ; operands[1].vas: 0x2

!# issue 1839 AArch64 Incorrect detailed disassembly of ldr
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0x41,0x00,0x40,0xf9 == ldr x1, [x2] ; operands[0].access: WRITE ; operands[1].access: READ

// !# issue 1827 x86-16 lcall 0:0xd
// !# CS_ARCH_X86, CS_MODE_16, CS_OPT_DETAIL
// 0x9a,0x0d,0x00,0x00,0x00 == lcall 0:0xd

!# issue 1827 x16 lcall seg:off format
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_DETAIL
0xb8,0x01,0x00,0x00,0x00 == mov eax, 1
0xb9,0x00,0x00,0x00,0x00 == mov ecx, 0
0x80,0xb8,0x01,0x00,0x00,0x00,0xb9 == cmp byte ptr [eax + 1], 0xb9
0x00,0x00 == add byte ptr [eax], al
0x01,0x00 == add dword ptr [eax], eax

!# issue 1827 x16 lcall seg:off format
!# CS_ARCH_X86, CS_MODE_16, CS_OPT_DETAIL
0x33,0xc0 == xor ax, ax
0xba,0x5a,0xff == mov dx, 0xff5a

!# issue 1708 M68K floating point loads and stores generate the same op_str
!# CS_ARCH_M68K, CS_MODE_BIG_ENDIAN | CS_MODE_M68K_040, None
0xf2,0x27,0x74,0x00 == fmove.d fp0, -(a7)
0xf2,0x1f,0x54,0x80 == fmove.d (a7)+, fp1
0x4e,0x75 == rts

!# issue 1661 M68K invalid transfer direction in MOVEC instruction
!# CS_ARCH_M68K, CS_MODE_BIG_ENDIAN | CS_MODE_M68K_040, None
0x4E,0x7A,0x00,0x02 == movec cacr, d0

// !# issue 1653 AArch64 wrong register access read/write flags on cmp instruction
// !# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
// 0x3F,0x00,0x02,0xEB == cmp x1, x2 ; operands[0].access: READ

!# issue 1643 M68K incorrect read of 32-bit imm for bsr
!# CS_ARCH_M68K, CS_MODE_BIG_ENDIAN | CS_MODE_M68K_040 , None
0x61,0xff,0x00,0x00,0x0b,0xea == bsr.l $bec

!# issue 1627 Arm64 LD1 missing immediate operand
!# CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_DETAIL
0xe0,0x73,0xdf,0x0c == ld1 {v0.8b}, [sp], #8 ; operands[2].type: IMM = 0x8

!# issue 1587 ARM thumb pushed registers write
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0x2d,0xe9,0xf0,0x47 == push.w {r4, r5, r6, r7, r8, sb, sl, lr} ; operands[0].access: READ

!# issue 1504 movhps qword ptr
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
0x0f,0x16,0x08 == movhps xmm1, qword ptr [rax] ; Opcode:0x0f 0x16 0x00 0x00

!# issue 1505 opcode 0f
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
0x0f,0xa5,0xc2 == shld edx, eax, cl ; Opcode:0x0f 0xa5 0x00 0x00

!# issue 1478 tbegin.
!# CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN, CS_OPT_DETAIL
0x7c,0x20,0x05,0x1d == tbegin. 1 ; Update-CR0: True

!# issue 970 PPC bdnzt lt
!# CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN, CS_OPT_DETAIL
0x41,0x00,0xff,0xac == bdnzt lt, 0xffffffffffffffac ; operands[0].type: REG = cr0lt

!# issue 970 PPC bdnzt eq
!# CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN, CS_OPT_DETAIL
0x41,0x02,0xff,0xac == bdnzt eq, 0xffffffffffffffac ; operands[0].type: REG = cr0eq

!# issue 969 PPC bdnzflr operand 2
!# CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN, CS_OPT_DETAIL
0x4c,0x10,0x00,0x20 == bdnzflr 4*cr4+lt ; operands[0].type: REG = cr4lt

0x41,0x82,0x00,0x10 == beq 0x10 ; Groups: jump

!# issue 1481 ARM64 LDR operand2
!# CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_OPT_DETAIL
0xe9,0x03,0x40,0xf9 == ldr x9, [sp] ; operands[1].mem.base: REG = sp

!# issue 968 PPC absolute branch: bdnzla
!# CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN, None
0x1000: 0x42,0x00,0x12,0x37 == bdnzla 0x1234

!# issue 968 PPC absolute branch: bdzla
!# CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN, None
0x1000: 0x42,0x40,0x12,0x37 == bdzla 0x1234

!# issue X86 xrelease xchg
!# CS_ARCH_X86, CS_MODE_32, None
0xf3,0x87,0x03 == xrelease xchg dword ptr [ebx], eax

!# issue X86 xacquire xchg
!# CS_ARCH_X86, CS_MODE_32, None
0xf2,0x87,0x03 == xacquire xchg dword ptr [ebx], eax

!# issue X86 xrelease
!# CS_ARCH_X86, CS_MODE_64, None
0xf3,0xf0,0x31,0x1f == xrelease lock xor dword ptr [rdi], ebx

!# issue 1477 X86 xacquire
!# CS_ARCH_X86, CS_MODE_64, None
0xf2,0xf0,0x31,0x1f == xacquire lock xor dword ptr [rdi], ebx

!# issue PPC JUMP group
!# CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN, CS_OPT_DETAIL
0x41,0x82,0x00,0x10 == beq 0x10 ; Groups: jump

!# issue 1468 PPC bdnz
!# CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN, None
0x101086c: 0x42,0x00,0xff,0xf8 == bdnz 0x1010864

!# issue PPC bdnzt
!# CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN, None
0x1000: 0x41,0x00,0xff,0xac == bdnzt lt, 0xfac

!# issue 1469 PPC CRx
!# CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN, CS_OPT_DETAIL
0x4c,0x02,0x39,0x82 == crxor cr0lt, cr0eq, cr1un ; operands[0].type: REG = cr0lt

!# issue 1468 B target
!# CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN, None
0x1000: 0x4b,0xff,0xf8,0x00 == b 0x800

!# issue 1456 test alt 1
!# CS_ARCH_X86, CS_MODE_32, None
0xf6,0x08,0x00 == test byte ptr [eax], 0

!# issue 1456 test alt 2
!# CS_ARCH_X86, CS_MODE_32, None
0xf7,0x08,0x00,0x00,0x00,0x00 == test dword ptr [eax], 0

!# issue 1472 lock sub
!# CS_ARCH_X86, CS_MODE_32, None
0xF0,0x2B,0x45,0x08 == lock sub eax, dword ptr [ebp + 8]

!# issue 1472 lock or
!# CS_ARCH_X86, CS_MODE_32, None
0xF0,0x0B,0x45,0x08 == lock or eax, dword ptr [ebp + 8]

!# issue 1472 lock and
!# CS_ARCH_X86, CS_MODE_32, None
0xF0,0x23,0x45,0x08 == lock and eax, dword ptr [ebp + 8]

!# issue 1472 lock add
!# CS_ARCH_X86, CS_MODE_32, None
0xF0,0x03,0x45,0x08 == lock add eax, dword ptr [ebp + 8]

!# issue 1456 MOV dr
!# CS_ARCH_X86, CS_MODE_32, None
0x0f,0x23,0x00 == mov dr0, eax

!# issue 1456 MOV dr
!# CS_ARCH_X86, CS_MODE_32, None
0x0f,0x21,0x00 == mov eax, dr0

!# issue 1456 MOV cr
!# CS_ARCH_X86, CS_MODE_32, None
0x0f,0x22,0x00 == mov cr0, eax

!# issue 1472 lock adc
!# CS_ARCH_X86, CS_MODE_32, None
0xf0,0x12,0x45,0x08 == lock adc al, byte ptr [ebp + 8]

!# issue 1456 xmmword
!# CS_ARCH_X86, CS_MODE_32, None
0x66,0x0f,0x2f,0x00 == comisd xmm0, xmmword ptr [eax]

!# issue 1456 ARM printPKHASRShiftImm
!# CS_ARCH_ARM, CS_MODE_THUMB, None
0xca,0xea,0x21,0x06 == pkhtb r6, sl, r1, asr #0x20

!# issue 1456 EIZ
!# CS_ARCH_X86, CS_MODE_32, None
0x8d,0xb4,0x26,0x00,0x00,0x00,0x00 == lea esi, [esi]

!# issue 1456 ARM POP
!# CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, None
0x04,0x10,0x9d,0xe4 == pop {r1}

!# issue 1456
!# CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_OPT_DETAIL
0x31,0x02,0xa0,0xe1 == lsr r0, r1, r2 ; operands[2].type: REG = r2

!# issue 1456
!# CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_OPT_DETAIL
0x0c,0x00,0x80,0x12 == mov w12, #-1 ; operands[1].type: IMM = 0xffffffffffffffff

0xb8,0x00,0x00,0x00,0x00 == movl $0, %eax

!# issue 1456
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_SYNTAX_ATT
0xb8,0x00,0x00,0x00,0x00 == movl $0, %eax

0xd1,0x5e,0x48 == rcrl $1, 0x48(%esi)

!# issue 1456
!# CS_ARCH_X86, CS_MODE_32, None
0xd1,0x5e,0x48 == rcr dword ptr [esi + 0x48], 1

!# issue 1456
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_SYNTAX_ATT
0xd1,0x5e,0x48 == rcrl $1, 0x48(%esi)

!# issue 1456
!# CS_ARCH_X86, CS_MODE_32, None
0x62,0x00 == bound eax, qword ptr [eax]

!# issue 1454
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_DETAIL
0xf0,0x0f,0xb1,0x1e == lock cmpxchg dword ptr [esi], ebx ; Registers read: eax esi ebx

!# issue 1452
!# CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_OPT_DETAIL
0x20,0x3c,0x0c,0x0e == mov w0, v1.s[1] ; operands[1].vas: 0xb

!# issue 1452
!# CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_OPT_DETAIL
0x20,0x3c,0x18,0x4e == mov x0, v1.d[1] ; operands[1].vas: 0xd

!# issue 1452
!# CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_OPT_DETAIL
0x20,0x3c,0x03,0x0e == umov w0, v1.b[1] ; operands[1].vas: 0x4

!# issue 1452
!# CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_OPT_DETAIL
0x20,0x3c,0x06,0x0e == umov w0, v1.h[1] ; operands[1].vas: 0x8

!# issue 1211
!# CS_ARCH_X86, CS_MODE_64, None
0xc4,0xe1,0xf8,0x90,0xc0 == kmovq k0, k0

!# issue 1211
!# CS_ARCH_X86, CS_MODE_64, None
0xc4,0xe1,0xfb,0x92,0xc3 == kmovq k0, rbx

!# issue 1211
!# CS_ARCH_X86, CS_MODE_64, None
0x62,0xf1,0x7d,0x48,0x74,0x83,0x12,0x00,0x00,0x00 == vpcmpeqb k0, zmm0, zmmword ptr [rbx + 0x12]

!# issue 1211
!# CS_ARCH_X86, CS_MODE_64, None
0x62,0xf2,0x7d,0x48,0x30,0x43,0x08 == vpmovzxbw zmm0, ymmword ptr [rbx + 0x100]

!# issue x86 BND register (OSS-fuzz #13467)
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_DETAIL
0x0f,0x1a,0x1a == bndldx bnd3, [edx] ; operands[0].type: REG = bnd3

!# issue 1335
!# CS_ARCH_X86, CS_MODE_32, None
0x0f,0x1f,0xc0 == nop eax

!# issue 1335
!# CS_ARCH_X86, CS_MODE_64, None
0x48,0x0f,0x1f,0x00 == nop qword ptr [rax]

!# issue 1259
!# CS_ARCH_X86, CS_MODE_64, None
0x0f,0x0d,0x44,0x11,0x40 == prefetch byte ptr [rcx + rdx + 0x40]

!# issue 1259
!# CS_ARCH_X86, CS_MODE_64, None
0x41,0x0f,0x0d,0x44,0x12,0x40 == prefetch byte ptr [r10 + rdx + 0x40]

!# issue 1304
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
0x66,0x0f,0x7f,0x4c,0x24,0x40 == movdqa xmmword ptr [rsp + 0x40], xmm1 ; operands[0].access: WRITE

!# issue 1304
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
0x66,0x0f,0x7e,0x04,0x24 == movd dword ptr [rsp], xmm0 ; operands[0].access: WRITE

!# issue 1304
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
0xf3,0x41,0x0f,0x7f,0x4d,0x00 == movdqu xmmword ptr [r13], xmm1 ; operands[0].access: WRITE

!# issue 1346
!# CS_ARCH_X86, CS_MODE_64, None
0xf3,0x48,0x0f,0x1e,0xc8 == rdsspq rax

!# issue 1346
!# CS_ARCH_X86, CS_MODE_64, None
0xf3,0x0f,0x1e,0xc8 == rdsspd eax

!# issue 1346
!# CS_ARCH_X86, CS_MODE_64, None
0xf3,0x48,0x0f,0xae,0xe8 == incsspq rax

!# issue 1346
!# CS_ARCH_X86, CS_MODE_64, None
0xf3,0x0f,0xae,0xe8 == incsspd eax

!# issue 1346
!# CS_ARCH_X86, CS_MODE_64, None
0xf3,0x0f,0x01,0xea == saveprevssp

!# issue 1346
!# CS_ARCH_X86, CS_MODE_64, None
0xf3,0x0f,0x01,0x28 == rstorssp dword ptr [rax]

!# issue 1346
!# CS_ARCH_X86, CS_MODE_64, None
0x67,0xf3,0x0f,0x01,0x28 == rstorssp dword ptr [eax]

!# issue 1346
!# CS_ARCH_X86, CS_MODE_64, None
0x48,0x0f,0x38,0xf6,0x00 == wrssq qword ptr [rax], rax

!# issue 1346
!# CS_ARCH_X86, CS_MODE_64, None
0x67,0x0f,0x38,0xf6,0x00 == wrssd dword ptr [eax], eax

!# issue 1346
!# CS_ARCH_X86, CS_MODE_64, None
0xf3,0x0f,0x01,0xe8 == setssbsy

!# issue 1346
!# CS_ARCH_X86, CS_MODE_64, None
0xf3,0x0f,0xae,0x30 == clrssbsy dword ptr [rax]

!# issue 1346
!# CS_ARCH_X86, CS_MODE_64, None
0x67,0xf3,0x0f,0xae,0x30 == clrssbsy dword ptr [eax]

!# issue 1206
!# CS_ARCH_X86, CS_MODE_64, None
0xc4,0xe2,0x7d,0x5a,0x0c,0x0e == vbroadcasti128 ymm1, xmmword ptr [rsi + rcx]

!# issue xchg 16bit
!# CS_ARCH_X86, CS_MODE_16, None
0x91 == xchg cx, ax

!# issue ROL 1, ATT syntax
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT
0x66,0x48,0xf3,0xd1,0xc0 == rolw $1, %ax

!# issue 1129
!# CS_ARCH_X86, CS_MODE_64, None
0xf3,0x0f,0x1e,0xfa == endbr64

!# issue 1129
!# CS_ARCH_X86, CS_MODE_32, None
0xf3,0x0f,0x1e,0xfa == endbr64

!# issue 1129
!# CS_ARCH_X86, CS_MODE_64, None
0xf3,0x0f,0x1e,0xfb == endbr32

!# issue 1129
!# CS_ARCH_X86, CS_MODE_32, None
0xf3,0x0f,0x1e,0xfb == endbr32

!# issue x64 jmp
!# CS_ARCH_X86, CS_MODE_64, None
0x1000: 0xeb,0xfe == jmp 0x1000

!# issue x64att jmp
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT
0x1000: 0xeb,0xfe == jmp 0x1000

!# issue x32 jmp
!# CS_ARCH_X86, CS_MODE_32, None
0x1000: 0xeb,0xfe == jmp 0x1000

!# issue x32att jmp
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_SYNTAX_ATT
0x1000: 0xeb,0xfe == jmp 0x1000

!# issue 1389
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
0x66,0x0f,0x73,0xf9,0x01 == pslldq xmm1, 1 ; operands[1].size: 1

!# issue 1389
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT | CS_OPT_DETAIL
0x66,0x0f,0x73,0xf9,0x01 == pslldq $1, %xmm1 ; operands[0].size: 1

!# issue x64 unsigned
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_UNSIGNED
0x66,0x83,0xc0,0x80 == add ax, 0xff80

!# issue x64att unsigned
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT | CS_OPT_UNSIGNED
0x66,0x83,0xc0,0x80 == addw $0xff80, %ax

!# issue 1323
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0x0: 0x70,0x47,0x00 == bx lr ; op_count: 1 ; operands[0].type: REG = lr ; operands[0].access: READ ; Registers read: lr ; Registers modified: pc ; Groups: thumb jump 

!# issue 1317
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0x0: 0xd0,0xe8,0x11,0xf0 == tbh [r0, r1, lsl #1] ; op_count: 1 ; operands[0].type: MEM ; operands[0].mem.base: REG = r0 ; operands[0].mem.index: REG = r1 ; operands[0].mem.lshift: 0x1 ; operands[0].access: READ ; Shift: 2 = 1 ; Registers read: r0 r1 ; Groups: thumb2 jump 

!# issue 1308
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
0x0: 0x83,0x3d,0xa1,0x75,0x21,0x00,0x04 == cmp dword ptr [rip + 0x2175a1], 4 ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0x83 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 8 ; modrm: 0x3d ; disp: 0x2175a1 ; sib: 0x0 ; imm_count: 1 ; imms[1]: 0x4 ; op_count: 2 ; operands[0].type: MEM ; operands[0].mem.base: REG = rip ; operands[0].mem.disp: 0x2175a1 ; operands[0].size: 4 ; operands[0].access: READ ; operands[1].type: IMM = 0x4 ; operands[1].size: 4 ; Registers read: rip ; Registers modified: rflags ; EFLAGS: MOD_AF MOD_CF MOD_SF MOD_ZF MOD_PF MOD_OF

!# issue 1262
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
0x0: 0x0f,0x95,0x44,0x24,0x5e == setne byte ptr [rsp + 0x5e] ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0x0f 0x95 0x00 0x00  ; rex: 0x0 ; addr_size: 8 ; modrm: 0x44 ; disp: 0x5e ; sib: 0x24 ; sib_base: rsp ; sib_scale: 1 ; op_count: 1 ; operands[0].type: MEM ; operands[0].mem.base: REG = rsp ; operands[0].mem.disp: 0x5e ; operands[0].size: 1 ; operands[0].access: WRITE ; Registers read: rflags rsp ; EFLAGS: TEST_ZF

!# issue 1262
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
0x0: 0x0f,0x94,0x44,0x24,0x1f == sete byte ptr [rsp + 0x1f] ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0x0f 0x94 0x00 0x00  ; rex: 0x0 ; addr_size: 8 ; modrm: 0x44 ; disp: 0x1f ; sib: 0x24 ; sib_base: rsp ; sib_scale: 1 ; op_count: 1 ; operands[0].type: MEM ; operands[0].mem.base: REG = rsp ; operands[0].mem.disp: 0x1f ; operands[0].size: 1 ; operands[0].access: WRITE ; Registers read: rflags rsp ; EFLAGS: TEST_ZF

!# issue 1263
!# CS_ARCH_X86, CS_MODE_64, None
0x0: 0x67,0x48,0x89,0x18 == mov qword ptr [eax], rbx

!# issue 1263
!# CS_ARCH_X86, CS_MODE_64, None
0x0: 0x67,0x48,0x8b,0x03 == mov rax, qword ptr [ebx]

!# issue 1255
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
0x0: 0xdb,0x7c,0x24,0x40 == fstp xword ptr [rsp + 0x40] ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0xdb 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 8 ; modrm: 0x7c ; disp: 0x40 ; sib: 0x24 ; sib_base: rsp ; sib_scale: 1 ; op_count: 1 ; operands[0].type: MEM ; operands[0].mem.base: REG = rsp ; operands[0].mem.disp: 0x40 ; operands[0].size: 10 ; operands[0].access: WRITE ; Registers read: rsp ; Registers modified: fpsw ; FPU_FLAGS: MOD_C1 UNDEF_C0 UNDEF_C2 UNDEF_C3 ; Groups: fpu 

!# issue 1255
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
0x0: 0xdd,0xd9 == fstp st(1) ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0xdd 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 8 ; modrm: 0xd9 ; disp: 0x0 ; sib: 0x0 ; op_count: 1 ; operands[0].type: REG = st(1) ; operands[0].size: 10 ; operands[0].access: WRITE ; Registers modified: fpsw st(1) ; EFLAGS: MOD_CF PRIOR_SF PRIOR_AF PRIOR_PF

!# issue 1255
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
0x0: 0xdf,0x7c,0x24,0x68 == fistp qword ptr [rsp + 0x68] ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0xdf 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 8 ; modrm: 0x7c ; disp: 0x68 ; sib: 0x24 ; sib_base: rsp ; sib_scale: 1 ; op_count: 1 ; operands[0].type: MEM ; operands[0].mem.base: REG = rsp ; operands[0].mem.disp: 0x68 ; operands[0].size: 8 ; operands[0].access: WRITE ; Registers read: rsp ; Registers modified: fpsw ; FPU_FLAGS: RESET_C1 UNDEF_C0 UNDEF_C2 UNDEF_C3 ; Groups: fpu 

!# issue 1221
!# CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN, None
0x0: 0x55,0x48,0x89,0xe5 == call 0x55222794

!# issue 1144
!# CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, None
0x0: 0x00,0x00,0x02,0xb6 == tbz x0, #0x20, #0x4000

!# issue 1144
!# CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, None
0x0: 0x00,0x00,0x04,0xb6 == tbz x0, #0x20, #0xffffffffffff8000

!# issue 1144
!# CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, None
0x0: 0x00,0x00,0x02,0xb7 == tbnz x0, #0x20, #0x4000

!# issue 1144
!# CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, None
0x0: 0x00,0x00,0x04,0xb7 == tbnz x0, #0x20, #0xffffffffffff8000

!# issue 826
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x0: 0x0b,0x00,0x00,0x0a == beq #0x34 ; op_count: 1 ; operands[0].type: IMM = 0x34 ; Code condition: 1 ; Registers read: pc ; Registers modified: pc ; Groups: branch_relative arm jump 

!# issue 1047
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT
0x0: 0x48,0x83,0xe4,0xf0 == andq $0xfffffffffffffff0, %rsp

!# issue 959
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xa0,0x28,0x57,0x88,0x7c == mov al, byte ptr [0x7c885728]

!# issue 950
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_DETAIL
0x0: 0x66,0xa3,0x94,0x90,0x04,0x08 == mov word ptr [0x8049094], ax ; Prefix:0x00 0x00 0x66 0x00  ; Opcode:0xa3 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 4 ; modrm: 0x0 ; disp: 0x8049094 ; sib: 0x0 ; op_count: 2 ; operands[0].type: MEM ; operands[0].mem.disp: 0x8049094 ; operands[0].size: 2 ; operands[0].access: WRITE ; operands[1].type: REG = ax ; operands[1].size: 2 ; operands[1].access: READ ; Registers read: ax

!# issue 938
!# CS_ARCH_MIPS, CS_MODE_MIPS64+CS_MODE_LITTLE_ENDIAN, None
0x0: 0x70,0x00,0xb2,0xff == sd $s2, 0x70($sp)

!# issue 915
!# CS_ARCH_X86, CS_MODE_64, None
0x0: 0xf0,0x0f,0x1f,0x00 == lock nop dword ptr [rax]

// !# issue 913
// !# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x0: 0x04,0x10,0x9d,0xe4 == pop {r1} ; op_count: 1 ; operands[0].type: REG = r1 ; operands[0].access: WRITE ; Write-back: True ; Registers read: sp ; Registers modified: sp r1 ; Groups: arm 

!# issue 884
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT
0x0: 0x64,0x48,0x03,0x04,0x25,0x00,0x00,0x00,0x00 == addq %fs:0, %rax

!# issue 872
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xf2,0xeb,0x3e == bnd jmp 0x41

!# issue 861
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x0: 0x01,0x81,0xa0,0xfc == stc2 p1, c8, [r0], #4 ; op_count: 4 ; operands[0].type: P-IMM = 1 ; operands[1].type: C-IMM = 8 ; operands[2].type: MEM ; operands[2].mem.base: REG = r0 ; operands[2].access: READ ; operands[3].type: IMM = 0x4 ; Write-back: True ; Registers read: r0 ; Registers modified: r0 ; Groups: prev8 

!# issue 852
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_DETAIL
0x0: 0x64,0xa3,0x00,0x00,0x00,0x00 == mov dword ptr fs:[0], eax ; Prefix:0x00 0x64 0x00 0x00  ; Opcode:0xa3 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 4 ; modrm: 0x0 ; disp: 0x0 ; sib: 0x0 ; op_count: 2 ; operands[0].type: MEM ; operands[0].mem.segment: REG = fs ; operands[0].size: 4 ; operands[0].access: WRITE ; operands[1].type: REG = eax ; operands[1].size: 4 ; operands[1].access: READ ; Registers read: fs eax

!# issue 825
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x0: 0x0e,0xf0,0xa0,0xe1 == mov pc, lr ; op_count: 2 ; operands[0].type: REG = pc ; operands[0].access: WRITE ; operands[1].type: REG = lr ; operands[1].access: READ ; Registers read: lr ; Registers modified: pc ; Groups: arm 

!# issue 813
!# CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_BIG_ENDIAN, None
0x0: 0xF6,0xC0,0x04,0x01 == movt r4, #0x801

!# issue 809
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
0x0: 0x0f,0x29,0x8d,0xf0,0xfd,0xff,0xff == movaps xmmword ptr [rbp - 0x210], xmm1 ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0x0f 0x29 0x00 0x00  ; rex: 0x0 ; addr_size: 8 ; modrm: 0x8d ; disp: 0xfffffffffffffdf0 ; sib: 0x0 ; op_count: 2 ; operands[0].type: MEM ; operands[0].mem.base: REG = rbp ; operands[0].mem.disp: 0xfffffffffffffdf0 ; operands[0].size: 16 ; operands[0].access: WRITE ; operands[1].type: REG = xmm1 ; operands[1].size: 16 ; operands[1].access: READ ; Registers read: rbp xmm1 ; Groups: sse1 

!# issue 807
!# CS_ARCH_X86, CS_MODE_64, None
0x0: 0x4c,0x0f,0x00,0x80,0x16,0x76,0x8a,0xfe == sldt word ptr [rax - 0x17589ea]

!# issue 806
!# CS_ARCH_X86, CS_MODE_64, None
0x0: 0x0f,0x35 == sysexit 

!# issue 805
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT
0x0: 0x48,0x4c,0x0f,0xb5,0x80,0x16,0x76,0x8a,0xfe == lgs -0x17589ea(%rax), %r8

!# issue 804
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT
0x0: 0x66,0x48,0xf3,0xd1,0xc0 == rolw $1, %ax

!# issue 789
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT
0x0: 0x8e,0x1e == movw (%rsi), %ds

!# issue 767
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0x0: 0xb1,0xe8,0xfc,0x07 == ldm.w r1!, {r2, r3, r4, r5, r6, r7, r8, sb, sl} ; op_count: 10 ; operands[0].type: REG = r1 ; operands[0].access: READ | WRITE ; operands[1].type: REG = r2 ; operands[1].access: WRITE ; operands[2].type: REG = r3 ; operands[2].access: WRITE ; operands[3].type: REG = r4 ; operands[3].access: WRITE ; operands[4].type: REG = r5 ; operands[4].access: WRITE ; operands[5].type: REG = r6 ; operands[5].access: WRITE ; operands[6].type: REG = r7 ; operands[6].access: WRITE ; operands[7].type: REG = r8 ; operands[7].access: WRITE ; operands[8].type: REG = sb ; operands[8].access: WRITE ; operands[9].type: REG = sl ; operands[9].access: WRITE ; Write-back: True ; Registers read: r1 ; Registers modified: r1 r2 r3 r4 r5 r6 r7 r8 sb sl ; Groups: thumb2 

!# issue 760
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x0: 0x02,0x80,0xbd,0xe8 == pop {r1, pc} ; op_count: 2 ; operands[0].type: REG = r1 ; operands[0].access: WRITE ; operands[1].type: REG = pc ; operands[1].access: WRITE ; Registers read: sp ; Registers modified: sp r1 pc ; Groups: arm 

!# issue 750
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x0: 0x0e,0x00,0x20,0xe9 == stmdb r0!, {r1, r2, r3} ; op_count: 4 ; operands[0].type: REG = r0 ; operands[0].access: READ ; operands[1].type: REG = r1 ; operands[2].type: REG = r2 ; operands[3].type: REG = r3 ; Write-back: True ; Registers read: r0 ; Groups: arm

!# issue 747
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x0: 0x0e,0x00,0xb0,0xe8 == ldm r0!, {r1, r2, r3} ; op_count: 4 ; operands[0].type: REG = r0 ; operands[0].access: READ | WRITE ; operands[1].type: REG = r1 ; operands[1].access: WRITE ; operands[2].type: REG = r2 ; operands[2].access: WRITE ; operands[3].type: REG = r3 ; operands[3].access: WRITE ; Write-back: True ; Registers read: r0 ; Registers modified: r0 r1 r2 r3 ; Groups: arm 

!# issue 747
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0x0: 0x0e,0xc8 == ldm r0!, {r1, r2, r3} ; op_count: 4 ; operands[0].type: REG = r0 ; operands[0].access: READ | WRITE ; operands[1].type: REG = r1 ; operands[1].access: WRITE ; operands[2].type: REG = r2 ; operands[2].access: WRITE ; operands[3].type: REG = r3 ; operands[3].access: WRITE ; Write-back: True ; Registers read: r0 ; Registers modified: r0 r1 r2 r3 ; Groups: thumb thumb1only 

!# issue 746
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x0: 0x89,0x00,0x2d,0xe9 == push {r0, r3, r7} ; op_count: 3 ; operands[0].type: REG = r0 ; operands[0].access: READ ; operands[1].type: REG = r3 ; operands[1].access: READ ; operands[2].type: REG = r7 ; operands[2].access: READ ; Registers read: sp r0 r3 r7 ; Registers modified: sp ; Groups: arm 

!# issue 744
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x0: 0x02,0x80,0xbd,0xe8 == pop {r1, pc} ; op_count: 2 ; operands[0].type: REG = r1 ; operands[0].access: WRITE ; operands[1].type: REG = pc ; operands[1].access: WRITE ; Registers read: sp ; Registers modified: sp r1 pc ; Groups: arm 

!# issue 741
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0x83,0xff,0xf7 == cmp edi, -9

!# issue 717
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT
0x0: 0x48,0x8b,0x04,0x25,0x00,0x00,0x00,0x00 == movq 0, %rax

!# issue 711
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_DETAIL
0x0: 0xa3,0x44,0xb0,0x00,0x10 == mov dword ptr [0x1000b044], eax ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0xa3 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 4 ; modrm: 0x0 ; disp: 0x1000b044 ; sib: 0x0 ; op_count: 2 ; operands[0].type: MEM ; operands[0].mem.disp: 0x1000b044 ; operands[0].size: 4 ; operands[0].access: WRITE ; operands[1].type: REG = eax ; operands[1].size: 4 ; operands[1].access: READ ; Registers read: eax

!# issue 613
!# CS_ARCH_X86, CS_MODE_64, None
0x0: 0xd9,0x74,0x24,0xd8 == fnstenv [rsp - 0x28]

!# issue 554
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xe7,0x84 == out 0x84, eax

!# issue 554
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xe5,0x8c == in eax, 0x8c

!# issue 545
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_DETAIL
0x0: 0x95 == xchg ebp, eax ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0x95 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 4 ; modrm: 0x0 ; disp: 0x0 ; sib: 0x0 ; op_count: 2 ; operands[0].type: REG = ebp ; operands[0].size: 4 ; operands[0].access: READ | WRITE ; operands[1].type: REG = eax ; operands[1].size: 4 ; operands[1].access: READ | WRITE ; Registers read: ebp eax ; Registers modified: ebp eax ; Groups: not64bitmode 

!# issue 544
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xdf,0x30 == fbstp tbyte ptr [eax]

!# issue 544
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xdf,0x20 == fbld tbyte ptr [eax]

!# issue 541
!# CS_ARCH_X86, CS_MODE_64, None
0x0: 0x48,0xb8,0x00,0x00,0x00,0x00,0x80,0xf8,0xff,0xff == movabs rax, 0xfffff88000000000

!# issue 499
!# CS_ARCH_X86, CS_MODE_64, None
0x0: 0x48,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80 == movabs rax, 0x8000000000000000

!# issue 492
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xff,0x18 == call ptr [eax]

!# issue 492
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xff,0x28 == jmp ptr [eax]

!# issue 492
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0x0f,0xae,0x04,0x24 == fxsave [esp]

!# issue 492
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0x0f,0xae,0x0c,0x24 == fxrstor [esp]

!# issue 470
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0x0f,0x01,0x05,0xa0,0x90,0x04,0x08 == sgdt [0x80490a0]

!# issue 470
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0x0f,0x01,0x0d,0xa7,0x90,0x04,0x08 == sidt [0x80490a7]

!# issue 470
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0x0f,0x01,0x15,0xa0,0x90,0x04,0x08 == lgdt [0x80490a0]

!# issue 470
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0x0f,0x01,0x1d,0xa7,0x90,0x04,0x08 == lidt [0x80490a7]

!# issue 459
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
0x0: 0xd3,0x20,0x11,0xe1 == ldrsb r2, [r1, -r3] ; op_count: 2 ; operands[0].type: REG = r2 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = r1 ; operands[1].mem.index: REG = r3 ; operands[1].mem.scale: -1 ; Subtracted: True ; Registers read: r1 r3 ; Registers modified: r2 ; Groups: arm 

!# issue 456
!# CS_ARCH_X86, CS_MODE_16, None
0x0: 0xe8,0x35,0x64 == call 0x6438

!# issue 456
!# CS_ARCH_X86, CS_MODE_16, None
0x0: 0xe9,0x35,0x64 == jmp 0x6438

!# issue 456
!# CS_ARCH_X86, CS_MODE_16, None
0x0: 0x66,0xe9,0x35,0x64,0x93,0x53 == jmp 0x5393643b

!# issue 456
!# CS_ARCH_X86, CS_MODE_16, None
0x0: 0x66,0xe8,0x35,0x64,0x93,0x53 == call 0x5393643b

!# issue 456
!# CS_ARCH_X86, CS_MODE_16, None
0x0: 0x66,0xe9,0x35,0x64,0x93,0x53 == jmp 0x5393643b

!# issue 456
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0x66,0xe8,0x35,0x64 == call 0x6439

!# issue 456
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xe9,0x35,0x64,0x93,0x53 == jmp 0x5393643a

!# issue 456
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0x66,0xe9,0x35,0x64 == jmp 0x6439

!# issue 458
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_DETAIL
0x0: 0xA1,0x12,0x34,0x90,0x90 == mov eax, dword ptr [0x90903412] ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0xa1 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 4 ; modrm: 0x0 ; disp: 0x90903412 ; sib: 0x0 ; op_count: 2 ; operands[0].type: REG = eax ; operands[0].size: 4 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.disp: 0x90903412 ; operands[1].size: 4 ; operands[1].access: READ ; Registers modified: eax

!# issue 454
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xf2,0x6c == repne insb byte ptr es:[edi], dx

!# issue 454
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xf2,0x6d == repne insd dword ptr es:[edi], dx

!# issue 454
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xf2,0x6e == repne outsb dx, byte ptr [esi]

!# issue 454
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xf2,0x6f == repne outsd dx, dword ptr [esi]

!# issue 454
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xf2,0xac == repne lodsb al, byte ptr [esi]

!# issue 454
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xf2,0xad == repne lodsd eax, dword ptr [esi]

!# issue 450
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_DETAIL
0x0: 0xff,0x2d,0x34,0x35,0x23,0x01 == jmp ptr [0x1233534] ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0xff 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 4 ; modrm: 0x2d ; disp: 0x1233534 ; sib: 0x0 ; op_count: 1 ; operands[0].type: MEM ; operands[0].mem.disp: 0x1233534 ; operands[0].size: 6 ; Groups: jump 

!# issue 448
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_DETAIL
0x0: 0xea,0x12,0x34,0x56,0x78,0x9a,0xbc == ljmp 0xbc9a:0x78563412 ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0xea 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 4 ; modrm: 0x0 ; disp: 0x0 ; sib: 0x0 ; imm_count: 2 ; imms[1]: 0xbc9a ; imms[2]: 0x78563412 ; op_count: 2 ; operands[0].type: IMM = 0xbc9a ; operands[0].size: 2 ; operands[1].type: IMM = 0x78563412 ; operands[1].size: 4 ; Groups: not64bitmode jump 

!# issue 426
!# CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN, None
0x0: 0xbb,0x70,0x00,0x00 == popc %g0, %i5

!# issue 358
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_DETAIL
0x0: 0xe8,0xe3,0xf6,0xff,0xff == call 0xfffff6e8 ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0xe8 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 4 ; modrm: 0x0 ; disp: 0x0 ; sib: 0x0 ; imm_count: 1 ; imms[1]: 0xfffff6e8 ; op_count: 1 ; operands[0].type: IMM = 0xfffff6e8 ; operands[0].size: 4 ; Registers read: esp eip ; Registers modified: esp ; Groups: call branch_relative not64bitmode 

!# issue 353
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_DETAIL
0x0: 0xe6,0xa2 == out 0xa2, al ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0xe6 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 4 ; modrm: 0x0 ; disp: 0x0 ; sib: 0x0 ; imm_count: 1 ; imms[1]: 0xa2 ; op_count: 2 ; operands[0].type: IMM = 0xa2 ; operands[0].size: 1 ; operands[1].type: REG = al ; operands[1].size: 1 ; operands[1].access: READ ; Registers read: al

!# issue 305
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0x34,0x8b == xor al, 0x8b

!# issue 298
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xf3,0x90 == pause 

!# issue 298
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0x66,0xf3,0xf2,0x0f,0x59,0xff == mulsd xmm7, xmm7

// !# issue 298
// !# CS_ARCH_X86, CS_MODE_32, None
// 0x0: 0xf2,0x66,0x0f,0x59,0xff == mulpd xmm7, xmm7

!# issue 294
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_DETAIL
0x0: 0xc1,0xe6,0x08 == shl esi, 8 ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0xc1 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 4 ; modrm: 0xe6 ; disp: 0x0 ; sib: 0x0 ; imm_count: 1 ; imms[1]: 0x8 ; op_count: 2 ; operands[0].type: REG = esi ; operands[0].size: 4 ; operands[0].access: READ | WRITE ; operands[1].type: IMM = 0x8 ; operands[1].size: 1 ; Registers read: esi ; Registers modified: eflags esi ; EFLAGS: MOD_CF MOD_SF MOD_ZF MOD_PF MOD_OF UNDEF_AF

!# issue 285
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_DETAIL
0x0: 0x3c,0x12,0x80 == cmp al, 0x12 ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0x3c 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 4 ; modrm: 0x0 ; disp: 0x0 ; sib: 0x0 ; imm_count: 1 ; imms[1]: 0x12 ; op_count: 2 ; operands[0].type: REG = al ; operands[0].size: 1 ; operands[0].access: READ ; operands[1].type: IMM = 0x12 ; operands[1].size: 1 ; Registers read: al ; Registers modified: eflags ; EFLAGS: MOD_AF MOD_CF MOD_SF MOD_ZF MOD_PF MOD_OF

!# issue 265
!# CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
0x0: 0x52,0xf8,0x23,0x30 == ldr.w r3, [r2, r3, lsl #2] ; op_count: 2 ; operands[0].type: REG = r3 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = r2 ; operands[1].mem.index: REG = r3 ; operands[1].access: READ ; Shift: 2 = 2 ; Registers read: r2 r3 ; Registers modified: r3 ; Groups: thumb2 

!# issue 264
!# CS_ARCH_ARM, CS_MODE_THUMB, None
0x0: 0x0c,0xbf == ite eq

!# issue 264
!# CS_ARCH_ARM, CS_MODE_THUMB, None
0x0: 0x17,0x20 == movs r0, #0x17

!# issue 264
!# CS_ARCH_ARM, CS_MODE_THUMB, None
0x0: 0x4f,0xf0,0xff,0x30 == mov.w r0, #-1

!# issue 246
!# CS_ARCH_ARM, CS_MODE_THUMB, None
0x0: 0x52,0xf8,0x23,0xf0 == ldr.w pc, [r2, r3, lsl #2]

!# issue 232
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_DETAIL
0x0: 0x8e,0x10 == mov ss, word ptr [eax] ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0x8e 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 4 ; modrm: 0x10 ; disp: 0x0 ; sib: 0x0 ; op_count: 2 ; operands[0].type: REG = ss ; operands[0].size: 2 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = eax ; operands[1].size: 2 ; operands[1].access: READ ; Registers read: eax ; Registers modified: ss ; Groups: privilege 

!# issue 231
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_DETAIL
0x0: 0x66,0x6b,0xc0,0x02 == imul ax, ax, 2 ; Prefix:0x00 0x00 0x66 0x00  ; Opcode:0x6b 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 4 ; modrm: 0xc0 ; disp: 0x0 ; sib: 0x0 ; imm_count: 1 ; imms[1]: 0x2 ; op_count: 3 ; operands[0].type: REG = ax ; operands[0].size: 2 ; operands[0].access: WRITE ; operands[1].type: REG = ax ; operands[1].size: 2 ; operands[1].access: READ ; operands[2].type: IMM = 0x2 ; operands[2].size: 2 ; Registers read: ax ; Registers modified: eflags ax ; EFLAGS: MOD_CF MOD_SF MOD_OF UNDEF_ZF UNDEF_PF UNDEF_AF

!# issue 230
!# CS_ARCH_X86, CS_MODE_32, CS_OPT_DETAIL
0x0: 0xec == in al, dx ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0xec 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 4 ; modrm: 0x0 ; disp: 0x0 ; sib: 0x0 ; op_count: 2 ; operands[0].type: REG = al ; operands[0].size: 1 ; operands[0].access: WRITE ; operands[1].type: REG = dx ; operands[1].size: 2 ; operands[1].access: READ ; Registers read: dx ; Registers modified: al

!# issue 213
!# CS_ARCH_X86, CS_MODE_16, None
0x0: 0xea,0xaa,0xff,0x00,0xf0 == ljmp 0xf000:0xffaa

!# issue 191
!# CS_ARCH_X86, CS_MODE_64, None
0x0: 0xc5,0xe8,0xc2,0x33,0x9b == vcmpps xmm6, xmm2, xmmword ptr [rbx], 0x9b

!# issue 176
!# CS_ARCH_ARM, CS_MODE_ARM, None
0x0: 0xfd,0xff,0xff,0x1a == bne #0xfffffffc

!# issue 151
!# CS_ARCH_X86, CS_MODE_64, None
0x0: 0x4d,0x8d,0x3d,0x02,0x00,0x00,0x00 == lea r15, [rip + 2]

!# issue 151
!# CS_ARCH_X86, CS_MODE_64, None
0x0: 0xeb,0xb0 == jmp 0xffffffffffffffb2

!# issue 134
!# CS_ARCH_ARM, CS_MODE_BIG_ENDIAN, CS_OPT_DETAIL
0x0: 0xe7,0x92,0x11,0x80 == ldr r1, [r2, r0, lsl #3] ; op_count: 2 ; operands[0].type: REG = r1 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = r2 ; operands[1].mem.index: REG = r0 ; operands[1].access: READ ; Shift: 2 = 3 ; Registers read: r2 r0 ; Registers modified: r1 ; Groups: arm 

!# issue 133
!# CS_ARCH_ARM, CS_MODE_BIG_ENDIAN, CS_OPT_DETAIL
0x0: 0xed,0xdf,0x2b,0x1b == vldr d18, [pc, #0x6c] ; op_count: 2 ; operands[0].type: REG = d18 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = pc ; operands[1].mem.disp: 0x6c ; operands[1].access: READ ; Registers read: pc ; Registers modified: d18 ; Groups: vfp2 

!# issue 132
!# CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_BIG_ENDIAN, CS_OPT_DETAIL
0x0: 0x49,0x19 == ldr r1, [pc, #0x64] ; op_count: 2 ; operands[0].type: REG = r1 ; operands[0].access: WRITE ; operands[1].type: MEM ; operands[1].mem.base: REG = pc ; operands[1].mem.disp: 0x64 ; operands[1].access: READ ; Registers read: pc ; Registers modified: r1 ; Groups: thumb thumb1only 

!# issue 130
!# CS_ARCH_ARM, CS_MODE_BIG_ENDIAN, CS_OPT_DETAIL
0x0: 0xe1,0xa0,0xf0,0x0e == mov pc, lr ; op_count: 2 ; operands[0].type: REG = pc ; operands[0].access: WRITE ; operands[1].type: REG = lr ; operands[1].access: READ ; Registers read: lr ; Registers modified: pc ; Groups: arm 

!# issue 85
!# CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, None
0x0: 0xee,0x3f,0xbf,0x29 == stp w14, w15, [sp, #-8]!

!# issue 82
!# CS_ARCH_X86, CS_MODE_64, None
0x0: 0xf2,0x66,0xaf == repne scasw ax, word ptr [rdi]

!# issue 35
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xe8,0xc6,0x02,0x00,0x00 == call 0x2cb

!# issue 8
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xff,0x8c,0xf9,0xff,0xff,0x9b,0xf9 == dec dword ptr [ecx + edi*8 - 0x6640001]

!# issue 29
!# CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, None
0x0: 0x00,0x00,0x00,0x4c == st4 {v0.16b, v1.16b, v2.16b, v3.16b}, [x0]

