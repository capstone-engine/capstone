!# issue 0
!# CS_ARCH_X86, CS_MODE_64, CS_OPT_UNSIGNED
0x66,0x83,0xc0,0x80 == add ax, 0xff80

!# issue 0
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

!# issue 913
!# CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_DETAIL
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
0x0: 0x66,0x48,0xf3,0xd1,0xc0 == rol $1, %ax

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
0x0: 0x95 == xchg eax, ebp ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0x95 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 4 ; modrm: 0x0 ; disp: 0x0 ; sib: 0x0 ; op_count: 2 ; operands[0].type: REG = eax ; operands[0].size: 4 ; operands[0].access: READ | WRITE ; operands[1].type: REG = ebp ; operands[1].size: 4 ; operands[1].access: READ | WRITE ; Registers read: eax ebp ; Registers modified: eax ebp ; Groups: not64bitmode 

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
0x0: 0xff,0x18 == lcall [eax]

!# issue 492
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xff,0x28 == ljmp [eax]

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
0x0: 0xff,0x2d,0x34,0x35,0x23,0x01 == ljmp [0x1233534] ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0xff 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 4 ; modrm: 0x2d ; disp: 0x1233534 ; sib: 0x0 ; op_count: 1 ; operands[0].type: MEM ; operands[0].mem.disp: 0x1233534 ; operands[0].size: 6 ; Groups: jump 

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
0x0: 0xe6,0xa2 == out 0xa2, al ; Prefix:0x00 0x00 0x00 0x00  ; Opcode:0xe6 0x00 0x00 0x00  ; rex: 0x0 ; addr_size: 4 ; modrm: 0x0 ; disp: 0x0 ; sib: 0x0 ; imm_count: 1 ; imms[1]: 0xa2 ; op_count: 2 ; operands[0].type: IMM = 0xa2 ; operands[0].size: 4 ; operands[1].type: REG = al ; operands[1].size: 1 ; operands[1].access: READ ; Registers read: al

!# issue 305
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0x34,0x8b == xor al, 0x8b

!# issue 298
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xf3,0x90 == pause 

!# issue 298
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0x66,0xf3,0xf2,0x0f,0x59,0xff == mulsd xmm7, xmm7

!# issue 298
!# CS_ARCH_X86, CS_MODE_32, None
0x0: 0xf2,0x66,0x0f,0x59,0xff == mulpd xmm7, xmm7

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

