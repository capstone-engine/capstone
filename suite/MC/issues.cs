!#CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB, CS_OPT_DETAIL
!#1323
0x70,0x47,0x00 = bx	lr | 1 | REG | lr | READ | lr | pc | | thumb, jump
!#CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_OPT_DETAIL
!#1318
0x00,0xd0,0xe8,0x11,0xf0 = tbh	[r0, r1, lsl #1] | 1 | MEM | r0, r1, 0x1, READ, 2_1 | r0, r1 | thumb2, jump
!#