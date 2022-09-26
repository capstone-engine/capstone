# CS_ARCH_ARM64, 0, None
0x00,0xd2,0x1b,0xd5 = msr AMCR_EL0, x0
0x60,0xd2,0x1b,0xd5 = msr AMUSERENR_EL0, x0
0x80,0xd2,0x1b,0xd5 = msr AMCNTENCLR0_EL0, x0
0xa0,0xd2,0x1b,0xd5 = msr AMCNTENSET0_EL0, x0
0x00,0xd4,0x1b,0xd5 = msr AMEVCNTR00_EL0, x0
0x20,0xd4,0x1b,0xd5 = msr AMEVCNTR01_EL0, x0
0x40,0xd4,0x1b,0xd5 = msr AMEVCNTR02_EL0, x0
0x60,0xd4,0x1b,0xd5 = msr AMEVCNTR03_EL0, x0
0x00,0xd3,0x1b,0xd5 = msr AMCNTENCLR1_EL0, x0
0x20,0xd3,0x1b,0xd5 = msr AMCNTENSET1_EL0, x0
0x00,0xdc,0x1b,0xd5 = msr AMEVCNTR10_EL0, x0
0x20,0xdc,0x1b,0xd5 = msr AMEVCNTR11_EL0, x0
0x40,0xdc,0x1b,0xd5 = msr AMEVCNTR12_EL0, x0
0x60,0xdc,0x1b,0xd5 = msr AMEVCNTR13_EL0, x0
0x80,0xdc,0x1b,0xd5 = msr AMEVCNTR14_EL0, x0
0xa0,0xdc,0x1b,0xd5 = msr AMEVCNTR15_EL0, x0
0xc0,0xdc,0x1b,0xd5 = msr AMEVCNTR16_EL0, x0
0xe0,0xdc,0x1b,0xd5 = msr AMEVCNTR17_EL0, x0
0x00,0xdd,0x1b,0xd5 = msr AMEVCNTR18_EL0, x0
0x20,0xdd,0x1b,0xd5 = msr AMEVCNTR19_EL0, x0
0x40,0xdd,0x1b,0xd5 = msr AMEVCNTR110_EL0, x0
0x60,0xdd,0x1b,0xd5 = msr AMEVCNTR111_EL0, x0
0x80,0xdd,0x1b,0xd5 = msr AMEVCNTR112_EL0, x0
0xa0,0xdd,0x1b,0xd5 = msr AMEVCNTR113_EL0, x0
0xc0,0xdd,0x1b,0xd5 = msr AMEVCNTR114_EL0, x0
0xe0,0xdd,0x1b,0xd5 = msr AMEVCNTR115_EL0, x0
0x00,0xde,0x1b,0xd5 = msr AMEVTYPER10_EL0, x0
0x20,0xde,0x1b,0xd5 = msr AMEVTYPER11_EL0, x0
0x40,0xde,0x1b,0xd5 = msr AMEVTYPER12_EL0, x0
0x60,0xde,0x1b,0xd5 = msr AMEVTYPER13_EL0, x0
0x80,0xde,0x1b,0xd5 = msr AMEVTYPER14_EL0, x0
0xa0,0xde,0x1b,0xd5 = msr AMEVTYPER15_EL0, x0
0xc0,0xde,0x1b,0xd5 = msr AMEVTYPER16_EL0, x0
0xe0,0xde,0x1b,0xd5 = msr AMEVTYPER17_EL0, x0
0x00,0xdf,0x1b,0xd5 = msr AMEVTYPER18_EL0, x0
0x20,0xdf,0x1b,0xd5 = msr AMEVTYPER19_EL0, x0
0x40,0xdf,0x1b,0xd5 = msr AMEVTYPER110_EL0, x0
0x60,0xdf,0x1b,0xd5 = msr AMEVTYPER111_EL0, x0
0x80,0xdf,0x1b,0xd5 = msr AMEVTYPER112_EL0, x0
0xa0,0xdf,0x1b,0xd5 = msr AMEVTYPER113_EL0, x0
0xc0,0xdf,0x1b,0xd5 = msr AMEVTYPER114_EL0, x0
0xe0,0xdf,0x1b,0xd5 = msr AMEVTYPER115_EL0, x0
0x00,0xd2,0x3b,0xd5 = mrs x0, AMCR_EL0
0x20,0xd2,0x3b,0xd5 = mrs x0, AMCFGR_EL0
0x40,0xd2,0x3b,0xd5 = mrs x0, AMCGCR_EL0
0x60,0xd2,0x3b,0xd5 = mrs x0, AMUSERENR_EL0
0x80,0xd2,0x3b,0xd5 = mrs x0, AMCNTENCLR0_EL0
0xa0,0xd2,0x3b,0xd5 = mrs x0, AMCNTENSET0_EL0
0x00,0xd4,0x3b,0xd5 = mrs x0, AMEVCNTR00_EL0
0x20,0xd4,0x3b,0xd5 = mrs x0, AMEVCNTR01_EL0
0x40,0xd4,0x3b,0xd5 = mrs x0, AMEVCNTR02_EL0
0x60,0xd4,0x3b,0xd5 = mrs x0, AMEVCNTR03_EL0
0x00,0xd6,0x3b,0xd5 = mrs x0, AMEVTYPER00_EL0
0x20,0xd6,0x3b,0xd5 = mrs x0, AMEVTYPER01_EL0
0x40,0xd6,0x3b,0xd5 = mrs x0, AMEVTYPER02_EL0
0x60,0xd6,0x3b,0xd5 = mrs x0, AMEVTYPER03_EL0
0x00,0xd3,0x3b,0xd5 = mrs x0, AMCNTENCLR1_EL0
0x20,0xd3,0x3b,0xd5 = mrs x0, AMCNTENSET1_EL0
0x00,0xdc,0x3b,0xd5 = mrs x0, AMEVCNTR10_EL0
0x20,0xdc,0x3b,0xd5 = mrs x0, AMEVCNTR11_EL0
0x40,0xdc,0x3b,0xd5 = mrs x0, AMEVCNTR12_EL0
0x60,0xdc,0x3b,0xd5 = mrs x0, AMEVCNTR13_EL0
0x80,0xdc,0x3b,0xd5 = mrs x0, AMEVCNTR14_EL0
0xa0,0xdc,0x3b,0xd5 = mrs x0, AMEVCNTR15_EL0
0xc0,0xdc,0x3b,0xd5 = mrs x0, AMEVCNTR16_EL0
0xe0,0xdc,0x3b,0xd5 = mrs x0, AMEVCNTR17_EL0
0x00,0xdd,0x3b,0xd5 = mrs x0, AMEVCNTR18_EL0
0x20,0xdd,0x3b,0xd5 = mrs x0, AMEVCNTR19_EL0
0x40,0xdd,0x3b,0xd5 = mrs x0, AMEVCNTR110_EL0
0x60,0xdd,0x3b,0xd5 = mrs x0, AMEVCNTR111_EL0
0x80,0xdd,0x3b,0xd5 = mrs x0, AMEVCNTR112_EL0
0xa0,0xdd,0x3b,0xd5 = mrs x0, AMEVCNTR113_EL0
0xc0,0xdd,0x3b,0xd5 = mrs x0, AMEVCNTR114_EL0
0xe0,0xdd,0x3b,0xd5 = mrs x0, AMEVCNTR115_EL0
0x00,0xde,0x3b,0xd5 = mrs x0, AMEVTYPER10_EL0
0x20,0xde,0x3b,0xd5 = mrs x0, AMEVTYPER11_EL0
0x40,0xde,0x3b,0xd5 = mrs x0, AMEVTYPER12_EL0
0x60,0xde,0x3b,0xd5 = mrs x0, AMEVTYPER13_EL0
0x80,0xde,0x3b,0xd5 = mrs x0, AMEVTYPER14_EL0
0xa0,0xde,0x3b,0xd5 = mrs x0, AMEVTYPER15_EL0
0xc0,0xde,0x3b,0xd5 = mrs x0, AMEVTYPER16_EL0
0xe0,0xde,0x3b,0xd5 = mrs x0, AMEVTYPER17_EL0
0x00,0xdf,0x3b,0xd5 = mrs x0, AMEVTYPER18_EL0
0x20,0xdf,0x3b,0xd5 = mrs x0, AMEVTYPER19_EL0
0x40,0xdf,0x3b,0xd5 = mrs x0, AMEVTYPER110_EL0
0x60,0xdf,0x3b,0xd5 = mrs x0, AMEVTYPER111_EL0
0x80,0xdf,0x3b,0xd5 = mrs x0, AMEVTYPER112_EL0
0xa0,0xdf,0x3b,0xd5 = mrs x0, AMEVTYPER113_EL0
0xc0,0xdf,0x3b,0xd5 = mrs x0, AMEVTYPER114_EL0
0xe0,0xdf,0x3b,0xd5 = mrs x0, AMEVTYPER115_EL0
