# CS_ARCH_HPPA, CS_MODE_HPPA_11+CS_MODE_BIG_ENDIAN, None
0x14,0x00,0x00,0x01 = diag 1
0x18,0x22,0x29,0x03 = fmpyadd,dbl fpe2,fpe4,fpe6,fr4,fr5
0x20,0x39,0x00,0x00 = ldil 0x32000,r1
0x28,0x39,0x00,0x00 = addil 0x32000,r1
0x34,0x22,0x00,0x1e = ldo 0xf(r1),rp
0x0c,0x3e,0x50,0x02 = ldbs 0xf(sr1,r1),rp
0x0c,0x3e,0x50,0x42 = ldhs 0xf(sr1,r1),rp
0x0c,0x3e,0x50,0x82 = ldws 0xf(sr1,r1),rp
0x4c,0x22,0x40,0x1e = ldwm 0xf(sr1,r1),rp
0x0c,0x41,0x12,0x1e = stbs r1,0xf(rp)
0x0c,0x41,0x12,0x5e = sths r1,0xf(rp)
0x0c,0x41,0x12,0x9e = stws r1,0xf(rp)
0x6c,0x41,0x00,0x1e = stwm r1,0xf(rp)
0x80,0x41,0x1f,0x0d = combt r1,rp,-0x74
0x80,0x41,0x3f,0x05 = combt,= r1,rp,-0x78
0x80,0x41,0x5e,0xfd = combt,< r1,rp,-0x7c
0x80,0x41,0x7e,0xf5 = combt,<= r1,rp,-0x80
0x80,0x41,0x9e,0xed = combt,<< r1,rp,-0x84
0x80,0x41,0xbe,0xe5 = combt,<<= r1,rp,-0x88
0x80,0x41,0xde,0xdd = combt,sv r1,rp,-0x8c
0x80,0x41,0xfe,0xd5 = combt,od r1,rp,-0x90
0x84,0x5e,0x1e,0xcd = comibt 0xf,rp,-0x94
0x84,0x5e,0x3e,0xc5 = comibt,= 0xf,rp,-0x98
0x84,0x5e,0x5e,0xbd = comibt,< 0xf,rp,-0x9c
0x84,0x5e,0x7e,0xb5 = comibt,<= 0xf,rp,-0xa0
0x84,0x5e,0x9e,0xad = comibt,<< 0xf,rp,-0xa4
0x84,0x5e,0xbe,0xa5 = comibt,<<= 0xf,rp,-0xa8
0x84,0x5e,0xde,0x9d = comibt,sv 0xf,rp,-0xac
0x84,0x5e,0xfe,0x95 = comibt,od 0xf,rp,-0xb0
0x88,0x41,0x1e,0x8d = combf r1,rp,-0xb4
0x88,0x41,0x3e,0x85 = combf,= r1,rp,-0xb8
0x88,0x41,0x5e,0x7d = combf,< r1,rp,-0xbc
0x88,0x41,0x7e,0x75 = combf,<= r1,rp,-0xc0
0x88,0x41,0x9e,0x6d = combf,<< r1,rp,-0xc4
0x88,0x41,0xbe,0x65 = combf,<<= r1,rp,-0xc8
0x88,0x41,0xde,0x5d = combf,sv r1,rp,-0xcc
0x88,0x41,0xfe,0x55 = combf,od r1,rp,-0xd0
0x8c,0x5e,0x1e,0x4d = comibf 0xf,rp,-0xd4
0x8c,0x5e,0x3e,0x45 = comibf,= 0xf,rp,-0xd8
0x8c,0x5e,0x5e,0x3d = comibf,< 0xf,rp,-0xdc
0x8c,0x5e,0x7e,0x35 = comibf,<= 0xf,rp,-0xe0
0x8c,0x5e,0x9e,0x2d = comibf,<< 0xf,rp,-0xe4
0x8c,0x5e,0xbe,0x25 = comibf,<<= 0xf,rp,-0xe8
0x8c,0x5e,0xde,0x1d = comibf,sv 0xf,rp,-0xec
0x8c,0x5e,0xfe,0x15 = comibf,od 0xf,rp,-0xf0
0x90,0x41,0x00,0x1e = comiclr 0xf,rp,r1
0x90,0x41,0x20,0x1e = comiclr,= 0xf,rp,r1
0x90,0x41,0x40,0x1e = comiclr,< 0xf,rp,r1
0x90,0x41,0x60,0x1e = comiclr,<= 0xf,rp,r1
0x90,0x41,0x80,0x1e = comiclr,<< 0xf,rp,r1
0x90,0x41,0xa0,0x1e = comiclr,<<= 0xf,rp,r1
0x90,0x41,0xc0,0x1e = comiclr,sv 0xf,rp,r1
0x90,0x41,0xe0,0x1e = comiclr,od 0xf,rp,r1
0x98,0x22,0x29,0x03 = fmpysub,dbl fpe2,fpe4,fpe6,fr4,fr5
0xa0,0x41,0x1d,0xc5 = addbt r1,rp,-0x118
0xa0,0x41,0x3d,0xbd = addbt,= r1,rp,-0x11c
0xa0,0x41,0x5d,0xb5 = addbt,< r1,rp,-0x120
0xa0,0x41,0x7d,0xad = addbt,<= r1,rp,-0x124
0xa0,0x41,0x9d,0xa7 = addbt,nuv,n r1,rp,-0x128
0xa0,0x41,0xbd,0x9f = addbt,znv,n r1,rp,-0x12c
0xa0,0x41,0xdd,0x95 = addbt,sv r1,rp,-0x130
0xa0,0x41,0xfd,0x8d = addbt,od r1,rp,-0x134
0xa4,0x5e,0x1d,0x85 = addibt 0xf,rp,-0x138
0xa4,0x5e,0x3d,0x7d = addibt,= 0xf,rp,-0x13c
0xa4,0x5e,0x5d,0x75 = addibt,< 0xf,rp,-0x140
0xa4,0x5e,0x7d,0x6d = addibt,<= 0xf,rp,-0x144
0xa4,0x5e,0x9d,0x67 = addibt,nuv,n 0xf,rp,-0x148
0xa4,0x5e,0xbd,0x5f = addibt,znv,n 0xf,rp,-0x14c
0xa4,0x5e,0xdd,0x55 = addibt,sv 0xf,rp,-0x150
0xa4,0x5e,0xfd,0x4d = addibt,od 0xf,rp,-0x154
0xa8,0x41,0x1d,0x45 = addbf r1,rp,-0x158
0xa8,0x41,0x3d,0x3d = addbf,= r1,rp,-0x15c
0xa8,0x41,0x5d,0x35 = addbf,< r1,rp,-0x160
0xa8,0x41,0x7d,0x2d = addbf,<= r1,rp,-0x164
0xa8,0x41,0x9d,0x27 = addbf,nuv,n r1,rp,-0x168
0xa8,0x41,0xbd,0x1f = addbf,znv,n r1,rp,-0x16c
0xa8,0x41,0xdd,0x15 = addbf,sv r1,rp,-0x170
0xa8,0x41,0xfd,0x0d = addbf,od r1,rp,-0x174
0xac,0x5e,0x1d,0x05 = addibf 0xf,rp,-0x178
0xac,0x5e,0x3c,0xfd = addibf,= 0xf,rp,-0x17c
0xac,0x5e,0x5c,0xf5 = addibf,< 0xf,rp,-0x180
0xac,0x5e,0x7c,0xed = addibf,<= 0xf,rp,-0x184
0xac,0x5e,0x9c,0xe7 = addibf,nuv,n 0xf,rp,-0x188
0xac,0x5e,0xbc,0xdf = addibf,znv,n 0xf,rp,-0x18c
0xac,0x5e,0xdc,0xd5 = addibf,sv 0xf,rp,-0x190
0xac,0x5e,0xfc,0xcd = addibf,od 0xf,rp,-0x194
0xc0,0x01,0x5c,0xc7 = bvb,<,n r1,-0x198
0xc0,0x01,0xdc,0xbf = bvb,>=,n r1,-0x19c
0xc4,0x61,0x5c,0xb7 = bb,<,n r1,3,-0x1a0
0xc4,0x61,0xdc,0xaf = bb,>=,n r1,3,-0x1a4
0xc8,0x41,0x1c,0xa7 = movb,n r1,rp,-0x1a8
0xc8,0x41,0x3c,0x9d = movb,= r1,rp,-0x1ac
0xc8,0x41,0x5c,0x95 = movb,< r1,rp,-0x1b0
0xc8,0x41,0x7c,0x8d = movb,od r1,rp,-0x1b4
0xc8,0x41,0x9c,0x85 = movb,tr r1,rp,-0x1b8
0xc8,0x41,0xbc,0x7d = movb,<> r1,rp,-0x1bc
0xc8,0x41,0xdc,0x75 = movb,>= r1,rp,-0x1c0
0xc8,0x41,0xfc,0x6d = movb,ev r1,rp,-0x1c4
0xcc,0x5e,0x1c,0x67 = movib,n 0xf,rp,-0x1c8
0xcc,0x5e,0x3c,0x5d = movib,= 0xf,rp,-0x1cc
0xcc,0x5e,0x5c,0x55 = movib,< 0xf,rp,-0x1d0
0xcc,0x5e,0x7c,0x4d = movib,od 0xf,rp,-0x1d4
0xcc,0x5e,0x9c,0x45 = movib,tr 0xf,rp,-0x1d8
0xcc,0x5e,0xbc,0x3d = movib,<> 0xf,rp,-0x1dc
0xcc,0x5e,0xdc,0x35 = movib,>= 0xf,rp,-0x1e0
0xcc,0x5e,0xfc,0x2d = movib,ev 0xf,rp,-0x1e4
0xe0,0x20,0x42,0x02 = be,n 0x100(sr1,r1)
0xe4,0x20,0x42,0x02 = ble,n 0x100(sr1,r1)