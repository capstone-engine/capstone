# CS_ARCH_HPPA, CS_MODE_HPPA_20+CS_MODE_BIG_ENDIAN, None
0x08,0x41,0x03,0xc3 = hadd	r1,rp,r3
0x08,0x41,0x03,0x43 = hadd,ss	r1,rp,r3
0x08,0x41,0x03,0x03 = hadd,us	r1,rp,r3
0x08,0x41,0x01,0xc3 = hsub	r1,rp,r3
0x08,0x41,0x01,0x43 = hsub,ss	r1,rp,r3
0x08,0x41,0x01,0x03 = hsub,us	r1,rp,r3
0x08,0x41,0x02,0xc3 = havg r1,rp,r3
0x08,0x41,0x07,0xc3 = hshladd	r1,3,rp,r3
0x08,0x41,0x05,0xc3 = hshradd	r1,3,rp,r3
0xf8,0x01,0x88,0xc2 = hshl	r1,3,rp
0xf8,0x20,0xcc,0xc2 = hshr,s	r1,3,rp
0xf8,0x21,0x00,0x02 = permh,0000	r1,rp
0xf8,0x21,0x06,0xc2 = permh,0123	r1,rp