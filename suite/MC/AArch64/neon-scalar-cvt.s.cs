# CS_ARCH_AARCH64, 0, None
0xd7,0xd9,0x79,0x5e = scvtf	h23, h14
0xb6,0xd9,0x21,0x5e = scvtf	s22, s13
0x95,0xd9,0x61,0x5e = scvtf	d21, d12
0x94,0xd9,0x79,0x7e = ucvtf	h20, h12
0xb6,0xd9,0x21,0x7e = ucvtf	s22, s13
0xd5,0xd9,0x61,0x7e = ucvtf	d21, d14
0xb6,0xe5,0x10,0x5f = scvtf	h22, h13, #16
0xb6,0xe5,0x20,0x5f = scvtf	s22, s13, #32
0x95,0xe5,0x40,0x5f = scvtf	d21, d12, #64
0xb6,0xe5,0x10,0x7f = ucvtf	h22, h13, #16
0xb6,0xe5,0x20,0x7f = ucvtf	s22, s13, #32
0xd5,0xe5,0x40,0x7f = ucvtf	d21, d14, #64
0x95,0xfd,0x1f,0x5f = fcvtzs	h21, h12, #1
0x95,0xfd,0x3f,0x5f = fcvtzs	s21, s12, #1
0x95,0xfd,0x7f,0x5f = fcvtzs	d21, d12, #1
0x95,0xfd,0x1f,0x7f = fcvtzu	h21, h12, #1
0x95,0xfd,0x3f,0x7f = fcvtzu	s21, s12, #1
0x95,0xfd,0x7f,0x7f = fcvtzu	d21, d12, #1
0xb6,0x69,0x61,0x7e = fcvtxn	s22, d13
0xac,0xc9,0x79,0x5e = fcvtas	h12, h13
0xac,0xc9,0x21,0x5e = fcvtas	s12, s13
0xd5,0xc9,0x61,0x5e = fcvtas	d21, d14
0xac,0xc9,0x79,0x7e = fcvtau	h12, h13
0xac,0xc9,0x21,0x7e = fcvtau	s12, s13
0xd5,0xc9,0x61,0x7e = fcvtau	d21, d14
0xb6,0xb9,0x79,0x5e = fcvtms	h22, h13
0xb6,0xb9,0x21,0x5e = fcvtms	s22, s13
0xd5,0xb9,0x61,0x5e = fcvtms	d21, d14
0xac,0xb9,0x79,0x7e = fcvtmu	h12, h13
0xac,0xb9,0x21,0x7e = fcvtmu	s12, s13
0xd5,0xb9,0x61,0x7e = fcvtmu	d21, d14
0xb6,0xa9,0x79,0x5e = fcvtns	h22, h13
0xb6,0xa9,0x21,0x5e = fcvtns	s22, s13
0xd5,0xa9,0x61,0x5e = fcvtns	d21, d14
0xac,0xa9,0x79,0x7e = fcvtnu	h12, h13
0xac,0xa9,0x21,0x7e = fcvtnu	s12, s13
0xd5,0xa9,0x61,0x7e = fcvtnu	d21, d14
0xb6,0xa9,0xf9,0x5e = fcvtps	h22, h13
0xb6,0xa9,0xa1,0x5e = fcvtps	s22, s13
0xd5,0xa9,0xe1,0x5e = fcvtps	d21, d14
0xac,0xa9,0xf9,0x7e = fcvtpu	h12, h13
0xac,0xa9,0xa1,0x7e = fcvtpu	s12, s13
0xd5,0xa9,0xe1,0x7e = fcvtpu	d21, d14
0xac,0xb9,0xf9,0x5e = fcvtzs	h12, h13
0xac,0xb9,0xa1,0x5e = fcvtzs	s12, s13
0xd5,0xb9,0xe1,0x5e = fcvtzs	d21, d14
0xac,0xb9,0xf9,0x7e = fcvtzu	h12, h13
0xac,0xb9,0xa1,0x7e = fcvtzu	s12, s13
0xd5,0xb9,0xe1,0x7e = fcvtzu	d21, d14
