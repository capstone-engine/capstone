# CS_ARCH_ARM, CS_MODE_THUMB+CS_MODE_V8+CS_MODE_MCLASS, None
0x80,0xed,0x80,0x2f = vstr fpscr, [r0]
0x09,0xed,0x86,0x4f = vstr fpscr_nzcvqc, [r9, #-0x18]
0x29,0xed,0x86,0x4f = vstr fpscr_nzcvqc, [r9, #-0x18]!
0x29,0xec,0x86,0x4f = vstr fpscr_nzcvqc, [r9], #-0x18
0x88,0xbf = it hi
0x80,0xed,0x80,0x2f = vstrhi fpscr, [r0]
0x90,0xed,0x80,0x2f = vldr fpscr, [r0]
0x19,0xed,0x86,0x4f = vldr fpscr_nzcvqc, [r9, #-0x18]
0x39,0xed,0x86,0x4f = vldr fpscr_nzcvqc, [r9, #-0x18]!
0x39,0xec,0x86,0x4f = vldr fpscr_nzcvqc, [r9], #-0x18
0x3d,0xec,0x8d,0x4f = vldr fpscr_nzcvqc, [sp], #-0x34
0x88,0xbf = it hi
0x90,0xed,0x80,0x2f = vldrhi fpscr, [r0]
0xcc,0xed,0xff,0xef = vstr fpcxts, [r12, #0x1fc]
0xec,0xed,0xff,0xef = vstr fpcxts, [r12, #0x1fc]!
0xec,0xec,0xff,0xef = vstr fpcxts, [r12], #0x1fc
0x6d,0xec,0x86,0xef = vstr fpcxts, [sp], #-0x18
0xdc,0xed,0xff,0xef = vldr fpcxts, [r12, #0x1fc]
0xfc,0xed,0xff,0xef = vldr fpcxts, [r12, #0x1fc]!
0xfc,0xec,0xff,0xef = vldr fpcxts, [r12], #0x1fc
0x7d,0xec,0x86,0xef = vldr fpcxts, [sp], #-0x18
0xc0,0xed,0x80,0xcf = vstr fpcxtns, [r0]
0x49,0xed,0x86,0xcf = vstr fpcxtns, [r9, #-0x18]
0xc6,0xed,0xfd,0xcf = vstr fpcxtns, [r6, #0x1f4]
0x4e,0xed,0xff,0xcf = vstr fpcxtns, [lr, #-0x1fc]
0xcc,0xed,0xff,0xcf = vstr fpcxtns, [r12, #0x1fc]
0x6d,0xec,0x86,0xcf = vstr fpcxtns, [sp], #-0x18
0xd0,0xed,0x80,0xcf = vldr fpcxtns, [r0]
0x59,0xed,0x86,0xcf = vldr fpcxtns, [r9, #-0x18]
0xd6,0xed,0xfd,0xcf = vldr fpcxtns, [r6, #0x1f4]
0x5e,0xed,0xff,0xcf = vldr fpcxtns, [lr, #-0x1fc]
0xdc,0xed,0xff,0xcf = vldr fpcxtns, [r12, #0x1fc]
0x7d,0xec,0x86,0xcf = vldr fpcxtns, [sp], #-0x18
0xc6,0xed,0xfd,0x8f = vstr vpr, [r6, #0x1f4]
0x4e,0xed,0xff,0xaf = vstr p0, [lr, #-0x1fc]
0xe6,0xed,0xfd,0x8f = vstr vpr, [r6, #0x1f4]!
0x6e,0xed,0xff,0xaf = vstr p0, [lr, #-0x1fc]!
0xe6,0xec,0xfd,0x8f = vstr vpr, [r6], #0x1f4
0x6e,0xec,0xff,0xaf = vstr p0, [lr], #-0x1fc
0x6d,0xec,0x86,0xaf = vstr p0, [sp], #-0x18
0xd6,0xed,0xfd,0x8f = vldr vpr, [r6, #0x1f4]
0x5e,0xed,0xff,0xaf = vldr p0, [lr, #-0x1fc]
0xf6,0xed,0xfd,0x8f = vldr vpr, [r6, #0x1f4]!
0x7e,0xed,0xff,0xaf = vldr p0, [lr, #-0x1fc]!
0xf6,0xec,0xfd,0x8f = vldr vpr, [r6], #0x1f4
0x7e,0xec,0xff,0xaf = vldr p0, [lr], #-0x1fc
0x7d,0xec,0x86,0xaf = vldr p0, [sp], #-0x18
