# CS_ARCH_ARM64, 0, None
// 0bAAA00010,A,0b100AAAAA,0xd2 = movz x2, #:abs_g0:sym
// 0bAAA00011,A,0b100AAAAA,0x72 = movk w3, #:abs_g0_nc:sym
// 0bAAA00100,A,0b101AAAAA,0xd2 = movz x4, #:abs_g1:sym
// 0bAAA00101,A,0b101AAAAA,0x72 = movk w5, #:abs_g1_nc:sym
// 0bAAA00110,A,0b110AAAAA,0xd2 = movz x6, #:abs_g2:sym
// 0bAAA00111,A,0b110AAAAA,0xf2 = movk x7, #:abs_g2_nc:sym
// 0bAAA01000,A,0b111AAAAA,0xd2 = movz x8, #:abs_g3:sym
