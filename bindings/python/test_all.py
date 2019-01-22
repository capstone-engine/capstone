#!/usr/bin/env python

import test_basic, test_arm, test_arm64, test_detail, test_lite, test_m68k, test_mips, \
    test_ppc, test_x86, test_skipdata, test_sparc, test_systemz, test_tms320c64x, test_customized_mnem, \
    test_m680x, test_mos65xx

test_basic.test_class()
test_arm.test_class()
test_arm64.test_class()
test_detail.test_class()
test_lite.test_class()
test_m68k.test_class()
test_mips.test_class()
test_mos65xx.test_class()
test_ppc.test_class()
test_sparc.test_class()
test_systemz.test_class()
test_x86.test_class()
test_tms320c64x.test_class()
test_m680x.test_class()
test_skipdata.test_class()
test_customized_mnem.test()
