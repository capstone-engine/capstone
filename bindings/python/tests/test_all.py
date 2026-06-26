#!/usr/bin/env python

import test_basic, test_arm, test_arm64, test_detail, test_lite, test_m68k, test_mips, \
    test_ppc, test_x86, test_skipdata, test_sparc, test_systemz, test_tms320c64x, test_customized_mnem, \
    test_m680x, test_mos65xx, test_xcore, test_riscv
from test_arm64_atomics import ARM64AtomicsRegAccessTest
import unittest

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
test_xcore.test_class()
test_riscv.test_class()

# Create a test suite with specific tests
suite = unittest.TestSuite()
suite.addTest(ARM64AtomicsRegAccessTest('test_regs_access'))

# Run the suite
runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)
