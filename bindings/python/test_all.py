#!/usr/bin/env python

import warnings
import test, test_arm, test_arm64, test_detail, test_lite, test_mips, test_ppc, \
    test_x86, test_skipdata, test_sparc, test_systemz


warnings.simplefilter('default')    # turn on deprecation warnings (default disabled for non-dev)
test.test_class()
test_arm.test_class()
test_arm64.test_class()
test_detail.test_class()
test_lite.test_class()
test_mips.test_class()
test_ppc.test_class()
test_sparc.test_class()
test_systemz.test_class()
test_x86.test_class()
test_skipdata.test_class()
