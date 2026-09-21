#!/usr/bin/env python3

import test_lite
import test_iter
import test_skipdata
import test_customized_mnem
import test_compatibility_layer
import test_riscv_sysreg
import test_riscv_reg_access

errors = []
errors.extend(test_lite.test_class())
errors.extend(test_iter.test_class())
errors.extend(test_skipdata.test_class())
errors.extend(test_customized_mnem.test())
errors.extend(test_compatibility_layer.test_compatibility())
errors.extend(test_riscv_sysreg.test())
errors.extend(test_riscv_reg_access.test())

if errors:
    print("Some errors happened. Please check the output")
    for error in errors:
        print(error)
    exit(1)
