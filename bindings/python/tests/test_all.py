#!/usr/bin/env python3

import test_lite
import test_iter
import test_skipdata
import test_customized_mnem
import test_compatibility_layer

errors = []
errors.extend(test_lite.test_class())
errors.extend(test_iter.test_class())
errors.extend(test_skipdata.test_class())
errors.extend(test_customized_mnem.test())
errors.extend(test_compatibility_layer.test_compatibility())

if errors:
    print("Some errors happened. Please check the output")
    for error in errors:
        print(error)
    exit(1)
