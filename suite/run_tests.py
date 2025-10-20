# SPDX-FileCopyrightText: 2024 Antelox <anteloxrce@gmail.com>
# SPDX-License-Identifier: BSD-3

import logging
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger('tests')
logging.basicConfig(level=logging.INFO)
root_dir = Path(__file__).parent.parent.resolve()
tests = [
    f"{sys.executable} {root_dir}/bindings/python/tests/test_all.py",
    f"{sys.executable} {root_dir}/suite/cstest/test/integration_tests.py cstest_py",
    f"cstest_py {root_dir}/tests/MC/",
    f"cstest_py {root_dir}/tests/details/",
    f"cstest_py {root_dir}/tests/issues/",
    f"cstest_py {root_dir}/tests/features/",
]

expected_to_fail = [
    f"cstest_py {root_dir}/tests/negative/",
]

for test in tests:
    logger.info(f'Running {test}')
    logger.info("#######################")
    subprocess.run(test.split(" "), check=True)
    logger.info("-----------------------")

for test in expected_to_fail:
    logger.info(f'Running {test}')
    logger.info("#######################")
    try:
        subprocess.run(test.split(" "), check=True)
        logger.error("Test was expected to fail.")
        exit(-1)
    except Exception as e:
        logger.info("-----------------------")
