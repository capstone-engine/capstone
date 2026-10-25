# SPDX-FileCopyrightText: 2024 Antelox <anteloxrce@gmail.com>
# SPDX-License-Identifier: BSD-3

import argparse
import logging
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger('tests')
logging.basicConfig(level=logging.INFO)
root_dir = Path(__file__).parent.parent.resolve()

parser = argparse.ArgumentParser()
parser.add_argument(
    "--json",
    action="store_true",
    help="Read the .json test files, converted from the .yaml files, in the test suites.",
)
parser.add_argument(
    "--jobs",
    type=int,
    default=1,
    help="Number of processes cstest_py tests the files of a suite with.",
)
args = parser.parse_args()
json_flag = " --json" if args.json else ""
jobs_flag = f" -j {args.jobs}"

tests = [
    f"{sys.executable} {root_dir}/bindings/python/tests/test_all.py",
    f"{sys.executable} {root_dir}/suite/cstest/test/integration_tests.py cstest_py",
    f"cstest_py {root_dir}/tests/MC/{json_flag}{jobs_flag}",
    f"cstest_py {root_dir}/tests/details/{json_flag}{jobs_flag}",
    f"cstest_py {root_dir}/tests/issues/{json_flag}{jobs_flag}",
    f"cstest_py {root_dir}/tests/features/{json_flag}{jobs_flag}",
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
