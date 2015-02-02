#!/usr/bin/env python
import os
import sys

from distutils.core import setup
from distutils.sysconfig import get_python_lib


VERSION = '3.0.1'

# Reference: https://docs.python.org/2/library/platform.html#cross-platform
is_64bits = sys.maxsize > 2**32

SITE_PACKAGES = os.path.join(get_python_lib(), "capstone")

SETUP_DATA_FILES = []

if is_64bits:
    SETUP_DATA_FILES.append("prebuilt/win64/capstone.dll")
else:
    SETUP_DATA_FILES.append("prebuilt/win32/capstone.dll")

setup(
    provides=['capstone'],
    packages=['capstone'],
    name='capstone',
    version=VERSION,
    author='Nguyen Anh Quynh',
    author_email='aquynh@gmail.com',
    description='Capstone disassembly engine',
    url='http://www.capstone-engine.org',
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],
    data_files=[(SITE_PACKAGES, SETUP_DATA_FILES)],
)