#!/usr/bin/env python

from distutils.core import setup

VERSION = '1.0'

setup(
    provides     = ['capstone'],
    packages     = ['capstone'],
    name         = 'capstone',
    version      = VERSION,
    author       = 'Nguyen Anh Quynh',
    author_email = 'aquynh@gmail.com',
    description  = 'Capstone disassembly engine',
    url          = 'http://www.capstone-engine.org',
    classifiers  = [
                'License :: OSI Approved :: BSD License',
                'Programming Language :: Python :: 2',
                ],
)


