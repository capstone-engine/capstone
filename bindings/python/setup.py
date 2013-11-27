#!/usr/bin/env python

from distutils.core import setup

VERSION = '0.9'

setup(
    provides     = ['capstone'],
    packages     = ['capstone'],
    name         = 'capstone',
    version      = VERSION,
    author       = 'Nguyen Anh Quynh',
    author_email = 'aquynh@gmail.com',
    description  = 'Capstone disassembly engine',
    url          = 'https://www.capstone-engine.org',
    #download_url = 'https://www.capstone-engine.org/files/capstone-0.9.zip',
    classifiers  = [
                'License :: OSI Approved :: BSD License',
                'Development Status :: 4 - Beta',
                'Programming Language :: Python :: 2',
                ],
)


