#!/usr/bin/env python

from distutils.core import setup

VERSION = '3.0'

# clean package directory first
#import os.path, shutil, sys
#for f in sys.path:
#    if f.endswith('packages'):
#        pkgdir = os.path.join(f, 'capstone')
#        #print(pkgdir)
#        try:
#            shutil.rmtree(pkgdir)
#        except:
#            pass

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


