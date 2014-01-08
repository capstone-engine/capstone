from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

VERSION = '2.0'

ext_modules = [ Extension("capstone.capstone", ["pyx/capstone.pyx"]),
    Extension("capstone.arm", ["pyx/arm.pyx"]),
    Extension("capstone.arm_const", ["pyx/arm_const.pyx"]),
    Extension("capstone.arm64", ["pyx/arm64.pyx"]),
    Extension("capstone.arm64_const", ["pyx/arm64_const.pyx"]),
    Extension("capstone.mips", ["pyx/mips.pyx"]),
    Extension("capstone.mips_const", ["pyx/mips_const.pyx"]),
    Extension("capstone.ppc", ["pyx/ppc.pyx"]),
    Extension("capstone.ppc_const", ["pyx/ppc_const.pyx"]),
    Extension("capstone.x86", ["pyx/x86.pyx"]),
    Extension("capstone.x86_const", ["pyx/x86_const.pyx"])
]

setup(
    provides     = ['capstone'],
    package_dir  = {'capstone' : 'pyx'},
    packages     = ['capstone'],
    name         = 'capstone',
    version      = VERSION,
    cmdclass = {'build_ext': build_ext},
    ext_modules = ext_modules,
    author       = 'Nguyen Anh Quynh',
    author_email = 'aquynh@gmail.com',
    description  = 'Capstone disassembly engine',
    url          = 'http://www.capstone-engine.org',
    classifiers  = [
                'License :: OSI Approved :: BSD License',
                'Programming Language :: Python :: 2',
                ],
)
