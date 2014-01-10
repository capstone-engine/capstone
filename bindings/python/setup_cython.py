from distutils.core import setup
from distutils.extension import Extension
from distutils.command.install_lib import install_lib as _install
from Cython.Distutils import build_ext

VERSION = '2.0'

compile_args = ['-O3', '-fomit-frame-pointer']

ext_modules = [ Extension("capstone.capstone", ["cython/capstone.pyx"], extra_compile_args=compile_args),
    Extension("capstone.arm", ["cython/arm.pyx"], extra_compile_args=compile_args),
    Extension("capstone.arm_const", ["cython/arm_const.pyx"], extra_compile_args=compile_args),
    Extension("capstone.arm64", ["cython/arm64.pyx"], extra_compile_args=compile_args),
    Extension("capstone.arm64_const", ["cython/arm64_const.pyx"], extra_compile_args=compile_args),
    Extension("capstone.mips", ["cython/mips.pyx"], extra_compile_args=compile_args),
    Extension("capstone.mips_const", ["cython/mips_const.pyx"], extra_compile_args=compile_args),
    Extension("capstone.ppc", ["cython/ppc.pyx"], extra_compile_args=compile_args),
    Extension("capstone.ppc_const", ["cython/ppc_const.pyx"], extra_compile_args=compile_args),
    Extension("capstone.x86", ["cython/x86.pyx"], extra_compile_args=compile_args),
    Extension("capstone.x86_const", ["cython/x86_const.pyx"], extra_compile_args=compile_args)
]

# clean package directory first
import os.path, shutil, sys
for f in sys.path:
    if f.endswith('packages'):
        pkgdir = os.path.join(f, 'capstone')
        #print(pkgdir)
        try:
            shutil.rmtree(pkgdir)
        except:
            pass

setup(
    provides     = ['capstone'],
    package_dir  = {'capstone' : 'cython'},
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
