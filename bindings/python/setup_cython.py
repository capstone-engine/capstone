from distutils.core import setup
from distutils.extension import Extension
from distutils.command.install_lib import install_lib as _install
from Cython.Distutils import build_ext

VERSION = '3.0.4'

compile_args = ['-O3', '-fomit-frame-pointer']

ext_modules = [
    Extension("capstone.ccapstone", ["pyx/ccapstone.pyx"], libraries=["capstone"], extra_compile_args=compile_args),
    Extension("capstone.arm", ["pyx/arm.pyx"], extra_compile_args=compile_args),
    Extension("capstone.arm_const", ["pyx/arm_const.pyx"], extra_compile_args=compile_args),
    Extension("capstone.arm64", ["pyx/arm64.pyx"], extra_compile_args=compile_args),
    Extension("capstone.arm64_const", ["pyx/arm64_const.pyx"], extra_compile_args=compile_args),
    Extension("capstone.mips", ["pyx/mips.pyx"], extra_compile_args=compile_args),
    Extension("capstone.mips_const", ["pyx/mips_const.pyx"], extra_compile_args=compile_args),
    Extension("capstone.ppc", ["pyx/ppc.pyx"], extra_compile_args=compile_args),
    Extension("capstone.ppc_const", ["pyx/ppc_const.pyx"], extra_compile_args=compile_args),
    Extension("capstone.x86", ["pyx/x86.pyx"], extra_compile_args=compile_args),
    Extension("capstone.x86_const", ["pyx/x86_const.pyx"], extra_compile_args=compile_args),
    Extension("capstone.sparc", ["pyx/sparc.pyx"], extra_compile_args=compile_args),
    Extension("capstone.sparc_const", ["pyx/sparc_const.pyx"], extra_compile_args=compile_args),
    Extension("capstone.systemz", ["pyx/systemz.pyx"], extra_compile_args=compile_args),
    Extension("capstone.sysz_const", ["pyx/sysz_const.pyx"], extra_compile_args=compile_args),
    Extension("capstone.xcore", ["pyx/xcore.pyx"], extra_compile_args=compile_args),
    Extension("capstone.xcore_const", ["pyx/xcore_const.pyx"], extra_compile_args=compile_args)
]

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
    package_dir  = {'capstone' : 'pyx'},
    packages     = ['capstone'],
    name         = 'capstone',
    version      = VERSION,
    cmdclass     = {'build_ext': build_ext},
    ext_modules  = ext_modules,
    author       = 'Nguyen Anh Quynh',
    author_email = 'aquynh@gmail.com',
    description  = 'Capstone disassembly engine',
    url          = 'http://www.capstone-engine.org',
    classifiers  = [
                'License :: OSI Approved :: BSD License',
                'Programming Language :: Python :: 2',
                ],
)
