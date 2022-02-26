import os
import sys
import shutil

from distutils import log
from distutils.core import setup
from distutils.extension import Extension
from distutils.command.build import build
from Cython.Distutils import build_ext

SYSTEM = sys.platform
VERSION = '4.0.0'

# adapted from commit e504b81 of Nguyen Tan Cong
# Reference: https://docs.python.org/2/library/platform.html#cross-platform
IS_64BITS = sys.maxsize > 2**32

# are we building from the repository or from a source distribution?
ROOT_DIR = os.path.dirname(os.path.realpath(__file__))
LIBS_DIR = os.path.join(ROOT_DIR, 'pyx', 'lib')
HEADERS_DIR = os.path.join(ROOT_DIR, 'pyx', 'include')
SRC_DIR = os.path.join(ROOT_DIR, 'src')
BUILD_DIR = SRC_DIR if os.path.exists(SRC_DIR) else os.path.join(ROOT_DIR, '../..')
PYPACKAGE_DIR = os.path.join(ROOT_DIR, 'capstone')
CYPACKAGE_DIR = os.path.join(ROOT_DIR, 'pyx')

if SYSTEM == 'darwin':
    VERSIONED_LIBRARY_FILE = "libcapstone.4.dylib"
    LIBRARY_FILE = "libcapstone.dylib"
    STATIC_LIBRARY_FILE = 'libcapstone.a'
elif SYSTEM in ('win32', 'cygwin'):
    VERSIONED_LIBRARY_FILE = "capstone.dll"
    LIBRARY_FILE = "capstone.dll"
    STATIC_LIBRARY_FILE = None
else:
    VERSIONED_LIBRARY_FILE = "libcapstone.so.4"
    LIBRARY_FILE = "libcapstone.so"
    STATIC_LIBRARY_FILE = 'libcapstone.a'

compile_args = ['-O3', '-fomit-frame-pointer', '-I' + HEADERS_DIR]
link_args = ['-L' + LIBS_DIR]

ext_module_names = ['arm', 'arm_const', 'arm64', 'arm64_const', 'm68k', 'm68k_const', 'm680x', 'm680x_const', 'mips', 'mips_const', 'ppc', 'ppc_const', 'x86', 'x86_const', 'sparc', 'sparc_const', 'systemz', 'sysz_const', 'xcore', 'xcore_const', 'tms320c64x', 'tms320c64x_const', 'evm', 'evm_const' ]

ext_modules = [Extension("capstone.ccapstone",
                         ["pyx/ccapstone.pyx"],
                         libraries=["capstone"],
                         extra_compile_args=compile_args,
                         extra_link_args=link_args)]
ext_modules += [Extension("capstone.%s" % name,
                          ["pyx/%s.pyx" % name],
                          extra_compile_args=compile_args,
                          extra_link_args=link_args)
                for name in ext_module_names]

def clean_bins():
    shutil.rmtree(LIBS_DIR, ignore_errors=True)
    shutil.rmtree(HEADERS_DIR, ignore_errors=True)

def copy_pysources():
    for fname in os.listdir(PYPACKAGE_DIR):
        if not fname.endswith('.py'):
            continue

        if fname == '__init__.py':
            shutil.copy(os.path.join(PYPACKAGE_DIR, fname), os.path.join(CYPACKAGE_DIR, fname))
        else:
            shutil.copy(os.path.join(PYPACKAGE_DIR, fname), os.path.join(CYPACKAGE_DIR, fname + 'x'))

def build_libraries():
    """
    Prepare the capstone directory for a binary distribution or installation.
    Builds shared libraries and copies header files.

    Will use a src/ dir if one exists in the current directory, otherwise assumes it's in the repo
    """
    cwd = os.getcwd()
    clean_bins()
    os.mkdir(HEADERS_DIR)
    os.mkdir(LIBS_DIR)

    # copy public headers
    shutil.copytree(os.path.join(BUILD_DIR, 'include', 'capstone'), os.path.join(HEADERS_DIR, 'capstone'))

    os.chdir(BUILD_DIR)

    # platform description refers at https://docs.python.org/2/library/sys.html#sys.platform
    if SYSTEM == "win32":
        # Windows build: this process requires few things:
        #    - CMake + MSVC installed
        #    - Run this command in an environment setup for MSVC
        if not os.path.exists("build"): os.mkdir("build")
        os.chdir("build")
        # Only build capstone.dll
        os.system('cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_BUILD_SHARED=ON -DCAPSTONE_BUILD_TESTS=OFF -DCAPSTONE_BUILD_CSTOOL=OFF -G "NMake Makefiles" ..')
        os.system("cmake --build .")
    else:  # Unix incl. cygwin
        os.system("CAPSTONE_BUILD_CORE_ONLY=yes bash ./make.sh")

    shutil.copy(VERSIONED_LIBRARY_FILE, os.path.join(LIBS_DIR, LIBRARY_FILE))
    if STATIC_LIBRARY_FILE: shutil.copy(STATIC_LIBRARY_FILE, LIBS_DIR)
    os.chdir(cwd)


class custom_build(build):
    def run(self):
        log.info('Copying python sources')
        copy_pysources()
        log.info('Building C extensions')
        build_libraries()
        return build.run(self)

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
    cmdclass     = {'build_ext': build_ext, 'build': custom_build},
    ext_modules  = ext_modules,
    author       = 'Nguyen Anh Quynh',
    author_email = 'aquynh@gmail.com',
    description  = 'Capstone disassembly engine',
    url          = 'http://www.capstone-engine.org',
    classifiers  = [
                'License :: OSI Approved :: BSD License',
                'Programming Language :: Python :: 2',
                ],
    include_package_data=True,
    package_data={
        "capstone": ["lib/*", "include/capstone/*"],
    }
)
