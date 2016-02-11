#!/usr/bin/env python
import glob
import os
import shutil
import stat
import sys

from distutils import log
from distutils import dir_util
from distutils.command.build_clib import build_clib
from setuptools.command.sdist import sdist
from setuptools import setup
from distutils.sysconfig import get_python_lib

# prebuilt libraries for Windows - for sdist
PATH_LIB64 = "prebuilt/win64/capstone.dll"
PATH_LIB32 = "prebuilt/win32/capstone.dll"

# package name can be 'capstone' or 'capstone-windows'
PKG_NAME = 'capstone'
if os.path.exists(PATH_LIB64) and os.path.exists(PATH_LIB32):
    PKG_NAME = 'capstone-windows'

VERSION = '3.0.4'
SYSTEM = sys.platform

# virtualenv breaks import, but get_python_lib() will work.
SITE_PACKAGES = os.path.join(get_python_lib(), "capstone")
if "--user" in sys.argv:
    try:
        from site import getusersitepackages
        SITE_PACKAGES = os.path.join(getusersitepackages(), "capstone")
    except ImportError:
        pass


# adapted from commit e504b81 of Nguyen Tan Cong
# Reference: https://docs.python.org/2/library/platform.html#cross-platform
is_64bits = sys.maxsize > 2**32

def copy_sources():
    """Copy the C sources into the source directory.
    This rearranges the source files under the python distribution
    directory.
    """
    src = []

    try:
        dir_util.remove_tree("src/")
    except (IOError, OSError):
        pass

    dir_util.copy_tree("../../arch", "src/arch/")
    dir_util.copy_tree("../../include", "src/include/")
#    dir_util.copy_tree("../../msvc/headers", "src/msvc/headers")

    src.extend(glob.glob("../../*.[ch]"))
    src.extend(glob.glob("../../*.mk"))

    src.extend(glob.glob("../../Makefile"))
    src.extend(glob.glob("../../LICENSE*"))
    src.extend(glob.glob("../../README"))
    src.extend(glob.glob("../../*.TXT"))
    src.extend(glob.glob("../../RELEASE_NOTES"))
    src.extend(glob.glob("../../make.sh"))
    src.extend(glob.glob("../../CMakeLists.txt"))

    for filename in src:
        outpath = os.path.join("./src/", os.path.basename(filename))
        log.info("%s -> %s" % (filename, outpath))
        shutil.copy(filename, outpath)


class custom_sdist(sdist):
    """Reshuffle files for distribution."""

    def run(self):
        for filename in (glob.glob("capstone/*.dll")
                         + glob.glob("capstone/*.so")
                         + glob.glob("capstone/*.dylib")):
            try:
                os.unlink(filename)
            except Exception:
                pass

        # if prebuilt libraries are existent, then do not copy source
        if os.path.exists(PATH_LIB64) and os.path.exists(PATH_LIB32):
            return sdist.run(self)
        copy_sources()
        return sdist.run(self)


class custom_build_clib(build_clib):
    """Customized build_clib command."""

    def run(self):
        log.info('running custom_build_clib')
        build_clib.run(self)

    def finalize_options(self):
        # We want build-clib to default to build-lib as defined by the "build"
        # command.  This is so the compiled library will be put in the right
        # place along side the python code.
        self.set_undefined_options('build',
                                   ('build_lib', 'build_clib'),
                                   ('build_temp', 'build_temp'),
                                   ('compiler', 'compiler'),
                                   ('debug', 'debug'),
                                   ('force', 'force'))

        build_clib.finalize_options(self)

    def build_libraries(self, libraries):
        if SYSTEM in ("win32", "cygwin"):
            # if Windows prebuilt library is available, then include it
            if is_64bits and os.path.exists(PATH_LIB64):
                shutil.copy(PATH_LIB64, "capstone")
                return
            elif os.path.exists(PATH_LIB32):
                shutil.copy(PATH_LIB32, "capstone")
                return

        # build library from source if src/ is existent
        if not os.path.exists('src'):
            return

        for (lib_name, build_info) in libraries:
            log.info("building '%s' library", lib_name)

            os.chdir("src")

            # platform description refers at https://docs.python.org/2/library/sys.html#sys.platform
            if SYSTEM == "win32":
                # Windows build: this process requires few things:
                #    - CMake + MSVC installed
                #    - Run this command in an environment setup for MSVC
                os.mkdir("build")
                os.chdir("build")
                # Do not build tests & static library
                os.system('cmake -DCMAKE_BUILD_TYPE=RELEASE -DCAPSTONE_BUILD_TESTS=0 -DCAPSTONE_BUILD_STATIC=0 -G "NMake Makefiles" ..')
                os.system("nmake")
                os.chdir("..")
                so = "src/build/capstone.dll"
            elif SYSTEM == "cygwin":
                os.chmod("make.sh", stat.S_IREAD|stat.S_IEXEC)
                if is_64bits:
                    os.system("CAPSTONE_BUILD_CORE_ONLY=yes ./make.sh cygwin-mingw64")
                else:
                    os.system("CAPSTONE_BUILD_CORE_ONLY=yes ./make.sh cygwin-mingw32")

                so = "src/capstone.dll"
            else:   # Unix
                os.chmod("make.sh", stat.S_IREAD|stat.S_IEXEC)
                os.system("CAPSTONE_BUILD_CORE_ONLY=yes ./make.sh")
                if SYSTEM == "darwin":
                    so = "src/libcapstone.dylib"
                else:   # Non-OSX
                    so = "src/libcapstone.so"

            os.chdir("..")
            shutil.copy(so, "capstone")


def dummy_src():
    return []

setup(
    provides=['capstone'],
    packages=['capstone'],
    name=PKG_NAME,
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
    requires=['ctypes'],
    cmdclass=dict(
        build_clib=custom_build_clib,
        sdist=custom_sdist,
    ),

    libraries=[(
        'capstone', dict(
            package='capstone',
            sources=dummy_src()
        ),
    )],
    zip_safe=False,
    include_package_data=True,
    package_data={
        "capstone": ["*.so", "*.dll", "*.dylib"],
    }
)
