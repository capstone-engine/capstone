#!/usr/bin/env python
import glob
import os
import platform
import shutil
import stat
import sys

from distutils import log
from distutils import dir_util
from distutils.command.build_clib import build_clib
from distutils.command.sdist import sdist
from distutils.core import setup
from distutils.sysconfig import get_python_lib

from optparse import OptionParser

# platform description refers at https://docs.python.org/2/library/sys.html#sys.platform
SYSTEM = sys.platform
VERSION = '4.0'

FLAG_DONT_BUILD_CORE = "--do-not-build-core"
DONT_BUILD_CORE = False
# parse parameters to detect if FLAG_DONT_BUILD_CORE exists
parser = OptionParser()
parser.add_option(
        "", 
        FLAG_DONT_BUILD_CORE,
        action="store_true",
        dest="do_not_build_core",
        default=False,
        )

try:
    (option, _) = parser.parse_args()
    DONT_BUILD_CORE = option.do_not_build_core
except:
    pass

# remove FLAG_DONT_BUILD_CORE to prevent it pass to distutils setup parameters
if FLAG_DONT_BUILD_CORE in sys.argv:
    sys.argv.remove(FLAG_DONT_BUILD_CORE)


SITE_PACKAGES = os.path.join(get_python_lib(), "capstone")

SETUP_DATA_FILES = []

if not DONT_BUILD_CORE:
    if SYSTEM == "darwin":
        SETUP_DATA_FILES.append("src/libcapstone.dylib")
    elif SYSTEM != "win32":
        SETUP_DATA_FILES.append("src/libcapstone.so")

class LazyList(list):
    """A list which re-evaluates each time.

    This is used to provide late binding for setup() below.
    """
    def __init__(self, callback):
        super(LazyList, self).__init__()
        self.callback = callback

    def __iter__(self):
        return iter(self.callback())

def get_sources():
    #custom_sdist.copy_sources()

    return []

class custom_sdist(sdist):
    """Reshuffle files for distribution."""

    def run(self):
        self.copy_sources()
        return sdist.run(self)

    @staticmethod
    def copy_sources():
        """Copy the C sources into the source directory.

        This rearranges the source files under the python distribution
        directory.
        """
        result = []

        try:
            dir_util.remove_tree("src/")
        except (IOError, OSError):
            pass

        dir_util.copy_tree("../../arch", "src/arch/")
        dir_util.copy_tree("../../include", "src/include/")
        dir_util.copy_tree("../../msvc/headers", "src/msvc/headers/")

        result.extend(glob.glob("../../*.[ch]"))
        result.extend(glob.glob("../../*.mk"))

        result.extend(glob.glob("../../Makefile"))
        result.extend(glob.glob("../../LICENSE*"))
        result.extend(glob.glob("../../README"))
        result.extend(glob.glob("../../*.TXT"))
        result.extend(glob.glob("../../RELEASE_NOTES"))
        result.extend(glob.glob("../../make.sh"))

        for filename in result:
            outpath = os.path.join("./src/", os.path.basename(filename))
            print "%s -> %s" % (filename, outpath)
            shutil.copy(filename, outpath)


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
        if DONT_BUILD_CORE:
            return

        for (lib_name, build_info) in libraries:
            sources = self.get_source_files()
            sources = list(sources)

            log.info("building '%s' library", lib_name)

            os.chdir("src")

            if SYSTEM != "win32":
                os.chmod("make.sh", stat.S_IREAD|stat.S_IEXEC)
                os.system("BUILD_CORE_ONLY=yes ./make.sh")

            os.chdir("..")


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
    requires=['ctypes'],
    cmdclass=dict(
        build_clib=custom_build_clib,
        sdist=custom_sdist,
    ),

    libraries=[(
        'capstone', dict(
            package='capstone',
            sources=LazyList(get_sources)            
        ),
    )],

    data_files=[(SITE_PACKAGES, SETUP_DATA_FILES)],
)
