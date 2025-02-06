#!/usr/bin/env python3

import glob
import os
import shutil
import sys
import platform

import logging
from setuptools import setup
from sysconfig import get_platform
from setuptools.command.build import build
from setuptools.command.sdist import sdist
from setuptools.command.bdist_egg import bdist_egg

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

SYSTEM = sys.platform

# adapted from commit e504b81 of Nguyen Tan Cong
# Reference: https://docs.python.org/2/library/platform.html#cross-platform
IS_64BITS = sys.maxsize > 2**32

# are we building from the repository or from a source distribution?
ROOT_DIR = os.path.dirname(os.path.realpath(__file__))
LIBS_DIR = os.path.join(ROOT_DIR, 'capstone', 'lib')
HEADERS_DIR = os.path.join(ROOT_DIR, 'capstone', 'include')
SRC_DIR = os.path.join(ROOT_DIR, 'src')
BUILD_DIR = SRC_DIR if os.path.exists(SRC_DIR) else os.path.join(ROOT_DIR, '../..')

# Parse version from pkgconfig.mk
VERSION_DATA = {}
with open(os.path.join(BUILD_DIR, 'pkgconfig.mk')) as fp:
    lines = fp.readlines()
    for line in lines:
        line = line.strip()
        if len(line) == 0:
            continue
        if line.startswith('#'):
            continue
        if '=' not in line:
            continue

        k, v = line.split('=', 1)
        k = k.strip()
        v = v.strip()
        if len(k) == 0 or len(v) == 0:
            continue
        VERSION_DATA[k] = v

if 'PKG_MAJOR' not in VERSION_DATA or \
        'PKG_MINOR' not in VERSION_DATA or \
        'PKG_EXTRA' not in VERSION_DATA:
    raise Exception("Malformed pkgconfig.mk")

if 'PKG_TAG' in VERSION_DATA:
    VERSION = '{PKG_MAJOR}.{PKG_MINOR}.{PKG_EXTRA}{PKG_TAG}'.format(**VERSION_DATA)
else:
    VERSION = '{PKG_MAJOR}.{PKG_MINOR}.{PKG_EXTRA}'.format(**VERSION_DATA)

if SYSTEM == 'darwin':
    VERSIONED_LIBRARY_FILE = "libcapstone.{PKG_MAJOR}.dylib".format(**VERSION_DATA)
    LIBRARY_FILE = "libcapstone.dylib"
elif SYSTEM in ('win32', 'cygwin'):
    VERSIONED_LIBRARY_FILE = "capstone.dll"
    LIBRARY_FILE = "capstone.dll"
else:
    VERSIONED_LIBRARY_FILE = "libcapstone.so.{PKG_MAJOR}".format(**VERSION_DATA)
    LIBRARY_FILE = "libcapstone.so"

def clean_bins():
    shutil.rmtree(LIBS_DIR, ignore_errors=True)
    shutil.rmtree(HEADERS_DIR, ignore_errors=True)

def copy_sources():
    """Copy the C sources into the source directory.
    This rearranges the source files under the python distribution
    directory.
    """
    src = []

    try:
        shutil.rmtree("src/")
    except (IOError, OSError):
        pass

    shutil.copytree(os.path.join(BUILD_DIR, "arch"), os.path.join(SRC_DIR, "arch"))
    shutil.copytree(os.path.join(BUILD_DIR, "include"), os.path.join(SRC_DIR, "include"))

    src.extend(glob.glob(os.path.join(BUILD_DIR, "*.[ch]")))
    src.extend(glob.glob(os.path.join(BUILD_DIR, "*.in")))
    src.extend(glob.glob(os.path.join(BUILD_DIR, "*.mk")))

    src.extend(glob.glob(os.path.join(BUILD_DIR, "Makefile")))
    src.extend(glob.glob(os.path.join(BUILD_DIR, "LICENSE*")))
    src.extend(glob.glob(os.path.join(BUILD_DIR, "README")))
    src.extend(glob.glob(os.path.join(BUILD_DIR, "*.TXT")))
    src.extend(glob.glob(os.path.join(BUILD_DIR, "RELEASE_NOTES")))
    src.extend(glob.glob(os.path.join(BUILD_DIR, "make.sh")))
    src.extend(glob.glob(os.path.join(BUILD_DIR, "CMakeLists.txt")))
    src.extend(glob.glob(os.path.join(BUILD_DIR, "pkgconfig.mk")))
    src.extend(glob.glob(os.path.join(BUILD_DIR, "CPackConfig.txt")))
    src.extend(glob.glob(os.path.join(BUILD_DIR, "CPackConfig.cmake")))

    for filename in src:
        outpath = os.path.join(SRC_DIR, os.path.basename(filename))
        logger.info("%s -> %s" % (filename, outpath))
        shutil.copy(filename, outpath)

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

    # if prebuilt libraries are available, use those and cancel build
    if os.path.exists(os.path.join(ROOT_DIR, 'prebuilt', LIBRARY_FILE)):
        logger.info('Using prebuilt libraries')
        shutil.copy(os.path.join(ROOT_DIR, 'prebuilt', LIBRARY_FILE), LIBS_DIR)
        return

    os.chdir(BUILD_DIR)

    # platform description refers at https://docs.python.org/3/library/sys.html#sys.platform
    # Use cmake for both Darwin and Windows since it can generate fat binaries
    if SYSTEM == "win32" or SYSTEM == 'darwin':
        # Windows build: this process requires few things:
        #    - CMake + MSVC installed
        #    - Run this command in an environment setup for MSVC
        if not os.path.exists("build"):
            os.mkdir("build")
        os.chdir("build")
        print("Build Directory: {}\n".format(os.getcwd()))
        # Only build capstone.dll / libcapstone.dylib
        if SYSTEM in ('win32', 'cygwin'):
            os.system('cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DBUILD_STATIC_LIBS=OFF -DCAPSTONE_BUILD_TESTS=OFF -DCAPSTONE_BUILD_CSTOOL=OFF -G "NMake Makefiles" ..')
        else:
            os.system('cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCAPSTONE_BUILD_TESTS=OFF -DCAPSTONE_BUILD_CSTOOL=OFF -G "Unix Makefiles" ..')
        os.system("cmake --build .")
    else:  # Unix incl. cygwin
        os.system("CAPSTONE_BUILD_CORE_ONLY=yes bash ./make.sh")

    shutil.copy(VERSIONED_LIBRARY_FILE, os.path.join(LIBS_DIR, LIBRARY_FILE))
    os.chdir(cwd)


class custom_sdist(sdist):
    def run(self):
        clean_bins()
        copy_sources()
        return sdist.run(self)


class custom_build(build):
    def run(self):
        if 'LIBCAPSTONE_PATH' in os.environ:
            logger.info('Skipping building C extensions since LIBCAPSTONE_PATH is set')
        else:
            logger.info('Building C extensions')
            build_libraries()
        return build.run(self)


class custom_bdist_egg(bdist_egg):
    def run(self):
        self.run_command('build')
        return bdist_egg.run(self)

def dummy_src():
    return []

cmdclass = {}
cmdclass['build'] = custom_build
cmdclass['sdist'] = custom_sdist
cmdclass['bdist_egg'] = custom_bdist_egg

try:
    from setuptools.command.develop import develop
    class custom_develop(develop):
        def run(self):
            logger.info("Building C extensions")
            build_libraries()
            return develop.run(self)

    cmdclass['develop'] = custom_develop
except ImportError:
    print("Proper 'develop' support unavailable.")

if 'bdist_wheel' in sys.argv and '--plat-name' not in sys.argv:
    # Inject the platform identifier into argv.
    # Platform tags are described here:
    # https://packaging.python.org/en/latest/specifications/platform-compatibility-tags
    #
    # I couldn't really find out in time why we need to inject the platform here?
    # The cibuildwheel doesn't need it for the Windows job. But for Mac and Linux.
    # This here is very dirty and will maybe break in the future.
    # Sorry if this is the case and you read this.
    # See: https://github.com/capstone-engine/capstone/issues/2445
    idx = sys.argv.index('bdist_wheel') + 1
    sys.argv.insert(idx, '--plat-name')
    name = get_platform()
    sys.argv.insert(idx + 1, name.replace('.', '_').replace('-', '_'))

setup(
    provides=['capstone'],
    packages=['capstone'],
    name='capstone',
    version=VERSION,
    author='Nguyen Anh Quynh',
    author_email='aquynh@gmail.com',
    description='Capstone disassembly engine',
    url='https://www.capstone-engine.org',
    long_description=open('README.txt', encoding="utf8").read(),
    long_description_content_type='text/markdown',
    python_requires='>=3.8',
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
    ],
    cmdclass=cmdclass,
    zip_safe=False,
    include_package_data=True,
    package_data={
        "capstone": ["lib/*", "include/capstone/*"],
    },
    install_requires=[
        "importlib_resources;python_version<'3.9'",
    ],
)
