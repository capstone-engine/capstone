# SPDX-FileCopyrightText: 2024 Antelox <anteloxrce@gmail.com>
# SPDX-License-Identifier: BSD-3

import glob
import logging
import os
import shutil
import sys
from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.sdist import sdist

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# are we building from the repository or from a source distribution?
ROOT_DIR = os.path.dirname(os.path.realpath(__file__))
LIBS_DIR = os.path.join(ROOT_DIR, 'capstone', 'lib')
HEADERS_DIR = os.path.join(ROOT_DIR, 'capstone', 'include')
SRC_DIR = os.path.join(ROOT_DIR, 'src')
BUILD_DIR = SRC_DIR if os.path.exists(SRC_DIR) else os.path.join(ROOT_DIR, '../..')
BUILD_PYTHON = os.path.join(BUILD_DIR, 'build_python')

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

if sys.platform == 'darwin':
    VERSIONED_LIBRARY_FILE = "libcapstone.{PKG_MAJOR}.dylib".format(**VERSION_DATA)
    LIBRARY_FILE = "libcapstone.dylib"
elif sys.platform in ('win32', 'cygwin'):
    VERSIONED_LIBRARY_FILE = "capstone.dll"
    LIBRARY_FILE = "capstone.dll"
else:
    VERSIONED_LIBRARY_FILE = "libcapstone.so.{PKG_MAJOR}".format(**VERSION_DATA)
    LIBRARY_FILE = "libcapstone.so"


def clean_bins():
    shutil.rmtree(LIBS_DIR, ignore_errors=True)
    shutil.rmtree(HEADERS_DIR, ignore_errors=True)


def copy_sources():
    """
    Copy the C sources into the source directory.
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
    shutil.copytree(os.path.join(BUILD_DIR, "LICENSES"), os.path.join(SRC_DIR, "LICENSES"))

    src.extend(glob.glob(os.path.join(BUILD_DIR, "*.[ch]")))
    src.extend(glob.glob(os.path.join(BUILD_DIR, "*.m[dk]")))
    src.extend(glob.glob(os.path.join(BUILD_DIR, "*.in")))
    src.extend(glob.glob(os.path.join(BUILD_DIR, "SPONSORS.TXT")))
    src.extend(glob.glob(os.path.join(BUILD_DIR, "CREDITS.TXT")))
    src.extend(glob.glob(os.path.join(BUILD_DIR, "ChangeLog")))
    src.extend(glob.glob(os.path.join(BUILD_DIR, "CMakeLists.txt")))
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

    if not os.path.exists(BUILD_PYTHON):
        os.mkdir(BUILD_PYTHON)

    logger.info("Build Directory: {}\n".format(BUILD_PYTHON))

    conf = 'Debug' if int(os.getenv('DEBUG', 0)) else 'Release'
    cmake_args = ['cmake',
                  '-DCAPSTONE_BUILD_SHARED_LIBS=ON',
                  '-DCAPSTONE_BUILD_STATIC_LIBS=OFF',
                  '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
                  '-DCAPSTONE_BUILD_CSTOOL=OFF'
                  ]
    cmake_build = ['cmake',
                   '--build',
                   '.'
                   ]
    os.chdir(BUILD_PYTHON)

    if sys.platform in ('win32', 'cygwin'):
        # Windows build: this process requires few things:
        #    - MSVC installed
        #    - Run this command in an environment setup for MSVC
        cmake_args += ['-DCMAKE_BUILD_TYPE=' + conf,
                       '-G "NMake Makefiles"'
                       ]
    elif 'AFL_NOOPT' in os.environ:
        # build for test_corpus
        pass
    else:
        cmake_args += ['-DCMAKE_BUILD_TYPE=' + conf,
                       '-G "Unix Makefiles"'
                       ]
        cmake_build += ['-j', str(os.getenv("THREADS", "4"))]

    os.system(' '.join(cmake_args + ['..']))
    os.system(' '.join(cmake_build))

    shutil.copy(VERSIONED_LIBRARY_FILE, os.path.join(LIBS_DIR, LIBRARY_FILE))
    os.chdir(cwd)


class CustomSDist(sdist):
    def run(self):
        clean_bins()
        copy_sources()
        return super().run()


class CustomBuild(build_py):
    def run(self):
        if 'LIBCAPSTONE_PATH' in os.environ:
            logger.info('Skipping building C extensions since LIBCAPSTONE_PATH is set')
        else:
            logger.info('Building C extensions')
            build_libraries()
        return super().run()


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
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
    ],
    cmdclass={'build_py': CustomBuild, 'sdist': CustomSDist},
    package_data={
        "capstone": ["lib/*", "include/capstone/*"],
    },
    has_ext_modules=lambda: True,  # It's not a Pure Python wheel
    install_requires=[
        "importlib_resources;python_version<'3.9'",
    ],
)
