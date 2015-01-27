#!/usr/bin/env python
import glob
import os
import platform
import shutil

from distutils import log
from distutils import dir_util
from distutils.command.build_clib import build_clib
from distutils.command.sdist import sdist
from distutils.core import setup


VERSION = '3.0'
SYSTEM = platform.system().lower()


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
    """Returns a list of C source files that should be compiled to
    create the library.
    """
    result = []
    # Make the src directory if it does not exist.
    if not os.access("./src/", os.F_OK):
        custom_sdist.copy_sources()

    for root, _, files in os.walk("./src/"):
        for name in files:
            if name.endswith(".c"):
                result.append(os.path.join(root, name))

    return result


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
        for (lib_name, build_info) in libraries:
            sources = self.get_source_files()
            sources = list(sources)

            log.info("building '%s' library", lib_name)

            # Darwin systems must produce shared libraries with this extension.
            if "darwin" in SYSTEM:
                self.compiler.shared_lib_extension = ".dylib"

            # First, compile the source code to object files in the
            # library directory.
            macros = build_info.get('macros')
            include_dirs = build_info.get('include_dirs')
            objects = self.compiler.compile(
                sources,
                output_dir=self.build_temp,
                macros=macros,
                include_dirs=include_dirs,
                extra_postargs=build_info.get('extra_compile_args', []),
                debug=self.debug)

            # Then link the object files and put the result in the
            # package build directory.
            package = build_info.get('package', '')
            self.compiler.link_shared_lib(
                objects, lib_name,
                output_dir=os.path.join(self.build_clib, package),
                extra_preargs=build_info.get('extra_link_args', []),
                debug=self.debug,)

def get_compile_args():
    result = []
    for flag in ['CAPSTONE_X86_ATT_DISABLE_NO', 'CAPSTONE_DIET_NO',
                 'CAPSTONE_X86_REDUCE_NO', 'CAPSTONE_HAS_ARM',
                 'CAPSTONE_HAS_ARM64', 'CAPSTONE_HAS_MIPS',
                 'CAPSTONE_HAS_POWERPC', 'CAPSTONE_HAS_SPARC',
                 'CAPSTONE_HAS_SYSZ', 'CAPSTONE_HAS_X86',
                 'CAPSTONE_HAS_XCORE', 'CAPSTONE_USE_SYS_DYN_MEM',
                 "CAPSTONE_SHARED"]:

        if "windows" in SYSTEM:
            result.append("/D")
        else:
            result.append("-D")
        result.append(flag)

    if "windows" in SYSTEM:
        result += ['/GL', '/Ox', '/Ob1', '/Oy',
                   '/nologo', '/c', '/TC']

    elif "darwin" in SYSTEM:
        result += ['-arch', 'i386', '-arch', 'x86_64', '-O2',
                   '-Wall', '-fPIC']

    else:
        result += ['-fPIC', '-O2', '-Wall']

    return result

def get_link_args():
    result = []
    if "windows" in SYSTEM:
        result = [
            '/MANIFEST',
            '/LTCG',
        ]

    return result


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
    ],
    requires=['ctypes'],
    cmdclass=dict(
        build_clib=custom_build_clib,
        sdist=custom_sdist,
    ),

    libraries=[(
        'capstone', dict(
            package='capstone',
            sources=LazyList(get_sources),
            include_dirs=['./src/include/'],
            extra_compile_args=get_compile_args(),
            extra_link_args=get_link_args(),
        ),
    )],
)
