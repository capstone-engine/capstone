0. This documentation explains how to install Python binding for Capstone
   from source. If you want to install it from PyPi package, see the below
   docs instead:

   - README.pypi-src: How to compile the Capstone core & install binding
     at the same time from PyPi package "capstone"

   - README.pypi-win: How to install binding for Windows from PyPi package
     "capstone-windows". Note that this package already has prebuilt core
     inside, so no compilation is needed.

1. To install pure Python binding on *nix, run the command below:

		$ sudo make install

   To install Python3 binding package, run the command below:
   (Note: this requires python3 installed in your machine)

		$ sudo make install3

2. For better Python performance, install cython-based binding with:

		$ sudo make install_cython

	Note that this requires cython installed in your machine first.
	To install cython, see section 3 below.
	
3. To install cython, you have to ensure that the header files
   and the static library for Python are installed beforehand.

	E.g. on Ubuntu, do:

		$ sudo apt-get install python-dev

	Depending on if you already have pip or easy_install
	installed, install cython with either:

		$ sudo pip install cython
	or:
		$ sudo easy_install cython

	NOTE: Depending on your distribution you might also be able to
	      install the required cython version using your repository.

	E.g. on Ubuntu, do:
	
		$ sudo apt-get install cython

	However, our cython-based binding requires cython version 0.19 or newer,
	but sometimes distributions only provide older version. Make sure to
	verify the current installed version before going into section 2 above.
	
	E.g, on Ubuntu, you can verify the current cython version with:

		$ apt-cache policy cython

	Which should at least print version 0.19


This directory contains some test code to show how to use Capstone API.

- test.py
  This code shows the most simple form of API where we only want to get basic
  information out of disassembled instruction, such as address, mnemonic and
  operand string.

- test_lite.py
  Similarly to test.py, but this code shows how to use disasm_lite(), a lighter
  method to disassemble binary. Unlike disasm() API (used by test.py), which returns
  CsInsn objects, this API just returns tuples of (address, size, mnemonic, op_str).

  The main reason for using this API is better performance: disasm_lite() is at least
  20% faster than disasm(). Memory usage is also less. So if you just need basic
  information out of disassembler, use disasm_lite() instead of disasm().

- test_detail.py:
  This code shows how to access to architecture-neutral information in disassembled
  instructions, such as implicit registers read/written, or groups of instructions
  that this instruction belong to.

- test_<arch>.py
  These code show how to access architecture-specific information for each
  architecture.


2. To install Python binding on Windows:

Recommended method:

	Use the Python module installer for 32/64 bit Windows from:

		http://www.capstone-engine.org/download.html


Manual method:

	If the module installer fails to locate your Python install, or if you have
	additional Python installs (e.g. Anaconda / virtualenv), run the following
	command in command prompt:

		C:\> C:\location_to_python\python.exe setup.py install

	Next, copy capstone.dll from the 'Core engine for Windows' package available
	on the same Capstone download page and paste it in the path:

		C:\location_to_python\Lib\site-packages\capstone\
