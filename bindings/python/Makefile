.PHONY: all clean install install_cython

gen_const:
	cd ..; python const_generator.py python

install:
	# clean up first
	rm -rf build
	# then install
	python setup.py install

# NOTE: Newer cython can be installed by: sudo pip install --upgrade cython
install_cython:
	# Copy code from capstone/ to pyx/
	cp capstone/__init__.py pyx/__init__.py
	cp capstone/capstone.py pyx/capstone.pyx
	cp capstone/arm.py pyx/arm.pyx
	cp capstone/arm_const.py pyx/arm_const.pyx
	cp capstone/arm64.py pyx/arm64.pyx
	cp capstone/arm64_const.py pyx/arm64_const.pyx
	cp capstone/mips.py pyx/mips.pyx
	cp capstone/mips_const.py pyx/mips_const.pyx
	cp capstone/ppc.py pyx/ppc.pyx
	cp capstone/ppc_const.py pyx/ppc_const.pyx
	cp capstone/x86.py pyx/x86.pyx
	cp capstone/x86_const.py pyx/x86_const.pyx
	# clean up first
	rm -rf build
	# then install
	python setup_cython.py install

clean:
	rm -rf capstone/*.pyc
	rm -rf capstone/*.so
	rm -rf capstone/*.c
	rm -rf pyx/*.so
	rm -rf pyx/*.c
	rm -rf *.so *.dll *.pyc *.dylib
	rm -rf pyx/capstone.pyx
	rm -rf pyx/arm.pyx
	rm -rf pyx/arm_const.pyx
	rm -rf pyx/arm64.pyx
	rm -rf pyx/arm64_const.pyx
	rm -rf pyx/mips.pyx
	rm -rf pyx/mips_const.pyx
	rm -rf pyx/ppc.pyx
	rm -rf pyx/ppc_const.pyx
	rm -rf pyx/x86.pyx
	rm -rf pyx/x86_const.pyx
