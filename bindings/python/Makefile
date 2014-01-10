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
	# Copy code from capstone/ to cython/
	cp capstone/__init__.py cython/__init__.py
	cp capstone/capstone.py cython/capstone.pyx
	cp capstone/arm.py cython/arm.pyx
	cp capstone/arm_const.py cython/arm_const.pyx
	cp capstone/arm64.py cython/arm64.pyx
	cp capstone/arm64_const.py cython/arm64_const.pyx
	cp capstone/mips.py cython/mips.pyx
	cp capstone/mips_const.py cython/mips_const.pyx
	cp capstone/ppc.py cython/ppc.pyx
	cp capstone/ppc_const.py cython/ppc_const.pyx
	cp capstone/x86.py cython/x86.pyx
	cp capstone/x86_const.py cython/x86_const.pyx
	# clean up first
	rm -rf build
	# then install
	python setup_cython.py install

clean:
	rm -rf capstone/*.pyc
	rm -rf capstone/*.so
	rm -rf capstone/*.c
	rm -rf cython/*.py*
	rm -rf cython/*.so
	rm -rf cython/*.c
	rm -rf *.so *.dll *.pyc *.dylib
