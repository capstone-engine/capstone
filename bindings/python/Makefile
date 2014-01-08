.PHONY: all clean install

gen_const:
	cd ..; python const_generator.py python

install:
	python setup.py install

install_cython:
# NOTE: Newer cython can be installed by: sudo pip install --upgrade cython
	python setup_cython.py install

clean:
	rm -rf capstone/*.pyc
	rm -rf capstone/*.so
	rm -rf capstone/*.c
	rm -rf pyx/*.pyc
	rm -rf pyx/*.so
	rm -rf pyx/*.c
	rm -rf *.so *.dll *.pyc *.dylib
