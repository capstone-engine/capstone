.PHONY: all clean install

gen_const:
	cd ..; python const_generator.py python

install:
	python setup.py install

install_cython:
	python setup_cython.py install

clean:
	rm -rf capstone/*.pyc
	rm -rf capstone/*.so
	rm -rf capstone/*.c
	rm -rf *.so *.dll *.pyc *.dylib
