.PHONY: all clean install

gen_const:
	cd ..; python const_generator.py python

install:
	python setup.py install

clean:
	rm -rf capstone/*.pyc
	rm -rf capstone/*.so *.dll *.pyc *.dylib
