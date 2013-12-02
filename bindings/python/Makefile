.PHONY: all clean install

all:
	cd ..; python const_generator.py python

install:
	python setup.py install

clean:
	rm -rf capstone/*.pyc capstone/*_const.py
	rm -rf capstone/*.so *.dll *.pyc *.dylib
