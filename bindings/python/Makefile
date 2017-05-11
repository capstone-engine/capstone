.PHONY: gen_const install install3 install_cython sdist sdist3 bdist bdist3 clean check

gen_const:
	cd .. && python const_generator.py python

install:
	rm -rf src/
	if test -n "${DESTDIR}"; then \
		python setup.py build install --root="${DESTDIR}"; \
	else \
		python setup.py build install; \
	fi

install3:
	rm -rf src/
	if test -n "${DESTDIR}"; then \
		python3 setup.py build install --root="${DESTDIR}"; \
	else \
		python3 setup.py build install; \
	fi

# NOTE: Newer cython can be installed by: sudo pip install --upgrade cython
install_cython:
	rm -rf src/
	if test -n "${DESTDIR}"; then \
		python setup_cython.py build install --root="${DESTDIR}"; \
	else \
		python setup_cython.py build install; \
	fi

install3_cython:
	rm -rf src/
	if test -n "${DESTDIR}"; then \
		python3 setup_cython.py build install --root="${DESTDIR}"; \
	else \
		python3 setup_cython.py build install; \
	fi

# build & upload PyPi package with source code of the core
sdist:
	rm -rf src/ dist/
	python setup.py sdist register upload

# build & upload PyPi package with source code of the core
sdist3:
	rm -rf src/ dist/
	python3 setup.py sdist register upload

# build & upload PyPi package with prebuilt core
bdist:
	rm -rf src/ dist/
	python setup.py bdist_wheel register upload

# build & upload PyPi package with prebuilt core
bdist3:
	rm -rf src/ dist/
	python3 setup.py bdist_wheel register upload

clean:
	rm -rf build/ src/ dist/ *.egg-info
	rm -rf capstone/lib capstone/include pyx/lib pyx/include
	rm -f pyx/*.c pyx/__init__.py
	for f in capstone/*.py; do rm -f pyx/$$(basename $$f)x; done
	rm -f MANIFEST


TESTS = test_basic.py test_detail.py test_arm.py test_arm64.py test_mips.py test_ppc.py
TESTS += test_sparc.py test_systemz.py test_x86.py test_xcore.py test_skipdata.py
check:
	@for t in $(TESTS); do \
		echo Check $$t ... ; \
		./$$t > /dev/null && echo OK || echo FAILED; \
	done

