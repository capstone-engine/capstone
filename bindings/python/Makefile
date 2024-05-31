PYTHON2 ?= python2
PYTHON3 ?= python3

.PHONY: gen_const install sdist bdist clean check

gen_const:
	cd .. && $(PYTHON2) const_generator.py python

install:
	rm -rf src/
	if test -n "${DESTDIR}"; then \
		$(PYTHON2) setup.py build install --root="${DESTDIR}"; \
	else \
		$(PYTHON2) setup.py build install; \
	fi

install3:
	rm -rf src/
	if test -n "${DESTDIR}"; then \
		$(PYTHON3) setup.py build install --root="${DESTDIR}"; \
	else \
		$(PYTHON3) setup.py build install; \
	fi

# build & upload PyPi package with source code of the core
sdist:
	rm -rf src/ dist/
	$(PYTHON2) setup.py sdist register upload

# build & upload PyPi package with source code of the core
sdist3:
	rm -rf src/ dist/
	$(PYTHON3) setup.py sdist register upload

# build & upload PyPi package with prebuilt core
bdist:
	rm -rf src/ dist/
	$(PYTHON2) setup.py bdist_wheel register upload

# build & upload PyPi package with prebuilt core
bdist3:
	rm -rf src/ dist/
	$(PYTHON3) setup.py bdist_wheel register upload

clean:
	rm -rf build/ src/ dist/ *.egg-info
	rm -rf capstone/lib capstone/include pyx/lib pyx/include
	rm -f pyx/*.c pyx/__init__.py
	for f in capstone/*.py; do rm -f pyx/$$(basename $$f)x; done
	rm -f MANIFEST
	rm -f *.pyc capstone/*.pyc


TESTS = test_basic.py test_detail.py test_arm.py test_arm64.py test_m68k.py test_mips.py
TESTS += test_ppc.py test_sparc.py test_systemz.py test_x86.py test_xcore.py test_tms320c64x.py
TESTS += test_m680x.py test_skipdata.py test_mos65xx.py test_bpf.py test_riscv.py
TESTS += test_evm.py

check:
	@for t in $(TESTS); do \
		echo Check $$t ... ; \
		./$$t > /dev/null; \
		if [ $$? -eq 0 ]; then echo OK; else echo FAILED; exit 1; fi \
	done

