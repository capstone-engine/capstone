PYX_BUILDDIR=build_pyx

.PHONY: gen_const install install3 install_cython clean

gen_const:
	cd .. && python const_generator.py python

install:
	rm -rf src/
	rm -rf prebuilt/win64/capstone.dll
	rm -rf prebuilt/win32/capstone.dll
	if test -n "${DESTDIR}"; then \
		python setup.py build install --root="${DESTDIR}"; \
	else \
		python setup.py build install; \
	fi

install3:
	rm -rf src/
	rm -rf prebuilt/win64/capstone.dll
	rm -rf prebuilt/win32/capstone.dll
	if test -n "${DESTDIR}"; then \
		python3 setup.py build install --root="${DESTDIR}"; \
	else \
		python3 setup.py build install; \
	fi

# NOTE: Newer cython can be installed by: sudo pip install --upgrade cython
install_cython:
	rm -rf src/ dist/
	rm -rf prebuilt/win64/capstone.dll
	rm -rf prebuilt/win32/capstone.dll
	mkdir -p $(PYX_BUILDDIR)/pyx
	cp setup_cython.py $(PYX_BUILDDIR)
	cp pyx/ccapstone* $(PYX_BUILDDIR)/pyx/
	cp capstone/__init__.py $(PYX_BUILDDIR)/pyx/__init__.py
	cp capstone/arm.py $(PYX_BUILDDIR)/pyx/arm.pyx
	cp capstone/arm_const.py $(PYX_BUILDDIR)/pyx/arm_const.pyx
	cp capstone/arm64.py $(PYX_BUILDDIR)/pyx/arm64.pyx
	cp capstone/arm64_const.py $(PYX_BUILDDIR)/pyx/arm64_const.pyx
	cp capstone/mips.py $(PYX_BUILDDIR)/pyx/mips.pyx
	cp capstone/mips_const.py $(PYX_BUILDDIR)/pyx/mips_const.pyx
	cp capstone/ppc.py $(PYX_BUILDDIR)/pyx/ppc.pyx
	cp capstone/ppc_const.py $(PYX_BUILDDIR)/pyx/ppc_const.pyx
	cp capstone/sparc.py $(PYX_BUILDDIR)/pyx/sparc.pyx
	cp capstone/sparc_const.py $(PYX_BUILDDIR)/pyx/sparc_const.pyx
	cp capstone/systemz.py $(PYX_BUILDDIR)/pyx/systemz.pyx
	cp capstone/sysz_const.py $(PYX_BUILDDIR)/pyx/sysz_const.pyx
	cp capstone/x86.py $(PYX_BUILDDIR)/pyx/x86.pyx
	cp capstone/x86_const.py $(PYX_BUILDDIR)/pyx/x86_const.pyx
	cp capstone/xcore.py $(PYX_BUILDDIR)/pyx/xcore.pyx
	cp capstone/xcore_const.py $(PYX_BUILDDIR)/pyx/xcore_const.pyx
	cd $(PYX_BUILDDIR) && python setup_cython.py build -b ./tmp install --home=$(PYX_BUILDDIR)
	mv $(PYX_BUILDDIR)/build/lib/python/capstone/* capstone
	cd $(PYX_BUILDDIR) && python setup_cython.py build -b ./tmp install

# build & upload PyPi package with source code of the core
sdist:
	rm -rf src/ dist/
	rm -rf prebuilt/win64/capstone.dll
	rm -rf prebuilt/win32/capstone.dll
	cp README.pypi-src README
	cp PKG-INFO.src PKG-INFO
	python setup.py sdist register upload

# build & upload PyPi package with source code of the core
sdist3:
	rm -rf src/ dist/
	rm -rf prebuilt/win64/capstone.dll
	rm -rf prebuilt/win32/capstone.dll
	cp README.pypi-src README
	cp PKG-INFO.src PKG-INFO
	python3 setup.py sdist register upload

# build & upload PyPi package with prebuilt core
# NOTE: be sure to have precompiled core under prebuilt/win*/ beforehand
sdist_win:
	rm -rf src/ dist/
	cp README.pypi-win README
	cp PKG-INFO.win PKG-INFO
	python setup.py sdist register upload

# build & upload PyPi package with prebuilt core
# NOTE: be sure to have precompiled core under prebuilt/win*/ beforehand
sdist3_win:
	rm -rf src/ dist/
	cp README.pypi-win README
	cp PKG-INFO.win PKG-INFO
	python3 setup.py sdist register upload

clean:
	rm -rf $(PYX_BUILDDIR) build/ src/ dist/ *.egg-info README
	rm -rf capstone/lib capstone/include
	rm -rf prebuilt/win64/capstone.dll
	rm -rf prebuilt/win32/capstone.dll


TESTS = test_basic.py test_detail.py test_arm.py test_arm64.py test_m68k.py test_mips.py
TESTS += test_ppc.py test_sparc.py test_systemz.py test_x86.py test_xcore.py test_skipdata.py
check:
	@for t in $(TESTS); do \
		echo Check $$t ... ; \
		./$$t > /dev/null; \
		if [ $$? -eq 0 ]; then echo OK; else echo FAILED; exit 1; fi \
	done

