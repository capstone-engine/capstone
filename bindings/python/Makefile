ifndef BUILDDIR
OBJDIR = build
else
OBJDIR = $(abspath $(BUILDDIR))/obj/bindings/python
endif

.PHONY: gen_const install install3 install_cython clean

gen_const:
	cd .. && python const_generator.py python

install:
	rm -rf $(OBJDIR) src/
	rm -rf prebuilt/win64/capstone.dll
	rm -rf prebuilt/win32/capstone.dll
	if test -n "${DESTDIR}"; then \
		python setup.py build -b $(OBJDIR) install --root="${DESTDIR}"; \
	else \
		python setup.py build -b $(OBJDIR) install; \
	fi

install3:
	rm -rf $(OBJDIR) src/
	rm -rf prebuilt/win64/capstone.dll
	rm -rf prebuilt/win32/capstone.dll
	if test -n "${DESTDIR}"; then \
		python3 setup.py build -b $(OBJDIR) install --root="${DESTDIR}"; \
	else \
		python3 setup.py build -b $(OBJDIR) install; \
	fi

# NOTE: Newer cython can be installed by: sudo pip install --upgrade cython
install_cython:
	rm -rf $(OBJDIR) src/ dist/
	rm -rf prebuilt/win64/capstone.dll
	rm -rf prebuilt/win32/capstone.dll
	mkdir -p $(OBJDIR)/pyx
	cp setup_cython.py $(OBJDIR)
	cp pyx/ccapstone* $(OBJDIR)/pyx/
	cp capstone/__init__.py $(OBJDIR)/pyx/__init__.py
	cp capstone/arm.py $(OBJDIR)/pyx/arm.pyx
	cp capstone/arm_const.py $(OBJDIR)/pyx/arm_const.pyx
	cp capstone/arm64.py $(OBJDIR)/pyx/arm64.pyx
	cp capstone/arm64_const.py $(OBJDIR)/pyx/arm64_const.pyx
	cp capstone/mips.py $(OBJDIR)/pyx/mips.pyx
	cp capstone/mips_const.py $(OBJDIR)/pyx/mips_const.pyx
	cp capstone/ppc.py $(OBJDIR)/pyx/ppc.pyx
	cp capstone/ppc_const.py $(OBJDIR)/pyx/ppc_const.pyx
	cp capstone/sparc.py $(OBJDIR)/pyx/sparc.pyx
	cp capstone/sparc_const.py $(OBJDIR)/pyx/sparc_const.pyx
	cp capstone/systemz.py $(OBJDIR)/pyx/systemz.pyx
	cp capstone/sysz_const.py $(OBJDIR)/pyx/sysz_const.pyx
	cp capstone/x86.py $(OBJDIR)/pyx/x86.pyx
	cp capstone/x86_const.py $(OBJDIR)/pyx/x86_const.pyx
	cp capstone/xcore.py $(OBJDIR)/pyx/xcore.pyx
	cp capstone/xcore_const.py $(OBJDIR)/pyx/xcore_const.pyx
	cd $(OBJDIR) && python setup_cython.py build -b ./tmp install --home=$(OBJDIR)
	mv $(OBJDIR)/build/lib/python/capstone/* capstone
	cd $(OBJDIR) && python setup_cython.py build -b ./tmp install

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
	rm -rf $(OBJDIR) src/ dist/ README
	rm -f capstone/*.so
	rm -rf prebuilt/win64/capstone.dll
	rm -rf prebuilt/win32/capstone.dll


TESTS = test.py test_detail.py test_arm.py test_arm64.py test_mips.py test_ppc.py
TESTS += test_sparc.py test_systemz.py test_x86.py test_xcore.py test_skipdata.py
check:
	@for t in $(TESTS); do \
		echo Check $$t ... ; \
		./$$t > /dev/null && echo OK || echo FAILED; \
	done

