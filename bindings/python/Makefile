ifndef BUILDDIR
OBJDIR = ./build
else
OBJDIR = $(abspath $(BUILDDIR))/obj/bindings/python
endif

.PHONY: gen_const install install3 install_cython clean

gen_const:
	cd .. && python const_generator.py python

install:
	rm -rf $(OBJDIR)
	python setup.py build -b $(OBJDIR) install

install3:
	rm -rf $(OBJDIR)
	python3 setup.py build -b $(OBJDIR) install

# NOTE: Newer cython can be installed by: sudo pip install --upgrade cython
install_cython:
	rm -rf $(OBJDIR)
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

clean:
	rm -rf $(OBJDIR)
	rm -f capstone/*.so


TESTS = test.py test_detail.py test_arm.py test_arm64.py test_mips.py test_ppc.py
TESTS += test_sparc.py test_systemz.py test_x86.py test_xcore.py test_skipdata.py
check:
	@for t in $(TESTS); do \
		echo Check $$t ... ; \
		./$$t > /dev/null && echo OK || echo FAILED; \
	done

