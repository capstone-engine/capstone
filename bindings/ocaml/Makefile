# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015

LIB = capstone
FLAGS = '-Wall -Wextra -Wwrite-strings'
PYTHON2 ?= python

all: arm_const.cmxa arm64_const.cmxa m680x_const.cmxa mips_const.cmxa ppc_const.cmxa sparc_const.cmxa sysz_const.cmxa x86_const.cmxa xcore_const.cmxa arm.cmxa arm64.cmxa m680x.cmxa mips.cmxa ppc.cmxa x86.cmxa sparc.cmxa systemz.cmxa xcore.cmxa capstone.cmxa test_basic.cmx test_detail.cmx test_x86.cmx test_arm.cmx test_aarch64.cmx test_mips.cmx test_ppc.cmx test_sparc.cmx test_systemz.cmx test_xcore.cmx test_m680x.cmx ocaml.o
	ocamlopt -o test_basic -ccopt $(FLAGS) ocaml.o capstone.cmx test_basic.cmx -cclib -l$(LIB)
	ocamlopt -o test_detail -ccopt $(FLAGS) capstone.cmx ocaml.o test_detail.cmx -cclib -l$(LIB)
	ocamlopt -o test_x86 -ccopt $(FLAGS) capstone.cmx ocaml.o x86.cmx x86_const.cmx test_x86.cmx -cclib -l$(LIB)
	ocamlopt -o test_arm -ccopt $(FLAGS) capstone.cmx ocaml.o arm.cmx arm_const.cmx test_arm.cmx -cclib -l$(LIB)
	ocamlopt -o test_aarch64 -ccopt $(FLAGS) capstone.cmx ocaml.o arm64.cmx arm64_const.cmx test_aarch64.cmx -cclib -l$(LIB)
	ocamlopt -o test_mips -ccopt $(FLAGS) capstone.cmx ocaml.o mips.cmx mips_const.cmx test_mips.cmx -cclib -l$(LIB)
	ocamlopt -o test_ppc -ccopt $(FLAGS) capstone.cmx ocaml.o ppc.cmx ppc_const.cmx test_ppc.cmx -cclib -l$(LIB)
	ocamlopt -o test_sparc -ccopt $(FLAGS) capstone.cmx ocaml.o sparc.cmx sparc_const.cmx test_sparc.cmx -cclib -l$(LIB)
	ocamlopt -o test_systemz -ccopt $(FLAGS) capstone.cmx ocaml.o systemz.cmx sysz_const.cmx test_systemz.cmx -cclib -l$(LIB)
	ocamlopt -o test_xcore -ccopt $(FLAGS) capstone.cmx ocaml.o xcore.cmx xcore_const.cmx test_xcore.cmx -cclib -l$(LIB)
	ocamlopt -o test_m680x -ccopt $(FLAGS) capstone.cmx ocaml.o m680x.cmx m680x_const.cmx test_m680x.cmx -cclib -l$(LIB)


test_basic.cmx: test_basic.ml
	ocamlopt -ccopt $(FLAGS) -c $< -cclib -l$(LIB)

test_detail.cmx: test_detail.ml
	ocamlopt -ccopt $(FLAGS) -c $< -cclib -l$(LIB)

test_x86.cmx: test_x86.ml
	ocamlopt -ccopt $(FLAGS) -c $< -cclib -l$(LIB)

test_arm.cmx: test_arm.ml
	ocamlopt -ccopt $(FLAGS) -c $< -cclib -l$(LIB)

test_aarch64.cmx: test_aarch64.ml
	ocamlopt -ccopt $(FLAGS) -c $< -cclib -l$(LIB)

test_mips.cmx: test_mips.ml
	ocamlopt -ccopt $(FLAGS) -c $< -cclib -l$(LIB)

test_ppc.cmx: test_ppc.ml
	ocamlopt -ccopt $(FLAGS) -c $< -cclib -l$(LIB)

test_sparc.cmx: test_sparc.ml
	ocamlopt -ccopt $(FLAGS) -c $< -cclib -l$(LIB)

test_systemz.cmx: test_systemz.ml
	ocamlopt -ccopt $(FLAGS) -c $< -cclib -l$(LIB)

test_xcore.cmx: test_xcore.ml
	ocamlopt -ccopt $(FLAGS) -c $< -cclib -l$(LIB)

test_m680x.cmx: test_m680x.ml
	ocamlopt -ccopt $(FLAGS) -c $< -cclib -l$(LIB)

ocaml.o: ocaml.c
	ocamlc -ccopt $(FLAGS) -c $<

capstone.mli: capstone.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

capstone.cmi: capstone.mli
	ocamlc -ccopt $(FLAGS) -c $<

capstone.cmx: capstone.ml capstone.cmi
	ocamlopt -ccopt $(FLAGS) -c $< -cclib -l$(LIB)

capstone.cmxa: capstone.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $< -cclib -lsb_ocaml -cclib -l$(LIB)

x86.mli: x86.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

x86.cmi: x86.mli
	ocamlc -ccopt $(FLAGS) -c $<

x86.cmx: x86.ml x86.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

x86.cmxa: x86.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

x86_const.mli: x86_const.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

x86_const.cmi: x86_const.mli
	ocamlc -ccopt $(FLAGS) -c $<

x86_const.cmx: x86_const.ml x86_const.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

x86_const.cmxa: x86_const.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

arm.mli: arm.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

arm.cmi: arm.mli
	ocamlc -ccopt $(FLAGS) -c $<

arm.cmx: arm.ml arm.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

arm.cmxa: arm.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

arm_const.mli: arm_const.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

arm_const.cmi: arm_const.mli
	ocamlc -ccopt $(FLAGS) -c $<

arm_const.cmx: arm_const.ml arm_const.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

arm_const.cmxa: arm_const.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

arm64.mli: arm64.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

arm64.cmi: arm64.mli
	ocamlc -ccopt $(FLAGS) -c $<

arm64.cmx: arm64.ml arm64.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

arm64.cmxa: arm64.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

arm64_const.mli: arm64_const.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

arm64_const.cmi: arm64_const.mli
	ocamlc -ccopt $(FLAGS) -c $<

arm64_const.cmx: arm64_const.ml arm64_const.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

arm64_const.cmxa: arm64_const.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

m680x.mli: m680x.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

m680x.cmi: m680x.mli
	ocamlc -ccopt $(FLAGS) -c $<

m680x.cmx: m680x.ml m680x.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

m680x.cmxa: m680x.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

m680x_const.mli: m680x_const.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

m680x_const.cmi: m680x_const.mli
	ocamlc -ccopt $(FLAGS) -c $<

m680x_const.cmx: m680x_const.ml m680x_const.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

m680x_const.cmxa: m680x_const.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

mips.mli: mips.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

mips.cmi: mips.mli
	ocamlc -ccopt $(FLAGS) -c $<

mips.cmx: mips.ml mips.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

mips.cmxa: mips.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

mips_const.mli: mips_const.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

mips_const.cmi: mips_const.mli
	ocamlc -ccopt $(FLAGS) -c $<

mips_const.cmx: mips_const.ml mips_const.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

mips_const.cmxa: mips_const.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

ppc.mli: ppc.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

ppc.cmi: ppc.mli
	ocamlc -ccopt $(FLAGS) -c $<

ppc.cmx: ppc.ml ppc.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

ppc.cmxa: ppc.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

ppc_const.mli: ppc_const.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

ppc_const.cmi: ppc_const.mli
	ocamlc -ccopt $(FLAGS) -c $<

ppc_const.cmx: ppc_const.ml ppc_const.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

ppc_const.cmxa: ppc_const.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

sparc.mli: sparc.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

sparc.cmi: sparc.mli
	ocamlc -ccopt $(FLAGS) -c $<

sparc.cmx: sparc.ml sparc.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

sparc.cmxa: sparc.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

sparc_const.mli: sparc_const.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

sparc_const.cmi: sparc_const.mli
	ocamlc -ccopt $(FLAGS) -c $<

sparc_const.cmx: sparc_const.ml sparc_const.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

sparc_const.cmxa: sparc_const.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

systemz.mli: systemz.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

systemz.cmi: systemz.mli
	ocamlc -ccopt $(FLAGS) -c $<

systemz.cmx: systemz.ml systemz.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

systemz.cmxa: systemz.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

sysz_const.mli: sysz_const.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

sysz_const.cmi: sysz_const.mli
	ocamlc -ccopt $(FLAGS) -c $<

sysz_const.cmx: sysz_const.ml sysz_const.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

sysz_const.cmxa: sysz_const.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

xcore.mli: xcore.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

xcore.cmi: xcore.mli
	ocamlc -ccopt $(FLAGS) -c $<

xcore.cmx: xcore.ml xcore.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

xcore.cmxa: xcore.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

xcore_const.mli: xcore_const.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

xcore_const.cmi: xcore_const.mli
	ocamlc -ccopt $(FLAGS) -c $<

xcore_const.cmx: xcore_const.ml xcore_const.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

xcore_const.cmxa: xcore_const.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

clean:
	rm -f *.[oa] *.so *.cm[ixoa] *.cmxa *.mli test_basic test_detail test_x86 test_arm test_aarch64 test_mips test_ppc test_sparc test_systemz test_xcore test_m680x

gen_const:
	cd .. && $(PYTHON2) const_generator.py ocaml

TESTS = test_basic test_detail test_arm test_aarch64 test_m680x test_mips test_ppc
TESTS += test_sparc test_systemz test_x86 test_xcore
check:
	@for t in $(TESTS); do \
		echo Check $$t ... ; \
		./$$t > /dev/null && echo OK || echo FAILED; \
	done

