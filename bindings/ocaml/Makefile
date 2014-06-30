# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

LIB = capstone
FLAGS = '-Wall -Wextra -Wwrite-strings'

all: arm.cmxa arm64.cmxa mips.cmxa ppc.cmxa x86.cmxa capstone.cmxa test.cmx test_detail.cmx test_x86.cmx test_arm.cmx test_arm64.cmx test_mips.cmx test_ppc.cmx ocaml.o
	ocamlopt -o test -ccopt $(FLAGS) ocaml.o capstone.cmx test.cmx -cclib -l$(LIB)
	ocamlopt -o test_detail -ccopt $(FLAGS) capstone.cmx ocaml.o test_detail.cmx -cclib -l$(LIB)
	ocamlopt -o test_x86 -ccopt $(FLAGS) capstone.cmx ocaml.o x86.cmx test_x86.cmx -cclib -l$(LIB)
	ocamlopt -o test_arm -ccopt $(FLAGS) capstone.cmx ocaml.o arm.cmx test_arm.cmx -cclib -l$(LIB)
	ocamlopt -o test_arm64 -ccopt $(FLAGS) capstone.cmx ocaml.o arm64.cmx test_arm64.cmx -cclib -l$(LIB)
	ocamlopt -o test_mips -ccopt $(FLAGS) capstone.cmx ocaml.o mips.cmx test_mips.cmx -cclib -l$(LIB)
	ocamlopt -o test_ppc -ccopt $(FLAGS) capstone.cmx ocaml.o ppc.cmx test_ppc.cmx -cclib -l$(LIB)

test.cmx: test.ml
	ocamlopt -ccopt $(FLAGS) -c $< -cclib -l$(LIB)

test_detail.cmx: test_detail.ml
	ocamlopt -ccopt $(FLAGS) -c $< -cclib -l$(LIB)

test_x86.cmx: test_x86.ml
	ocamlopt -ccopt $(FLAGS) -c $< -cclib -l$(LIB)

test_arm.cmx: test_arm.ml
	ocamlopt -ccopt $(FLAGS) -c $< -cclib -l$(LIB)

test_arm64.cmx: test_arm64.ml
	ocamlopt -ccopt $(FLAGS) -c $< -cclib -l$(LIB)

test_mips.cmx: test_mips.ml
	ocamlopt -ccopt $(FLAGS) -c $< -cclib -l$(LIB)

test_ppc.cmx: test_ppc.ml
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

arm.mli: arm.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

arm.cmi: arm.mli
	ocamlc -ccopt $(FLAGS) -c $<

arm.cmx: arm.ml arm.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

arm.cmxa: arm.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

arm64.mli: arm64.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

arm64.cmi: arm64.mli
	ocamlc -ccopt $(FLAGS) -c $<

arm64.cmx: arm64.ml arm64.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

arm64.cmxa: arm64.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

mips.mli: mips.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

mips.cmi: mips.mli
	ocamlc -ccopt $(FLAGS) -c $<

mips.cmx: mips.ml mips.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

mips.cmxa: mips.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

ppc.mli: ppc.ml
	ocamlc -ccopt $(FLAGS) -i $< > $@

ppc.cmi: ppc.mli
	ocamlc -ccopt $(FLAGS) -c $<

ppc.cmx: ppc.ml ppc.cmi
	ocamlopt -ccopt $(FLAGS) -c $<

ppc.cmxa: ppc.cmx
	ocamlopt -ccopt $(FLAGS) -a -o $@ $<

clean:
	rm -f *.[oa] *.so *.cm[ixoa] *.cmxa *.mli test test_detail test_x86 test_arm test_arm64 test_mips

