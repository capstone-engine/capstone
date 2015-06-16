LIBNAME = capstone

fuzz_harness: fuzz_harness.o
	${CC} $< -O3 -Wall -l$(LIBNAME) -o $@

%.o: %.c
	${CC} -c -I../../include $< -o $@

clean:
	rm -rf *.o fuzz_harness
