LIBNAME = capstone

invalid_read_in_print_operand: invalid_read_in_print_operand.o
	${CC} $< -O3 -Wall -l$(LIBNAME) -o $@

%.o: %.c
	${CC} -c -I../../include $< -o $@

clean:
	rm -rf *.o invalid_read_in_print_operand
