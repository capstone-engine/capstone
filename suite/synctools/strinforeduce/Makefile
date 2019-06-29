all: full reduce

full:
	g++ strinforeduce.cpp -o strinforeduce

reduce:
	g++ -DCAPSTONE_X86_REDUCE strinforeduce.cpp -o strinforeduce_reduce

clean:
	rm -rf strinforeduce strinforeduce_reduce
