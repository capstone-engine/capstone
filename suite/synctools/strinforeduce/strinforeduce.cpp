// By Martin Tofall, Obsidium Software
#define GET_INSTRINFO_ENUM
#define GET_INSTRINFO_MC_DESC

#ifdef CAPSTONE_X86_REDUCE
#include "X86GenInstrInfo_reduce.inc"
#else
#include "X86GenInstrInfo.inc"
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string>

static const char *x86DisassemblerGetInstrName(unsigned Opcode)
{
	return &llvm::X86InstrNameData[llvm::X86InstrNameIndices[Opcode]];
}

static bool is16BitEquivalent(const char* orig, const char* equiv)
{
	size_t i;

	for (i = 0;; i++) {
		if (orig[i] == '\0' && equiv[i] == '\0')
			return true;

		if (orig[i] == '\0' || equiv[i] == '\0')
			return false;

		if (orig[i] != equiv[i]) {
			if ((orig[i] == 'Q' || orig[i] == 'L') && equiv[i] == 'W')
				continue;

			if ((orig[i] == '6' || orig[i] == '3') && equiv[i] == '1')
				continue;

			if ((orig[i] == '4' || orig[i] == '2') && equiv[i] == '6')
				continue;

			return false;
		}
	}
}

// static const char *header = "#ifdef GET_INSTRINFO_MC_DESC\n#undef GET_INSTRINFO_MC_DESC\n\n"
static const char *header = 
	"typedef struct x86_op_id_pair {\n"\
	"\tuint16_t first;\n" \
	"\tuint16_t second;\n" \
	"} x86_op_id_pair;\n\n" \
	"static const x86_op_id_pair x86_16_bit_eq_tbl[] = {\n";
static const char *footer = "};\n\n";

static const char *header_lookup = "static const uint16_t x86_16_bit_eq_lookup[] = {\n";
//static const char *footer_lookup = "};\n\n#endif\n";
static const char *footer_lookup = "};\n";

static bool is16BitEquivalent_old(unsigned id1, unsigned id2)
{
	return (is16BitEquivalent(x86DisassemblerGetInstrName(id1), x86DisassemblerGetInstrName(id2))) != false;
}

//#include "reduced.h"

#if 0
static bool is16BitEquivalent_new(unsigned orig, unsigned equiv)
{
	size_t i;
	uint16_t idx;

	if (orig == equiv)
		return true;	// emulate old behaviour

	if ((idx = x86_16_bit_eq_lookup[orig]) != 0) {
		for (i = idx - 1; x86_16_bit_eq_tbl[i].first == orig; ++i) {
			if (x86_16_bit_eq_tbl[i].second == equiv)
				return true;
		}
	}

	return false;
}
#endif

int main()
{
	size_t size_names = sizeof(llvm::X86InstrNameData);
	size_t size_indices = sizeof(llvm::X86InstrNameIndices);
	size_t size_total = size_names + size_indices;

#if 1
	printf("%s", header);

	size_t eq_count = 0;
	std::string str_lookup;
	bool got_i = false;

	for (size_t i = 0; i < llvm::X86::INSTRUCTION_LIST_END; ++i) {
		const char *name1 = x86DisassemblerGetInstrName(i);
		for (size_t j = 0; j < llvm::X86::INSTRUCTION_LIST_END; ++j) {
			const char *name2 = x86DisassemblerGetInstrName(j);
			if (i != j && is16BitEquivalent(name1, name2) != false) {
				//printf("Found equivalent %d and %d\n", i, j);
				printf("\t{ %zu, %zu },\n", i, j);
				if (!got_i) {
					char buf[16];
					sprintf(buf, "\t%zu,\n", eq_count + 1);
					str_lookup += buf;

					got_i = true;
				}
				++eq_count;
			}
		}

		if (!got_i) {
			//char buf[32];
			//sprintf(buf, "\t0, //%d\n", i);
			//str_lookup += buf;
			str_lookup += "\t0,\n";
		}

		// reset got_i
		got_i = false;
	}

	printf("%s", footer);
	printf("%s", header_lookup);
	printf("%s", str_lookup.c_str());
	printf("%s", footer_lookup);

	// printf("%zu equivalents total\n", eq_count);
	// size_t size_new = eq_count * 4 + llvm::X86::INSTRUCTION_LIST_END * 2;
	// printf("before: %zu, after: %zu, %zu bytes saved\n", size_total, size_new, size_total - size_new);
#endif

#if 0
		for (size_t i = 0; i < llvm::X86::INSTRUCTION_LIST_END; ++i) {
			for (size_t j = 0; j < llvm::X86::INSTRUCTION_LIST_END; ++j) {
				if (is16BitEquivalent_new(i, j) != is16BitEquivalent_old(i, j)) {
					bool old_result = is16BitEquivalent_old(i, j);
					bool new_result = is16BitEquivalent_new(i, j);
					printf("ERROR!\n");
				}
			}
		}
#endif

#if 0
	static const size_t BENCH_LOOPS = 50;

	size_t eq_count = 0;
	DWORD time = GetTickCount();
	for (size_t l = 0; l < BENCH_LOOPS; ++l) {
		for (size_t i = 0; i < llvm::X86::INSTRUCTION_LIST_END; ++i) {
			for (size_t j = 0; j < llvm::X86::INSTRUCTION_LIST_END; ++j)
				if (is16BitEquivalent_new(i, j))
					++eq_count;
		}
	}

	time = GetTickCount() - time;
	printf("new: %f msecs\n", static_cast<float>(time) / static_cast<float>(BENCH_LOOPS));

	eq_count = 0;
	time = GetTickCount();
	for (size_t l = 0; l < BENCH_LOOPS; ++l) {
		for (size_t i = 0; i < llvm::X86::INSTRUCTION_LIST_END; ++i) {
			for (size_t j = 0; j < llvm::X86::INSTRUCTION_LIST_END; ++j)
				if (is16BitEquivalent_old(i, j))
					++eq_count;
		}
	}

	time = GetTickCount() - time;
	printf("old: %f msecs\n", static_cast<float>(time) / static_cast<float>(BENCH_LOOPS));
#endif

	return 0;
}

