/* Capstone Disassembler Engine - Cross Platform */
/* VoltagedDebunked <rusindanilo@gmail.com> 2025 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <capstone/capstone.h>
#include <errno.h>

/* Platform-specific includes and definitions */
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#define PATH_SEPARATOR '\\'
#define open _open
#define close _close
#define read _read
#define lseek _lseek
#define fstat _fstat
#define stat _stat
#ifdef _MSC_VER
#define strtoull _strtoui64
#define strcasecmp _stricmp
#endif
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <strings.h>
#define PATH_SEPARATOR '/'
#ifndef strcasecmp
#define strcasecmp strcasecmp
#endif
#endif

/* Cross-platform getopt implementation for Windows */
#ifdef _WIN32
extern char *optarg;
extern int optind, opterr, optopt;

struct option {
	const char *name;
	int has_arg;
	int *flag;
	int val;
};

#define no_argument 0
#define required_argument 1
#define optional_argument 2

int getopt_long(int argc, char *const argv[], const char *optstring,
		const struct option *longopts, int *longindex);
#else
#include <getopt.h>
#endif

#define MAX_ARCH_NAME 16
#define MAX_FILE_SIZE (1024 * 1024 * 100) /* 100MB limit for safety */

typedef enum { BIN_RAW, BIN_ELF, BIN_MZ } binary_format_t;

typedef struct {
	csh handle;
	cs_arch arch;
	cs_mode mode;
	const char *filename;
	uint64_t base_addr;
	size_t start_offset;
	size_t limit;
	int color;
	int detail;
	binary_format_t format;
} csdump_opts_t;

/* Cross-platform file reading structure */
typedef struct {
	uint8_t *data;
	size_t size;
#ifdef _WIN32
	HANDLE file_handle;
	HANDLE mapping_handle;
#else
	int fd;
#endif
} file_mapping_t;

void usage(const char *prog)
{
	printf("Usage: %s [options] -i <file>\n", prog);
	puts("Options:");
	puts("  -a, --arch <arch>     Architecture (x86, arm, aarch64, mips, ppc, sparc, systemz, riscv, etc)");
	puts("  -m, --mode <mode>     Mode (16, 32, 64, thumb, etc)");
	puts("  -i, --input <file>    Input binary file");
	puts("  -b, --base <addr>     Base address (default 0x0)");
	puts("  -s, --start <offset>  Start offset in file");
	puts("  -l, --limit <bytes>   Max bytes to disassemble");
	puts("  -d, --detail          Enable detailed instruction info");
	puts("      --color           Enable colorized output");
	puts("  -h, --help            Show this help");
	puts("");
	puts("Supported architectures:");
	puts("  x86, arm, aarch64, mips, ppc, sparc, systemz, xcore, m68k,");
	puts("  tms320c64x, m680x, evm, mos65xx, wasm, bpf, riscv, sh,");
	puts("  tricore, alpha, hppa, loongarch, xtensa, arc");
}

cs_arch parse_arch(const char *name)
{
	if (!strcasecmp(name, "x86"))
		return CS_ARCH_X86;
	if (!strcasecmp(name, "arm"))
		return CS_ARCH_ARM;
	if (!strcasecmp(name, "aarch64") || !strcasecmp(name, "arm64"))
		return CS_ARCH_AARCH64;
	if (!strcasecmp(name, "mips"))
		return CS_ARCH_MIPS;
	if (!strcasecmp(name, "ppc"))
		return CS_ARCH_PPC;
	if (!strcasecmp(name, "sparc"))
		return CS_ARCH_SPARC;
	if (!strcasecmp(name, "systemz") || !strcasecmp(name, "sysz"))
		return CS_ARCH_SYSTEMZ;
	if (!strcasecmp(name, "xcore"))
		return CS_ARCH_XCORE;
	if (!strcasecmp(name, "m68k"))
		return CS_ARCH_M68K;
	if (!strcasecmp(name, "tms320c64x"))
		return CS_ARCH_TMS320C64X;
	if (!strcasecmp(name, "m680x"))
		return CS_ARCH_M680X;
	if (!strcasecmp(name, "evm"))
		return CS_ARCH_EVM;
	if (!strcasecmp(name, "mos65xx"))
		return CS_ARCH_MOS65XX;
	if (!strcasecmp(name, "wasm"))
		return CS_ARCH_WASM;
	if (!strcasecmp(name, "bpf"))
		return CS_ARCH_BPF;
	if (!strcasecmp(name, "riscv"))
		return CS_ARCH_RISCV;
	if (!strcasecmp(name, "sh"))
		return CS_ARCH_SH;
	if (!strcasecmp(name, "tricore"))
		return CS_ARCH_TRICORE;
	if (!strcasecmp(name, "alpha"))
		return CS_ARCH_ALPHA;
	if (!strcasecmp(name, "hppa"))
		return CS_ARCH_HPPA;
	if (!strcasecmp(name, "loongarch"))
		return CS_ARCH_LOONGARCH;
	if (!strcasecmp(name, "xtensa"))
		return CS_ARCH_XTENSA;
	if (!strcasecmp(name, "arc"))
		return CS_ARCH_ARC;
	return (cs_arch)-1;
}

cs_mode parse_mode(const char *name)
{
	if (!strcasecmp(name, "16"))
		return CS_MODE_16;
	if (!strcasecmp(name, "32"))
		return CS_MODE_32;
	if (!strcasecmp(name, "64"))
		return CS_MODE_64;
	if (!strcasecmp(name, "thumb"))
		return CS_MODE_THUMB;
	if (!strcasecmp(name, "mclass"))
		return CS_MODE_MCLASS;
	if (!strcasecmp(name, "v8"))
		return CS_MODE_V8;
	if (!strcasecmp(name, "v9"))
		return CS_MODE_V9;
	if (!strcasecmp(name, "big"))
		return CS_MODE_BIG_ENDIAN;
	if (!strcasecmp(name, "little"))
		return CS_MODE_LITTLE_ENDIAN;
	return (cs_mode)-1;
}

binary_format_t detect_format(const uint8_t *buf, size_t len)
{
	if (len >= 2 && buf[0] == 'M' && buf[1] == 'Z')
		return BIN_MZ;
	if (len >= 4 && buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' &&
	    buf[3] == 'F')
		return BIN_ELF;
	return BIN_RAW;
}

void print_instruction_details(const cs_insn *insn)
{
	if (!insn->detail)
		return;

	printf("    Groups: ");
	for (int i = 0; i < insn->detail->groups_count; i++) {
		printf("%d ", insn->detail->groups[i]);
	}
	printf("\n");

	if (insn->detail->regs_read_count > 0) {
		printf("    Implicit registers read: ");
		for (int i = 0; i < insn->detail->regs_read_count; i++) {
			printf("%d ", insn->detail->regs_read[i]);
		}
		printf("\n");
	}

	if (insn->detail->regs_write_count > 0) {
		printf("    Implicit registers written: ");
		for (int i = 0; i < insn->detail->regs_write_count; i++) {
			printf("%d ", insn->detail->regs_write[i]);
		}
		printf("\n");
	}

	if (insn->is_alias) {
		printf("    Alias ID: %lu\n", (unsigned long)insn->alias_id);
	}

	if (insn->illegal) {
		printf("    WARNING: Illegal instruction\n");
	}
}

void disassemble(csdump_opts_t *opts, uint8_t *code, size_t size)
{
	cs_insn *insn;
	size_t count =
		cs_disasm(opts->handle, code, size, opts->base_addr, 0, &insn);
	if (count == 0) {
		fprintf(stderr,
			"ERROR: Failed to disassemble code! (error: %s)\n",
			cs_strerror(cs_errno(opts->handle)));
		return;
	}

	for (size_t i = 0; i < count; i++) {
		if (opts->color) {
#ifdef _WIN32
			/* Windows console color support */
			HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
			SetConsoleTextAttribute(hConsole,
						FOREGROUND_GREEN |
							FOREGROUND_INTENSITY);
			printf("0x%llx:", (unsigned long long)insn[i].address);
			SetConsoleTextAttribute(
				hConsole, FOREGROUND_RED | FOREGROUND_GREEN |
						  FOREGROUND_BLUE);
			printf("  ");
#else
			printf("\033[1;32m0x%llx:\033[0m  ",
			       (unsigned long long)insn[i].address);
#endif
		} else {
			printf("0x%llx:\t",
			       (unsigned long long)insn[i].address);
		}

		/* Print raw bytes */
		for (int j = 0; j < insn[i].size; j++) {
			printf("%02x ", insn[i].bytes[j]);
		}
		for (int j = insn[i].size; j < 8; j++) {
			printf("   ");
		}
		printf("\t%-8s %s\n", insn[i].mnemonic, insn[i].op_str);

		if (opts->detail) {
			print_instruction_details(&insn[i]);
		}
	}

	cs_free(insn, count);
}

/* Cross-platform file mapping */
int map_file(const char *filename, file_mapping_t *mapping)
{
	memset(mapping, 0, sizeof(file_mapping_t));

#ifdef _WIN32
	mapping->file_handle = CreateFileA(filename, GENERIC_READ,
					   FILE_SHARE_READ, NULL, OPEN_EXISTING,
					   FILE_ATTRIBUTE_NORMAL, NULL);
	if (mapping->file_handle == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "Error opening file: %s\n", filename);
		return -1;
	}

	LARGE_INTEGER file_size;
	if (!GetFileSizeEx(mapping->file_handle, &file_size)) {
		fprintf(stderr, "Error getting file size\n");
		CloseHandle(mapping->file_handle);
		return -1;
	}

	if (file_size.QuadPart > MAX_FILE_SIZE) {
		fprintf(stderr, "File too large (max %d bytes)\n",
			MAX_FILE_SIZE);
		CloseHandle(mapping->file_handle);
		return -1;
	}

	mapping->size = (size_t)file_size.QuadPart;

	mapping->mapping_handle = CreateFileMapping(mapping->file_handle, NULL,
						    PAGE_READONLY, 0, 0, NULL);
	if (!mapping->mapping_handle) {
		fprintf(stderr, "Error creating file mapping\n");
		CloseHandle(mapping->file_handle);
		return -1;
	}

	mapping->data = (uint8_t *)MapViewOfFile(mapping->mapping_handle,
						 FILE_MAP_READ, 0, 0, 0);
	if (!mapping->data) {
		fprintf(stderr, "Error mapping file view\n");
		CloseHandle(mapping->mapping_handle);
		CloseHandle(mapping->file_handle);
		return -1;
	}
#else
	mapping->fd = open(filename, O_RDONLY);
	if (mapping->fd < 0) {
		perror("open");
		return -1;
	}

	struct stat st;
	if (fstat(mapping->fd, &st) < 0) {
		perror("fstat");
		close(mapping->fd);
		return -1;
	}

	if (st.st_size > MAX_FILE_SIZE) {
		fprintf(stderr, "File too large (max %d bytes)\n",
			MAX_FILE_SIZE);
		close(mapping->fd);
		return -1;
	}

	mapping->size = st.st_size;

	mapping->data = mmap(NULL, mapping->size, PROT_READ, MAP_PRIVATE,
			     mapping->fd, 0);
	if (mapping->data == MAP_FAILED) {
		perror("mmap");
		close(mapping->fd);
		return -1;
	}
#endif

	return 0;
}

void unmap_file(file_mapping_t *mapping)
{
#ifdef _WIN32
	if (mapping->data)
		UnmapViewOfFile(mapping->data);
	if (mapping->mapping_handle)
		CloseHandle(mapping->mapping_handle);
	if (mapping->file_handle)
		CloseHandle(mapping->file_handle);
#else
	if (mapping->data && mapping->data != MAP_FAILED) {
		munmap(mapping->data, mapping->size);
	}
	if (mapping->fd >= 0)
		close(mapping->fd);
#endif
}

int main(int argc, char **argv)
{
	csdump_opts_t opts = {
		.arch = CS_ARCH_X86,
		.mode = CS_MODE_64,
		.filename = NULL,
		.base_addr = 0,
		.start_offset = 0,
		.limit = 0,
		.color = 0,
		.detail = 0,
		.format = BIN_RAW,
	};

	static struct option longopts[] = {
		{ "arch", required_argument, 0, 'a' },
		{ "mode", required_argument, 0, 'm' },
		{ "input", required_argument, 0, 'i' },
		{ "base", required_argument, 0, 'b' },
		{ "start", required_argument, 0, 's' },
		{ "limit", required_argument, 0, 'l' },
		{ "detail", no_argument, 0, 'd' },
		{ "color", no_argument, 0, 'c' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "a:m:i:b:s:l:dch", longopts,
				  NULL)) != -1) {
		switch (opt) {
		case 'a':
			opts.arch = parse_arch(optarg);
			if (opts.arch == (cs_arch)-1) {
				fprintf(stderr, "Invalid architecture: %s\n",
					optarg);
				return 1;
			}
			break;
		case 'm':
			opts.mode = parse_mode(optarg);
			if (opts.mode == (cs_mode)-1) {
				fprintf(stderr, "Invalid mode: %s\n", optarg);
				return 1;
			}
			break;
		case 'i':
			opts.filename = optarg;
			break;
		case 'b':
			opts.base_addr = strtoull(optarg, NULL, 0);
			break;
		case 's':
			opts.start_offset = strtoull(optarg, NULL, 0);
			break;
		case 'l':
			opts.limit = strtoull(optarg, NULL, 0);
			break;
		case 'd':
			opts.detail = 1;
			break;
		case 'c':
			opts.color = 1;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		case 0:
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (!opts.filename) {
		fprintf(stderr, "Input file is required\n");
		usage(argv[0]);
		return 1;
	}

	/* Check if architecture is supported */
	if (!cs_support(opts.arch)) {
		fprintf(stderr,
			"Architecture %d is not supported in this build\n",
			opts.arch);
		return 1;
	}

#ifdef _WIN32
	/* Enable console color support on Windows 10+ */
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD dwMode = 0;
	GetConsoleMode(hOut, &dwMode);
	dwMode |= 0x0004; /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */
	SetConsoleMode(hOut, dwMode);
#endif

	file_mapping_t mapping;
	if (map_file(opts.filename, &mapping) < 0) {
		return 1;
	}

	opts.format = detect_format(mapping.data, mapping.size);

	if (opts.start_offset >= mapping.size) {
		fprintf(stderr, "Start offset out of range\n");
		unmap_file(&mapping);
		return 1;
	}

	size_t size = opts.limit ? opts.limit :
				   (mapping.size - opts.start_offset);
	if (opts.start_offset + size > mapping.size)
		size = mapping.size - opts.start_offset;

	cs_err err = cs_open(opts.arch, opts.mode, &opts.handle);
	if (err != CS_ERR_OK) {
		fprintf(stderr, "Failed to initialize Capstone: %s\n",
			cs_strerror(err));
		unmap_file(&mapping);
		return 1;
	}

	/* Enable detail mode if requested */
	if (opts.detail) {
		cs_option(opts.handle, CS_OPT_DETAIL, CS_OPT_ON);
	}

	/* Print version and architecture info */
	int major, minor;
	cs_version(&major, &minor);
	printf("Capstone Engine v%d.%d\n", major, minor);
	printf("Architecture: %d, Mode: %d\n", opts.arch, opts.mode);
	printf("File: %s (format: %s, size: %zu bytes)\n", opts.filename,
	       opts.format == BIN_ELF ? "ELF" :
	       opts.format == BIN_MZ  ? "PE/MZ" :
					"RAW",
	       mapping.size);
	printf("Base address: 0x%llx\n", (unsigned long long)opts.base_addr);
	printf("=====================================\n");

	disassemble(&opts, mapping.data + opts.start_offset, size);

	cs_close(&opts.handle);
	unmap_file(&mapping);
	return 0;
}

#ifdef _WIN32
char *optarg = NULL;
int optind = 1, opterr = 1, optopt = 0;

int getopt_long(int argc, char *const argv[], const char *optstring,
		const struct option *longopts, int *longindex)
{
	static int optpos = 1;
	char *arg;

	if (optind >= argc || argv[optind][0] != '-' ||
	    argv[optind][1] == '\0') {
		return -1;
	}

	if (argv[optind][1] == '-') {
		/* Long option */
		if (argv[optind][2] == '\0') {
			optind++;
			return -1;
		}

		arg = argv[optind] + 2;
		char *eq = strchr(arg, '=');
		size_t len = eq ? (size_t)(eq - arg) : strlen(arg);

		for (int i = 0; longopts[i].name; i++) {
			if (strncmp(longopts[i].name, arg, len) == 0 &&
			    strlen(longopts[i].name) == len) {
				optind++;
				if (longopts[i].has_arg == required_argument) {
					if (eq) {
						optarg = eq + 1;
					} else if (optind < argc) {
						optarg = argv[optind++];
					} else {
						return '?';
					}
				} else if (longopts[i].has_arg == no_argument &&
					   eq) {
					return '?';
				}
				if (longopts[i].flag) {
					*longopts[i].flag = longopts[i].val;
					return 0;
				}
				return longopts[i].val;
			}
		}
		return '?';
	}

	/* Short option */
	char opt = argv[optind][optpos];
	char *p = strchr(optstring, opt);

	if (!p) {
		optopt = opt;
		if (++optpos >= (int)strlen(argv[optind])) {
			optind++;
			optpos = 1;
		}
		return '?';
	}

	if (p[1] == ':') {
		if (argv[optind][optpos + 1] != '\0') {
			optarg = argv[optind] + optpos + 1;
		} else if (++optind < argc) {
			optarg = argv[optind];
		} else {
			optopt = opt;
			return '?';
		}
		optind++;
		optpos = 1;
	} else {
		if (++optpos >= (int)strlen(argv[optind])) {
			optind++;
			optpos = 1;
		}
	}

	return opt;
}
#endif