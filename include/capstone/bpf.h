/* Capstone Disassembly Engine */
/* BPF Backend by david942j <david942j@gmail.com>, 2019 */

#ifndef CAPSTONE_BPF_H
#define CAPSTONE_BPF_H

#ifdef __cplusplus
extern "C" {
#endif

#include "platform.h"

#ifdef _MSC_VER
#pragma warning(disable:4201)
#endif

typedef enum bpf_op_type {
	BPF_OP_INVALID = 0,
} bpf_op_type;

typedef struct cs_bpf_op {
	bpf_op_type type;
} cs_bpf_op;

/// Instruction structure
typedef struct cs_bpf {
	uint8_t op_count;
	cs_bpf_op *operands;
} cs_bpf;

#ifdef __cplusplus
}
#endif

#endif
