// SPDX-FileCopyrightText: 2026 moste00 <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3.0-Clause

#define CAPSTONE_RISCV_COMPAT_HEADER
#include <capstone/capstone.h>

int riscv(void)
{
	return CS_MODE_RISCVC == CS_MODE_RISCV_C ? 0 : -1;
}

#undef CAPSTONE_RISCV_COMPAT_HEADER
