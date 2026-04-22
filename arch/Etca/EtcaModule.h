/* Capstone Disassembly Engine */
/* By Alexander Nutz, 2025 */

#ifndef CS_ETCA_MODULE_H
#define CS_ETCA_MODULE_H

#include "../../utils.h"

cs_err Etca_global_init(cs_struct *ud);
cs_err Etca_option(cs_struct *handle, cs_opt_type type, size_t value);

#endif
