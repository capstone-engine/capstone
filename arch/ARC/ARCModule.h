/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2024 */

#ifndef CS_ARC_MODULE_H
#define CS_ARC_MODULE_H

#include "../../utils.h"

cs_err ARC_global_init(cs_struct *ud);
cs_err ARC_option(cs_struct *handle, cs_opt_type type, size_t value);

#endif