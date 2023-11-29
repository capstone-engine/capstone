/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2023 */

#ifndef CAPSTONE_ALPHAMODULE_H
#define CAPSTONE_ALPHAMODULE_H

#include "../../utils.h"

cs_err ALPHA_global_init(cs_struct *ud);
cs_err ALPHA_option(cs_struct *handle, cs_opt_type type, size_t value);

#endif // CAPSTONE_ALPHAMODULE_H
