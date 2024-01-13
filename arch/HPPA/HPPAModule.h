/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev  <sibirtsevdl@gmail.com>, 2023 */

#ifndef CS_HPPA_MODULE_H
#define CS_HPPA_MODULE_H

#include "../../utils.h"

cs_err HPPA_global_init(cs_struct *ud);
cs_err HPPA_option(cs_struct *handle, cs_opt_type type, size_t value);

#endif
