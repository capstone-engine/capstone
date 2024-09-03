/* Capstone Disassembly Engine */
/* By Jiajie Chen <c@jia.je>, 2024 */
/*    Yanglin Xun <1109673069@qq.com>, 2024 */

#ifndef CS_LOONGARCH_MODULE_H
#define CS_LOONGARCH_MODULE_H

#include "../../utils.h"

cs_err LoongArch_global_init(cs_struct *ud);
cs_err LoongArch_option(cs_struct *handle, cs_opt_type type, size_t value);

#endif // CS_LOONGARCH_MODULE_H
