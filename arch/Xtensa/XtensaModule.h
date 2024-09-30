/* Capstone Disassembly Engine */
/* By billow <billow.fun@gmail.com>, 2024 */

#ifndef CS_XTENSA_MODULE_H
#define CS_XTENSA_MODULE_H

cs_err Xtensa_global_init(cs_struct *ud);
cs_err Xtensa_option(cs_struct *handle, cs_opt_type type, size_t value);

#endif
