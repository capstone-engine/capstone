+/* Capstone Disassembly Engine */
+/* By Shawn Chang <citypw@gmail.com>, HardenedLinux@2018 */
+
+#ifndef CS_EVM_MODULE_H
+#define CS_EVM_MODULE_H
+
+#include "../../utils.h"
+
+cs_err RISCV_global_init(cs_struct *ud);
+cs_err RISCV_option(cs_struct *handle, cs_opt_type type, size_t value);
+
+#endif
