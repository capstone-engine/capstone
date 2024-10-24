#ifndef __RISCV_CONFIG_H__
#define __RISCV_CONFIG_H__

#include <stdint.h>

typedef uint8_t (*Void2Bool)(void);

typedef struct riscv_conf {
  Void2Bool sys_enable_fdext;
  Void2Bool sys_enable_zfinx;
} riscv_conf;

#endif