#pragma once

#include "test_ecalls.h"

#ifndef __ASSEMBLY__

#include <stdint.h>
#include <pk.h>

extern void ecall_test3(void);
extern int  ecall_register_test3(int did);

extern int  ecall_test3_nested(int arg);
extern int  ecall_register_test3_nested(int did);

extern uint64_t ecall_test3_time();
extern int      ecall_register_test3_time(int did);

#endif // __ASSEMBLY__
