#pragma once

#include "test_ecalls.h"

#ifndef __ASSEMBLY__

#include <stdint.h>

extern void ecall_register_test_args(int did);
extern void ecall_register_test_api_calls(int did);
extern void ecall_register_test_kill_all_regs(int did);
extern int  ecall_register_test2_nested(int arg);

extern uint64_t ecall_test_args(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f);
extern void     ecall_test_api_calls(void);
extern int      ecall_test_kill_all_regs(void);
extern int      ecall_test2_nested(int);

extern void ecall_save_frame_prepare();
extern void ecall_save_frame_overhead();
#endif // __ASSEMBLY__
