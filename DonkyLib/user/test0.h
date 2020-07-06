#pragma once

void test0(void);

extern void ecall_test0_child(volatile uintptr_t* mem, int allowed);

extern int ecall_register_test0_child(int did);
