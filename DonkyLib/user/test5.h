#pragma once

void test_missing_key_exception(void);
void test_pkey_isolation(void);

extern uintptr_t* ecall_pkey_isolation_child_alloc();
extern uintptr_t* ecall_pkey_isolation_child_stack();
extern void       ecall_pkey_isolation_child_success(volatile uintptr_t* mem, int shared_pkey);
extern void       ecall_pkey_isolation_child_fail(volatile uintptr_t* mem, int shared_pkey);
  
extern int ecall_register_pkey_isolation_child_alloc(int did);
extern int ecall_register_pkey_isolation_child_stack(int did);
extern int ecall_register_pkey_isolation_child_success(int did);
extern int ecall_register_pkey_isolation_child_fail(int did);
