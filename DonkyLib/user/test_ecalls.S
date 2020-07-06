#define __ASSEMBLY__
#include "pk.h"
#include "test_ecalls.h"

GEN_ALL_SIMPLE test0_child                   ECALL_TEST0_CHILD
GEN_ALL_SIMPLE test3                         ECALL_TEST3
GEN_ALL_SIMPLE test3_nested                  ECALL_TEST3_NESTED
GEN_ALL_SIMPLE test3_time                    ECALL_TEST3_TIME
GEN_ALL_SIMPLE pkey_isolation_child_alloc    ECALL_PKEY_ISOLATION_CHILD_ALLOC
GEN_ALL_SIMPLE pkey_isolation_child_stack    ECALL_PKEY_ISOLATION_CHILD_STACK
GEN_ALL_SIMPLE pkey_isolation_child_success  ECALL_PKEY_ISOLATION_CHILD_SUCCESS
GEN_ALL_SIMPLE pkey_isolation_child_fail     ECALL_PKEY_ISOLATION_CHILD_FAIL
