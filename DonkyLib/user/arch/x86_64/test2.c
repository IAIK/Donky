#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "test2_ecall.h"
#include "test3_ecall.h"
#include "pk_debug.h"


uint64_t test_args(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f) {
  //printf("%lx %lx %lx %lx %lx %lx\n", a, b, c, d, e, f);
  assert_ifdebug(a == 0x10);
  assert_ifdebug(b == 0x11);
  assert_ifdebug(c == 0x12);
  assert_ifdebug(d == 0x13);
  assert_ifdebug(e == 0x14);
  assert_ifdebug(f == 0x15);
  return 0xAABBCCDD00112233ULL;
}

int test2_nested(int arg){
    DEBUG_MPK("test2_nested(%d)\n", arg);
    //pk_print_current_reg();
    arg--;
    if(arg > 0){
        DEBUG_MPK("test2_nested: Calling test3_nested(%d)\n", arg);
        int ret = ecall_test3_nested(arg);
        DEBUG_MPK("test2_nested: Successfully called ecall_test3_nested(%d). return value was %d\n", arg, ret);
        assert_ifdebug(ret == arg - 1);
    }else{
      #ifndef RELEASE
        pk_print_debug_info();
      #endif
    }
    return arg;
}

void test_api_calls() {
  pk_print_debug_info();
  pk_print_current_reg();
}

int __attribute__((naked)) test_kill_all_regs() {
  asm volatile (
    // Write callee-saved registers
    "mov $0xFF, %rbx\n"
    "mov $0xEE, %r12\n"
    "mov $0xDD, %r13\n"
    "mov $0xCC, %r14\n"
    "mov $0xBB, %r15\n"
    // Return
    "mov $0xAA, %rax\n"
    "mov $0x99, %rdx\n"
    "ret\n"
    );
}
