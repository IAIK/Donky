#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "test2_ecall.h"
#include "test3_ecall.h"
#include "pk_debug.h"


uint64_t test_args(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f) {
  #ifndef RELEASE
      printf("%lx %lx %lx %lx %lx %lx\n", a, b, c, d, e, f);
  #endif
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

void __attribute__((naked)) test_api_calls() {
    asm volatile (
    "addi     sp,sp,-8;"
    "sd       ra,0(sp);"
    "call     pk_print_debug_info;"
    "call     pk_print_current_reg;"
    "ld       ra,0(sp);"
    "addi     sp,sp,8;"
    "ret;"
    );
}

int __attribute__((naked)) test_kill_all_regs(){
    asm volatile (
    //TODO overwrite sp and all others (except ra)
    //TODO destroy entire stack
    "li    t0,  0xFF;"
    "li    t1,  0xFF;"
    "li    t2,  0xFF;"
    "li    s1,  0xFF;"
    "li    a0,  0xF0;"
    "li    a1,  0xF1;"
    "li    a2,  0xF2;"
    "li    a3,  0xFF;"
    "li    a4,  0xFF;"
    "li    a5,  0xFF;"
    "li    a6,  0xFF;"
    "li    a7,  0xFF;"
    "li    s2,  0xFF;"
    "li    s3,  0xFF;"
    "li    s4,  0xFF;"
    "li    s5,  0xFF;"
    "li    s6,  0xFF;"
    "li    s7,  0xFF;"
    "li    s8,  0xFF;"
    "li    s9,  0xFF;"
    "li    s10, 0xFF;"
    "li    s11, 0xFF;"
    "li    t3,  0xFF;"
    "li    t4,  0xFF;"
    "li    t5,  0xFF;"
    "li    t6,  0xFF;"
    "ret;"
    );
}
