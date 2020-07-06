
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <mprotect.h>
#include "pk.h"

#define PATTERN1 0xAFFEAFFE
#define PATTERN2 0xDEADBEEF
#define PATTERN3 0xC0FFFFEE

void* pthread1(void* arg) {
#if __riscv
    //TODO: warning: optimization may eliminate reads and/or writes to register variables [-Wvolatile-register-var]
    volatile uint64_t something = 0;
    volatile register uint64_t ra asm("ra");
    something = ra;
#endif
    DEBUG_MPK("I am thread 1: %p\n", arg);
#if __riscv
    DEBUG_MPK("pthread1 ra       = 0x%zx", something);
    DEBUG_MPK("pthread1 umpk     = 0x%zx", CSRR(CSR_MPK));
    DEBUG_MPK("pthread1 utvec    = 0x%zx", CSRR(CSR_UTVEC));
    DEBUG_MPK("pthread1 uscratch = 0x%zx", CSRR(CSR_USCRATCH));
#endif
    uintptr_t var = (uintptr_t)arg;
    for (size_t i = 0; i < 1000; i++) {
      var++;
      sched_yield();
    }
    DEBUG_MPK("thread1 returning %lx", var);
    //pthread_exit((void*)var);
    return (void*)var; // same as pthread_exit
}

void* pthread2(void* arg) {
    DEBUG_MPK("I am thread 2: %p\n", arg);
#if __riscv
    DEBUG_MPK("pthread2 umpk     = 0x%zx", CSRR(CSR_MPK));
    DEBUG_MPK("pthread2 utvec    = 0x%zx", CSRR(CSR_UTVEC));
    DEBUG_MPK("pthread2 uscratch = 0x%zx", CSRR(CSR_USCRATCH));
#endif
    uintptr_t var = (uintptr_t)arg;
    for (size_t i = 0; i < 1000; i++) {
      var+=7;
      sched_yield();
    }
    DEBUG_MPK("thread2 returning %lx", var);
    //pthread_exit((void*)var);
    return (void*)var;
}

void* pthread3(void* arg) {
    DEBUG_MPK("I am thread 3: %p\n", arg);
#if __riscv
    DEBUG_MPK("pthread3 umpk     = 0x%zx", CSRR(CSR_MPK));
    DEBUG_MPK("pthread3 utvec    = 0x%zx", CSRR(CSR_UTVEC));
    DEBUG_MPK("pthread3 uscratch = 0x%zx", CSRR(CSR_USCRATCH));
#endif
    uintptr_t var = (uintptr_t)arg;
    for (size_t i = 0; i < 1000; i++) {
      var+=5;
      sched_yield();
    }
    DEBUG_MPK("thread3 returning %lx", var);
    //pthread_exit((void*)var);
    return (void*)var;
}

void test4_pthread() {
  int ret;
  DEBUG_MPK("TEST4");
  pthread_t thread1, thread2, thread3;
  ret = pk_pthread_create(&thread1, NULL, pthread1, (void*)PATTERN1);
  assert(ret == 0);
  ret = pk_pthread_create(&thread2, NULL, pthread2, (void*)PATTERN2);
  assert(ret == 0);
  ret = pk_pthread_create(&thread3, NULL, pthread3, (void*)PATTERN3);
  assert(ret == 0);
  DEBUG_MPK("Main waiting for other thread");

#if __riscv
    DEBUG_MPK("main umpk     = 0x%zx", CSRR(CSR_MPK));
    DEBUG_MPK("main utvec    = 0x%zx", CSRR(CSR_UTVEC));
    DEBUG_MPK("main uscratch = 0x%zx", CSRR(CSR_USCRATCH));
#endif

  uintptr_t retval;
  ret = pthread_join(thread3, (void*)&retval);
  assert(ret == 0);
  DEBUG_MPK("retval = %lx", retval);
  assert(retval == PATTERN3+1000*5);

  ret = pthread_join(thread2, (void*)&retval);
  assert(ret == 0);
  DEBUG_MPK("retval = %lx", retval);
  assert(retval == PATTERN2+1000*7);

  ret = pthread_join(thread1, (void*)&retval);
  assert(ret == 0);
  DEBUG_MPK("retval = %lx", retval);
  assert(retval == PATTERN1+1000);

  DEBUG_MPK("Main done waiting");
}
