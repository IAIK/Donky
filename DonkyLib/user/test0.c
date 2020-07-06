#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <setjmp.h>
#include <mprotect.h>
#include "pk.h"
#include "pk_debug.h"
#include "test0.h"

jmp_buf test0_exception_buffer;
bool test0_access_test_running = false;

int test0_current_test = 0;
size_t test0_exc_count = 0;

uint32_t test0_pkru = 0;

#define ACCESS_MUST_FAIL(access) do {             \
  assert(!test0_access_test_running);                   \
  test0_access_test_running = true;                     \
  SAVE_PKRU();                                    \
  /* Store reentry point for exception handler */ \
  int exc = setjmp(test0_exception_buffer);             \
  if (0 == exc) {                                 \
    /* Do critical access */                      \
    do { access; } while(0);                      \
    /* The access did not fail */                 \
    assert(!"ACCESS_MUST_FAIL("#access")");       \
  } else {                                        \
    /* We came from the exception handler */      \
    assert(1 == exc);                             \
    test0_exc_count++;                                  \
  }                                               \
  assert(test0_access_test_running);                    \
  test0_access_test_running = false;                    \
} while(0)

#define ACCESS_MUST_NOT_FAIL(access) do {         \
  assert(!test0_access_test_running);                   \
  test0_access_test_running = true;                     \
  SAVE_PKRU();                                    \
  /* Store reentry point for exception handler */ \
  int exc = setjmp(test0_exception_buffer);             \
  if (0 == exc) {                                 \
    /* Do critical access */                      \
    do { access; } while(0);                      \
    /* The access did not fail */                 \
  } else {                                        \
    /* We came from the exception handler */      \
    assert(!"ACCESS_MUST_NOT_FAIL("#access")");   \
  }                                               \
  assert(test0_access_test_running);                    \
  test0_access_test_running = false;                    \
} while(0)

#if __x86_64

// x86: Linux modifies pkru to kernel's copy before calling segfault handler
// We want to restore our own version of pkru
#define SAVE_PKRU()    do { test0_pkru = _read_pkru_reg(); } while(0)
#define RESTORE_PKRU() do { _write_pkru_reg(test0_pkru); } while(0)

#else

// riscv does not allow writing pkru from user space, but it should 
// also not be needed.
#define SAVE_PKRU()
#define RESTORE_PKRU()

#endif


void test0_child(volatile uint64_t* mem, int allowed) {
  //~ int ret;
  //~ ret = pk_domain_load_key(shared_pkey, PK_SLOT_ANY, 0);
  //~ assert(0 == ret);
  assert(mem);

  DEBUG_MPK("Hi, I am child-fail, accessing mem %p", mem);
  int i = 0;
  //for (size_t i = 0; i < 4096/sizeof(uint64_t); i+=64) {
    if (allowed) {
      ACCESS_MUST_NOT_FAIL(mem[i] = i);
    } else {
      ACCESS_MUST_FAIL(mem[i] = i);
    }
  //}
}

void test0_exception_handler(void *bad_addr) {
  DEBUG_MPK("test0_exception_handler(%p)", bad_addr);
  //assert(false);
  if (test0_access_test_running) {
    DEBUG_MPK("test0_access_test_running: resuming with longjmp");
    longjmp(test0_exception_buffer, 1);
    // should not reach here
    assert(false);
  } else {
    ERROR("test0_exception_handler: no test is running!");
    print_maps();
    assert(false);
  }
}

void test0_segfault_handler(int sig, siginfo_t *si, void *unused) {
  psiginfo(si, "test0_segfault_handler");
  assert(SIGSEGV == sig);

  //DEBUG_MPK("test0_segfault_handler at %p. Reason: %d", si->si_addr, si->si_code);

  RESTORE_PKRU();
  
  // Don't forget to unblock the signal
  sigset_t sigset;
  int ret;
  ret = sigemptyset(&sigset); assert(0 == ret);
  ret = sigaddset(&sigset, SIGSEGV); assert(0 == ret);
  ret = sigprocmask(SIG_UNBLOCK, &sigset, NULL); assert(0 == ret);
  
  test0_exception_handler(si->si_addr);
  assert(false);
}

#if __x86_64

static void __attribute__((naked)) test0_segfault_handler_asm() {
  // Linux segfault handler restores pkru to kernel's copy
  // Temporarily enable full PKRU permission to give
  // test0_segfault_handler stack access
  asm volatile(
      "xor %eax, %eax\n" // clear eax (full permission)
      "xor %ecx, %ecx\n" // clear ecx (needed for wrpkru)
      "xor %edx, %edx\n" // clear edx (needed for wrpkru)
      "wrpkru\n"
      "jmp test0_segfault_handler\n"
  );
}

#else

// riscv does not need asm handler
#define test0_segfault_handler_asm test0_segfault_handler

#endif

void test0() {
  int ret;

  DEBUG_MPK("Preparing for isolation tests");

  // register segfault handler (needed for x86)
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = test0_segfault_handler_asm;
  ret = sigaction(SIGSEGV, &sa, NULL);
  assert(0 == ret);

  ret = pk_register_exception_handler(test0_exception_handler);
  assert(0 == ret);

  int did = pk_domain_create(0);
  assert(did > 0);
  DEBUG_MPK("Child domain: %d", did);

  ret = ecall_register_test0_child(did);
  assert(ret >= 0);

  volatile uintptr_t* mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  ecall_test0_child(mem, 0);

  int pkey = 0;
  do {
    pkey = pkey_alloc(0, 0);
    if (pkey <= 0) {
      break;
    }
    DEBUG_MPK("Testing pkey: %d", pkey);

    ret = pkey_mprotect((void*)mem, 4096, PROT_READ | PROT_WRITE, pkey);
    assert(0 == ret);
    ecall_test0_child(mem, 0);
    
    ret = pk_domain_assign_pkey(did, pkey, PK_KEY_COPY, 0);
    assert(0 == ret);
    ecall_test0_child(mem, 1);

  } while (1);

  // Deregister signal handler
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_DFL;
  ret = sigaction(SIGSEGV, &sa, NULL);
  assert(0 == ret);
  return;
}
