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
#include "test5.h"

// Since assert might need to access stack, we need to give it full
// pkru permission if test failed. This avoids recursive SEGFAULT
//#define ASSERT(test) assert(test)
#if __riscv
#define ASSERT(test) do { if (!(test)) { ERROR_FAIL2("Assertion `" #test "' failed."); } } while (0)
#else
#define ASSERT(test) \
    if (!(test)) { \
        asm volatile( \
          "xor %eax, %eax\n" \
          "xor %ecx, %ecx\n" \
          "xor %edx, %edx\n" \
          "wrpkru\n" \
      ); \
      assert(test); \
    }
#endif

void test_missing_key_exception(){
    printf("testing missing-key-exception\n");
    int test_size = 4096;
    int test_key = pk_pkey_alloc(0, 0);
    printf("test_key = %d\n", test_key);
    ASSERT(test_key > 0);
    void * test_memory = mmap(NULL, test_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
    printf("test_memory = %p\n", test_memory);
    ASSERT(test_memory != MAP_FAILED);
    //printf("accessing %p", test_memory);
    //volatile int x1 = *(int*)test_memory;
    int ret = pk_pkey_mprotect(test_memory, test_size, PROT_READ | PROT_WRITE, test_key);
    ASSERT(ret == 0);
    ret = pk_domain_load_key(test_key, PK_SLOT_ANY, 0);
    ASSERT(ret == 0);
    printf("accessing %p\n", test_memory);
    volatile int x = *(int*)test_memory;
    (void)x;
    printf("testing missing-key-exception done\n");
}

jmp_buf exception_buffer;
bool access_test_running = false;

int current_test = 0;
size_t exc_count = 0;
uintptr_t* childmem = NULL;
uint32_t pkru = 0;

#define ACCESS_MUST_FAIL(access) do {             \
  ASSERT(!access_test_running);                   \
  access_test_running = true;                     \
  SAVE_PKRU();                                    \
  /* Store reentry point for exception handler */ \
  int exc = setjmp(exception_buffer);             \
  if (0 == exc) {                                 \
    /* Do critical access */                      \
    do { access; } while(0);                      \
    /* The access did not fail */                 \
    ASSERT(!"ACCESS_MUST_FAIL("#access")");       \
  } else {                                        \
    /* We came from the exception handler */      \
    ASSERT(1 == exc);                             \
    exc_count++;                                  \
  }                                               \
  ASSERT(access_test_running);                    \
  access_test_running = false;                    \
} while(0)

#define ACCESS_MUST_NOT_FAIL(access) do {         \
  ASSERT(!access_test_running);                   \
  access_test_running = true;                     \
  SAVE_PKRU();                                    \
  /* Store reentry point for exception handler */ \
  int exc = setjmp(exception_buffer);             \
  if (0 == exc) {                                 \
    /* Do critical access */                      \
    do { access; } while(0);                      \
    /* The access did not fail */                 \
  } else {                                        \
    /* We came from the exception handler */      \
    ASSERT(!"ACCESS_MUST_NOT_FAIL("#access")");   \
  }                                               \
  ASSERT(access_test_running);                    \
  access_test_running = false;                    \
} while(0)

#if __x86_64

// x86: Linux modifies pkru to kernel's copy before calling segfault handler
// We want to restore our own version of pkru
#define SAVE_PKRU()    do { pkru = _read_pkru_reg(); } while(0)
#define RESTORE_PKRU() do { _write_pkru_reg(pkru); } while(0)

#else

// riscv does not allow writing pkru from user space, but it should 
// also not be needed.
#define SAVE_PKRU()
#define RESTORE_PKRU()

#endif

uintptr_t* pkey_isolation_child_alloc() {
  uintptr_t* child = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  return child;
}

volatile uintptr_t* child_stack;
uintptr_t* pkey_isolation_child_stack() {
  volatile uintptr_t stack[PAGESIZE/sizeof(uintptr_t)];
  for (size_t i = 0; i < PAGESIZE/sizeof(uintptr_t); i++) {
    ACCESS_MUST_NOT_FAIL(stack[i] = i);
  }
  WARNING("pkey_isolation_child_stack returning %p", stack);
  child_stack = stack;
  return 0;
}

__thread uintptr_t mytls[PAGESIZE] = {0,};

void pkey_isolation_child_success(volatile uintptr_t* mem, int shared_pkey) {
  int ret;
  ret = pk_domain_load_key(shared_pkey, PK_SLOT_ANY, 0);
  ASSERT(0 == ret);
  ASSERT(mem);

  DEBUG_MPK("Hi, I am child, accessing mem %p", mem);
  for (size_t i = 0; i < 256/sizeof(uintptr_t); i++) {
    ACCESS_MUST_NOT_FAIL(mem[i] = i);
  }
}

void pkey_isolation_child_fail(volatile uintptr_t* mem, int shared_pkey) {
  int ret;
  ret = pk_domain_load_key(shared_pkey, PK_SLOT_ANY, 0);
  ASSERT(0 == ret);
  ASSERT(mem);

  DEBUG_MPK("Hi, I am child-fail, accessing mem %p", mem);
  for (size_t i = 0; i < 256/sizeof(uintptr_t); i++) {
    ACCESS_MUST_FAIL(mem[i] = i);
  }
}

void test5_exception_handler(void *bad_addr) {
  DEBUG_MPK("test5_exception_handler(%p)", bad_addr);

  if (access_test_running) {
    DEBUG_MPK("access_test_running: resuming with longjmp");
    longjmp(exception_buffer, 1);
    // should not reach here
    ASSERT(false);
  } else {
    ERROR("test5_exception_handler: no test is running!");
    print_maps();
    ASSERT(false);
  }
}

void test5_segfault_handler(int sig, siginfo_t *si, void *unused) {
  psiginfo(si, "test5_segfault_handler");
  ASSERT(SIGSEGV == sig);

  //DEBUG_MPK("test5_segfault_handler at %p. Reason: %d", si->si_addr, si->si_code);

  RESTORE_PKRU();
  
  // Don't forget to unblock the signal
  sigset_t sigset;
  int ret;
  ret = sigemptyset(&sigset); ASSERT(0 == ret);
  ret = sigaddset(&sigset, SIGSEGV); ASSERT(0 == ret);
  ret = sigprocmask(SIG_UNBLOCK, &sigset, NULL); ASSERT(0 == ret);
  
  test5_exception_handler(si->si_addr);
  ASSERT(false);
}

#if __x86_64

static void __attribute__((naked)) segfault_handler_asm() {
  // Linux segfault handler restores pkru to kernel's copy
  // Temporarily enable full PKRU permission to give
  // test5_segfault_handler stack access
  asm volatile(
      "xor %eax, %eax\n" // clear eax (full permission)
      "xor %ecx, %ecx\n" // clear ecx (needed for wrpkru)
      "xor %edx, %edx\n" // clear edx (needed for wrpkru)
      "wrpkru\n"
      "jmp test5_segfault_handler\n"
  );
}

#else

// riscv does not need asm handler
#define segfault_handler_asm test5_segfault_handler

#endif

extern __thread uintptr_t pk_trusted_tls;

void test_pkey_isolation() {
  int ret;

  DEBUG_MPK("Preparing for isolation tests");

  // register segfault handler (needed for x86)
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = segfault_handler_asm;
  ret = sigaction(SIGSEGV, &sa, NULL);
  ASSERT(0 == ret);

  ret = pk_register_exception_handler(test5_exception_handler);
  ASSERT(0 == ret);

  int did = pk_domain_create(0);
  ASSERT(did > 0);
  DEBUG_MPK("Child domain: %d", did);

  volatile uintptr_t* hostmem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  ASSERT(hostmem != MAP_FAILED);
  DEBUG_MPK("host memory: %p", hostmem);

  int shared_pkey = pkey_alloc(0, 0);
  ASSERT(shared_pkey > 0);
  DEBUG_MPK("Shared pkey: %d", shared_pkey);

  volatile uintptr_t* sharedmem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  ASSERT(sharedmem != MAP_FAILED);
  DEBUG_MPK("shared memory: %p", sharedmem);

  int ro_pkey = pkey_alloc(0, PKEY_DISABLE_WRITE);
  ASSERT(ro_pkey > 0);
  DEBUG_MPK("Read-only pkey: %d", ro_pkey);

  volatile uintptr_t currentval; // volatile prevents compiler from optimizing away the memory access

  // Read-only access test
  ret = pkey_mprotect((void*)sharedmem, 4096, PROT_READ | PROT_WRITE, ro_pkey);
  ASSERT(0 == ret);
  ret = pk_domain_load_key(ro_pkey, PK_SLOT_ANY, 0);
  ASSERT(0 == ret);
  ACCESS_MUST_NOT_FAIL(currentval = sharedmem[0]); // read access
  ACCESS_MUST_FAIL(sharedmem[0] = currentval);     // write access

  // Read-write access test
  ret = pkey_mprotect((void*)sharedmem, 4096, PROT_READ | PROT_WRITE, shared_pkey);
  ret = pk_domain_load_key(shared_pkey, PK_SLOT_ANY, 0);
  ASSERT(0 == ret);
  ACCESS_MUST_NOT_FAIL(currentval = sharedmem[1]); // read access
  ACCESS_MUST_NOT_FAIL(sharedmem[1] = currentval); // write access

  // Access test across domains
  ret = pk_domain_assign_pkey(did, shared_pkey, PK_KEY_COPY, 0);
  ASSERT(0 == ret);

  ret = pk_domain_load_key(shared_pkey, PK_SLOT_ANY, 0);
  ASSERT(0 == ret);

  ret = ecall_register_pkey_isolation_child_alloc(did);
  ASSERT(ret >= 0);
  ret = ecall_register_pkey_isolation_child_stack(did);
  ASSERT(ret >= 0);
  ret = ecall_register_pkey_isolation_child_success(did);
  ASSERT(ret >= 0);
  ret = ecall_register_pkey_isolation_child_fail(did);
  ASSERT(ret >= 0);
  childmem = ecall_pkey_isolation_child_alloc();
  ASSERT(MAP_FAILED != childmem);
  DEBUG_MPK("child memory: %p", childmem);

  // Let child access its own child memory
  ecall_pkey_isolation_child_success(childmem, shared_pkey);

  // Let child access shared memory
  ecall_pkey_isolation_child_success(sharedmem, shared_pkey);

  // Let child access host memory. Must fail
  ecall_pkey_isolation_child_fail(hostmem, shared_pkey);

  // Let child access host stack. Must fail
  uintptr_t stack_var[PAGESIZE/sizeof(uintptr_t)]; // some stack variable, should be protected
  ecall_pkey_isolation_child_fail(stack_var, shared_pkey);

  // Let child access child stack
  ecall_pkey_isolation_child_stack(); //writes to child_stack

  // Let host access child stack. Must fail
  for (size_t i = 0; i < PAGESIZE/sizeof(uintptr_t); i++) {
    uintptr_t val;
    /* We're accessing child-private memory */
    ACCESS_MUST_FAIL(val = child_stack[i]);
  }

  // Let child access TLS. Must succeed
  ecall_pkey_isolation_child_success(mytls, shared_pkey);
  DEBUG_MPK("mytls %p", mytls);
  DEBUG_MPK("errno %p", &errno);

  uintptr_t* ttls = &pk_trusted_tls;
  #ifdef TLS_MISALIGNMENT_BUG
    ttls = (uintptr_t*)((char*)ttls + PAGESIZE);
  #endif
  DEBUG_MPK("ttls: %p", ttls);

  //pk_print_debug_info();
  //print_maps();

  // Let host access trusted TLS. Must fail
  for (size_t i = 0; i < PAGESIZE/sizeof(uintptr_t); i++) {
    volatile uintptr_t val;
    /* We're accessing pk-private memory */
    ACCESS_MUST_FAIL(val = ttls[i]);
  }

  // Let host access trusted TLS. Must fail
  ecall_pkey_isolation_child_fail(ttls, shared_pkey);

  //test memory accesses with current pkey (non-child)
  for (size_t i = 0; i < 256/sizeof(uintptr_t); i++) {
    uintptr_t val;
    /* We're accessing our own memory */
    ACCESS_MUST_NOT_FAIL(hostmem[i] = i);
    /* We're accessing shared memory */
    ACCESS_MUST_NOT_FAIL(val = sharedmem[i]);
    ASSERT(val == i);
    /* We're trying to illegally access child memory */
    ACCESS_MUST_FAIL(childmem[i] = i);
  }

  ret = munmap((void*)sharedmem, 4096);
  ASSERT(0 == ret);

  ret = pkey_free(ro_pkey);
  // TODO: cleanup shared_pkey and subdomain

  // Deregister signal handler
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_DFL;
  ret = sigaction(SIGSEGV, &sa, NULL);
  ASSERT(0 == ret);
}
