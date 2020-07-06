#include "pk.h"
#include "pk_debug.h"

#include <mprotect.h>
#include "tests.h"
#include "test_ecalls.h"
#include "test0.h"
#include "test1_api.h"
#include "test2_ecall.h"
#include "test3_ecall.h"
#include "test4_pthread.h"
#include "test5.h"
#include "test6.h"
#include "bench.h"

//------------------------------------------------------------------------------
// Addresses of sections to be isolated
extern uintptr_t _test2_start[];
extern uintptr_t _test2_end[];

extern uintptr_t _test3t_start[];
extern uintptr_t _test3t_end[];
extern uintptr_t _test3d_start[];
extern uintptr_t _test3d_end[];
extern uintptr_t _test3_start[];
extern uintptr_t _test3_end[];
//------------------------------------------------------------------------------

#define SANITYCHECKS() do { pk_debug_usercheck(0); } while (0)
#define LINE() do { SANITYCHECKS(); printf("===========================================\n"); } while (0)

#define SYM_SIZE(sym) (size_t)((uintptr_t)_##sym##_end - (uintptr_t)_##sym##_start)


//------------------------------------------------------------------------------

int test3_domain = 0;
int test2_domain = 0;

//------------------------------------------------------------------------------
  
void setup_domains() {
    LINE();
    printf("Testing simple API call\n");
    int res = pk_simple_api_call(1,2,3,4,5,6);
    assert(res == (1+2+3+4+5+6));

    LINE();
    printf("START of test1 API\n");
    test1_api(); // This test must be before any other test allocating keys
    printf("END of test1 API\n");

    LINE();
    int domain_flags = PK_KEY_INHERIT | PK_KEY_COPY; //This is necessary because bench() calls some test2 function directly without an ecall. otherwise this would lead to a key mismatch fault and we'd die.
    test2_domain = pk_domain_create(domain_flags);
#ifndef SHARED
    bool ret = pk_pkey_mprotect2(test2_domain, _test2_start, SYM_SIZE(test2), PROT_EXEC | PROT_READ | PROT_WRITE, PK_DEFAULT_KEY);
    assert(ret == 0);
#endif
    ecall_register_test2(test2_domain);

    test3_domain = pk_domain_create(domain_flags);
    #ifndef SHARED
    #ifdef PROXYKERNEL
        // Proxy kernel has some mmap issues, so let's just use a single mapping for code+data which allows r+w+x
        ret = pk_pkey_mprotect2(test3_domain, _test3_start, SYM_SIZE(test3), PROT_EXEC | PROT_READ | PROT_WRITE, PK_DEFAULT_KEY);
        assert(ret == 0);
    #else /* PROXYKERNEL */
        ret = pk_pkey_mprotect2(test3_domain, _test3t_start, SYM_SIZE(test3t), PROT_EXEC | PROT_READ, PK_DEFAULT_KEY);
        assert(ret == 0);
        ret = pk_pkey_mprotect2(test3_domain, _test3d_start, SYM_SIZE(test3d), PROT_READ | PROT_WRITE, PK_DEFAULT_KEY);
        assert(ret == 0);
    #endif /* PROXYKERNEL */
    #endif /* SHARED */

    //currently not necessary because root domain is allowed to do any ecall?
    //pk_domain_allow_caller2(test3_domain, pk_current_did(), 0);
    //pk_domain_allow_caller2(test2_domain, pk_current_did(), 0);

    ecall_register_test3(test3_domain);
    ecall_register_test3_time(test3_domain);

    ecall_register_test2_nested(test2_domain);
    ecall_register_test3_nested(test3_domain);

    //test2 and test3 need to be able to call each other
    pk_domain_allow_caller2(test3_domain, test2_domain, 0);
    pk_domain_allow_caller2(test2_domain, test3_domain, 0);

    LINE();

    #ifndef RELEASE
    //Print debug info after setting up domains
    pk_print_debug_info();
    #endif
}

void run_tests() {
    //Run tests
    LINE();
    printf("START of test2\n");
    test2();
    printf("END of test2\n");

    LINE();
    printf("START of test3\n");
    ecall_test3(); //Note: calls ecall-function from test2
    printf("END of test3\n");

#if !defined(PROXYKERNEL)
    LINE();
    printf("START of test4\n");
    test4_pthread(); // does not work on riscv yet
    printf("END of test4\n");
#endif // PROXYKERNEL

#if !defined(FAKE_MPK_REGISTER)
    LINE();
    printf("START of test5\n");
    test_missing_key_exception(); //does not work on x86 yet?
#ifndef FAKE_MPK_REGISTER
    test_pkey_isolation();
#endif
    printf("END of test5\n");
#endif

    printf("START of test6\n");
    test6_signals();
    printf("END of test6\n");

    //testing nested calls
    LINE();
    printf("Testing nested calls\n");
    ecall_test3_nested(10);
    LINE();

    printf("run_tests done\n");
}
//------------------------------------------------------------------------------

void run_preinit_tests() {
  // Before initialization, all calls shall work as usual
  int ret;
  int pkey = pkey_alloc(0, 0);
  assert(pkey >= 0);
  char* mem = mmap(NULL, 2 * PAGESIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
  assert(MAP_FAILED != mem);
  mem[1] = mem[0]+1;
  ret = mprotect(mem, PAGESIZE, PROT_READ | PROT_WRITE);
  assert(0 == ret);
  ret = pkey_mprotect(mem + PAGESIZE, PAGESIZE, PROT_READ | PROT_WRITE, pkey);
  assert(0 == ret);
  ret = munmap(mem, 2 * PAGESIZE);
  assert(0 == ret);
  ret = pkey_free(pkey);
  assert(0 == ret);
}
//------------------------------------------------------------------------------

int main(){

#ifndef CONSTRUCTOR
#ifdef TIMING
    bench_preinit();
#else
    run_preinit_tests();
#endif

    // Initialize PK
    if(pk_init() != 0){
        ERROR_FAIL("main: pk_init failed");
    }
#endif /* CONSTRUCTOR */


    pk_print_current_reg();
    printf("pk_init done\n");

    // TODO: only run test0 standalone, i.e. without other tests
    //       because it allocates all protection keys without freeing them
    //~ LINE();
    //~ printf("START of test0\n");
    //~ test0();
    //~ printf("END of test0\n");
    //~ return 0;

    setup_domains();

#ifdef TIMING
    bench();
    timing_results();
#else
    run_tests();
#endif
    printf("END\n");

#ifndef CONSTRUCTOR
    // Deinitialize PK
    if(pk_deinit() != 0){
        ERROR_FAIL("main: pk_deinit failed");
    }
#endif /* CONSTRUCTOR */

    return 0;
}
