#ifdef TIMING

#include "pk.h"
#include "pk_debug.h" //for timing
//
#include "tests.h"
//#include "test1_api.h"
#include "test2_ecall.h"
#include "test3_ecall.h"
//#include "test4_pthread.h"
//#include "test5.h"
//#include "bench.h"
//
#include <limits.h>
#include <stdint.h>
#include <math.h>
#include <sys/syscall.h>

uint64_t get_minimum(timing_index idx) {
  uint64_t min = UINT64_MAX;
  for (size_t i = 0; i < NUM_TESTRUNS; i++) {
    if (timing_values[idx][i] < min) {
      min = timing_values[idx][i];
    }
  }
  return min;
}

uint64_t get_maximum(timing_index idx) {
  uint64_t max = 0;
  for (size_t i = 0; i < NUM_TESTRUNS; i++) {
    if (timing_values[idx][i] > max) {
      max = timing_values[idx][i];
    }
  }
  return max;
}

int timing_cmp(const void * a, const void * b) {
  return *(uint64_t*)a > *(uint64_t*)b;
}

double get_average(timing_index idx) {
  double avg = 0.0f;
  for (size_t i = 0; i < NUM_TESTRUNS; i++) {
    avg += (double)timing_values[idx][i] / (double)NUM_TESTRUNS;
  }
  return avg;
}

#ifdef PROXYKERNEL
uint64_t get_median(timing_index idx) {
  //qsrot doesn't work in proxykernel
  return (uint64_t)get_average(idx);
}
#else
uint64_t get_median(timing_index idx) {
  qsort(timing_values[idx], NUM_TESTRUNS, sizeof(uint64_t), timing_cmp);
  return timing_values[idx][NUM_TESTRUNS/2];
}
#endif

double get_variance(timing_index idx, double avg) {
  double var = 0.0f;
  for (size_t i = 0; i < NUM_TESTRUNS; i++) {
    var += pow(timing_values[idx][i] - avg, 2) / (double)NUM_TESTRUNS;
  }
  return var;
}

void timing_results(){
    FILE* f = fopen("results.csv", "w");
    if (!f) {
      perror("Could not open result file");
      exit(1);
    }
    fprintf(f, "test;min;max;med;avg;std\n");
    printf(">>> TIMING NUM_TESTRUNS: %u\n", NUM_TESTRUNS);
    printf(">>> TIMING NUM_NESTING_LEVEL: %u\n", NUM_NESTING_LEVEL);
    #if TIMING_HANDLER_C == 0
        for (size_t idx = 0; idx < TIMING_T_MAX; idx++)
        {
            #ifdef TIMING_MEASURE_MINIMUM
            printf(">>> TIMING RESULT for %s : %zu\n", TIMING_INDEX_TO_STR(idx), timing_values[idx]);
            #else
            uint64_t min = get_minimum(idx);
            uint64_t max = get_maximum(idx);
            uint64_t med = get_median(idx);
            double   avg = get_average(idx);
            double   var = get_variance(idx, avg);
            double   std = sqrt(var);
            printf(">>> TIMING RESULT for %35s (min|max): %6zu|%6zu, median: %6zu, avg: %8.2f+-%8.2f", TIMING_INDEX_TO_STR(idx), min, max, med, avg, std);
            fprintf(f, "%s;%zu;%zu;%zu;%0.2f;%0.2f\n", TIMING_INDEX_TO_STR(idx), min, max, med, avg, std);
            //~ for (size_t j = 0; j < NUM_TESTRUNS; j++) {
              //~ printf("%zu ", timing_values[idx][j]);
            //~ }
            printf("\n");
            #endif
        }
    #else // TIMING_HANDLER_C
    if(timing_min == UINT64_MAX){
        timing_min = 0;
    }
    printf(">>> TIMING RESULT for TIMING_HANDLER_C (min): %zu\n", timing_min);
    #endif // TIMING_HANDLER_C
    fclose(f);
}

#if __x86_64 && !(FAKE_MPK_REGISTER)
#define _test_pkru() \
    /* eax holds pkru value, ecx,edx must be 0. */ \
    __asm__ volatile( \
        "xor %%ecx, %%ecx\n" \
        "xor %%edx, %%edx\n" \
        "mov $0,   %%rax\n" \
        "wrpkru\n" \
        : : : "rax","rcx","rdx" \
    )
#elif __x86_64 && FAKE_MPK_REGISTER
#define _test_pkru()
#else
#define _test_pkru() \
  __asm__ volatile( \
      "li t0, 0;" \
  )
#endif

void bench_preinit(){
  printf("bench_preinit()\n");

  printf("before test getpid\n");
  getpid(); // warmup
  for (size_t i = 0; i < NUM_TESTRUNS; i++)
  {
      uint64_t time = RDTSC();
      getpid();
      TIME_LOG(TIMING_GETPID, i, RDTSC() - time);
  }
}

void bench(){
    printf("bench()\n");

    volatile int xx;
    for (size_t i = 0; i < NUM_TESTRUNS; i++) {
       xx = i;
    }
    printf("before ecall_test3_time\n");
    ecall_test3_time(); // warmup
    printf("after ecall_test3_time\n");
    for (size_t i = 0; i < NUM_TESTRUNS; i++)
    {
        uint64_t time0 = RDTSC();
        uint64_t time1 = ecall_test3_time();
        uint64_t time2 = RDTSC();
        TIME_LOG(TIMING_ECALL_TEST3_TIME_COMPLETE, i, time2 - time0);
        TIME_LOG(TIMING_ECALL_TO_INSIDE,           i, time1 - time0);
        TIME_LOG(TIMING_INSIDE_ECALL_TO_RETURN,    i, time2 - time1);
    }

    printf("before test RDTSC\n");
    for (size_t i = 0; i < NUM_TESTRUNS; i++)
    {
        uint64_t time = RDTSC();
        time = RDTSC() - time;
        TIME_LOG(TIMING_RDTSC, i, time);
    }

    printf("before test ecall_test_args\n");
    ecall_test_args(0x10, 0x11, 0x12, 0x13, 0x14, 0x15); // warmup
    for (size_t i = 0; i < NUM_TESTRUNS; i++)
    {
        uint64_t time = RDTSC();
        ecall_test_args(0x10, 0x11, 0x12, 0x13, 0x14, 0x15);
        TIME_LOG(TIMING_ECALL_TEST_ARGS, i, RDTSC() - time);
    }

    printf("before test ecall_save_frame_overhead\n");
    ecall_save_frame_prepare();
    ecall_save_frame_overhead(); // warmup
    for (size_t i = 0; i < NUM_TESTRUNS; i++)
    {
        uint64_t time = RDTSC();
        ecall_save_frame_overhead();
        TIME_LOG(TIMING_ECALL_SAVE_FRAME_OVERHEAD, i, RDTSC() - time);
    }

//#if __x86_64
    printf("before test test_args\n");
    //Note: Here we're calling test_args directly from root domain, 
    // so we need to have the key for that domain loaded in the root domain!
    extern uint64_t test_args(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f);
    //
    //workaround for faulty hardware which fails when FETCHING protected code.
    int x = test_args(0x10, 0x11, 0x12, 0x13, 0x14, 0x15); // warmup
    for (size_t i = 0; i < NUM_TESTRUNS; i++)
    {
        uint64_t time = RDTSC();
        x = test_args(0x10, 0x11, 0x12, 0x13, 0x14, 0x15);
        TIME_LOG(TIMING_TEST_ARGS, i, RDTSC() - time);
    }
//#endif

    printf("before test pk_simple_api_call\n");
    pk_simple_api_call(1,2,3,4,5,6); // warmup
    for (size_t i = 0; i < NUM_TESTRUNS; i++)
    {
        uint64_t time = RDTSC();
        pk_simple_api_call(1,2,3,4,5,6);
        TIME_LOG(TIMING_SIMPLE_API_CALL, i, RDTSC() - time);
    }

    printf("before test ecall_test3_nested\n");
    ecall_test3_nested(NUM_NESTING_LEVEL); // warmup
    for (size_t i = 0; i < NUM_TESTRUNS; i++)
    {
        uint64_t time = RDTSC();
        ecall_test3_nested(NUM_NESTING_LEVEL);
        TIME_LOG(TIMING_NESTING, i, RDTSC() - time);
    }

    // TODO: save and restore pkru before running this?
    printf("before test _test_pkru\n");
    _test_pkru(); // warmup
    for (size_t i = 0; i < NUM_TESTRUNS; i++)
    {
        uint64_t time = RDTSC();
        _test_pkru();
        TIME_LOG(TIMING_PKRU, i, RDTSC() - time);
    }

#ifndef PROXYKERNEL
    printf("before test mprotect\n");
    void* page = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
    // warmup
    // do not directly call syscall(SYS_mprotect...) as this is blocked by our sysfilter
    mprotect(page, 4096, PROT_READ);
    mprotect(page, 4096, PROT_READ);
    assert(0 == mprotect(page, 4096, PROT_READ));
    for (size_t i = 0; i < NUM_TESTRUNS; i++)
    {
        uint64_t time = RDTSC();
        mprotect(page, 4096, PROT_READ);
        TIME_LOG(TIMING_MPROTECT, i, RDTSC() - time);
    }
#endif /* PROXYKERNEL */

    printf("before test close\n");
    close(0); // warmup
    for (size_t i = 0; i < NUM_TESTRUNS; i++)
    {
        uint64_t time = RDTSC();
        close(0);
        TIME_LOG(TIMING_CLOSE, i, RDTSC() - time);
    }

    printf("before test sysfilter-getpid\n");
    int truepid = getpid();
    printf("pid: %d\n", truepid);
    for (size_t i = 0; i < NUM_TESTRUNS; i++)
    {
        uint64_t time = RDTSC();
        getpid();
        TIME_LOG(TIMING_INTERPOSE_GETPID, i, RDTSC() - time);
    }
}
#endif // TIMING
