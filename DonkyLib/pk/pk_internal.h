#pragma once
#include "pk_defs.h"

/**********************************************************************/
// Global Defines
/**********************************************************************/

// Max. number of ECALLs (over all domains)
#define NUM_REGISTERED_ECALLS 64

// Size of trusted exception stack slots
#ifdef RELEASE
// For debug output, give more stack
#define EXCEPTION_STACK_WORDS (1024*(PAGESIZE/WORDSIZE)) // 4MB
#else
#define EXCEPTION_STACK_WORDS (16*(PAGESIZE/WORDSIZE))   // 64KB
#endif // RELEASE

#define GET_STACK_TOP(DOMAIN_THREAD_DATA) ((uintptr_t)(DOMAIN_THREAD_DATA)->user_stack_base + ((DOMAIN_THREAD_DATA)->user_stack_size) - 2*WORDSIZE)

// Size of thread-local signal stack
#define PKU_SIGSTACK_SIZE_BYTES (4*PAGESIZE)

//------------------------------------------------------------------------------
//Defines for the API table
//NOTE this cannot be an enum because we need the values in assembly
#define _API_unused0                       0
#define _API_pk_deinit                     1
#define _API_pk_current_did                2
#define _API_pk_register_exception_handler 3
#define _API_unused4                       4
#define _API_pk_domain_create              5
#define _API_pk_domain_free                6
#define _API_pk_domain_release_child       7
#define _API_unused8                       8
#define _API_unused9                       9
#define _API_pk_pkey_alloc                10
#define _API_pk_pkey_free                 11
#define _API_pk_pkey_mprotect             12
#define _API_pk_pkey_mprotect2            13
#define _API_unused14                     14
#define _API_unused15                     15
#define _API_unused16                     16
#define _API_unused17                     17
#define _API_unused18                     18
#define _API_unused19                     19
#define _API_pk_mmap                      20
#define _API_pk_mmap2                     21
#define _API_pk_mmap3                     22
#define _API_pk_munmap                    23
#define _API_pk_munmap2                   24
#define _API_pk_mprotect                  25
#define _API_pk_mprotect2                 26
#define _API_unused27                     27
#define _API_unused28                     28
#define _API_unused29                     29
#define _API_pk_domain_register_ecall     30
#define _API_pk_domain_register_ecall2    31
#define _API_pk_domain_allow_caller       32
#define _API_pk_domain_allow_caller2      33
#define _API_pk_domain_assign_pkey        34
#define _API_pk_domain_default_key        35
#define _API_pk_domain_load_key           36
#define _API_unused37                     37
#define _API_unused38                     38
#define _API_unused39                     39
#define _API_pk_pthread_create            40
#define _API_pk_pthread_exit              41
#define _API_pk_print_debug_info          42
#define _API_pk_simple_api_call           43
#define _API_pk_malloc                    44
#define API_TABLE_SIZE                    45 // must be exactly 1 more than the highest API id
//------------------------------------------------------------------------------

#define KEY_FOR_UNPROTECTED       0
#define KEY_FOR_ROOT_DOMAIN       1
#define KEY_FOR_EXCEPTION_HANDLER 2

#define DID_FOR_ROOT_DOMAIN       0
#define DID_FOR_EXCEPTION_HANDLER 1
#define DID_INVALID              -1

/**********************************************************************/
// Arch-specific
/**********************************************************************/

#include "pk_handler.h"

/**********************************************************************/
// For C only
#ifndef __ASSEMBLY__
/**********************************************************************/

#include "pk_debug.h"
#include "pk.h"
#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>
#include <pthread.h>
#include <mprotect.h>

#ifdef __cplusplus
extern "C" {
#endif

//------------------------------------------------------------------------------
// C Defines
//------------------------------------------------------------------------------
#define C_STATIC_ASSERT(test) typedef char assertion_on_mystruct[( !!(test) )*2-1 ]

//------------------------------------------------------------------------------
// Linker symbols defined by linker_common.ld
//------------------------------------------------------------------------------
#ifndef SHARED
extern uintptr_t __start_pk_all[];
extern uintptr_t __stop_pk_all[];
extern uintptr_t __start_pk_data[];
extern uintptr_t __stop_pk_data[];
extern uintptr_t __start_pk_code[];
extern uintptr_t __stop_pk_code[];

extern uintptr_t __tls_static_start[];
extern uintptr_t __tls_static_end[];
#endif

//------------------------------------------------------------------------------
// Generic PK typedefs
//------------------------------------------------------------------------------

/* Struct which is pushed on caller stack upon dcall, and verified upon dreturn */
typedef struct _expected_return {
    int      did;
    void *   reentry;
    void *   previous;
#ifdef ADDITIONAL_DEBUG_CHECKS
    void *   sp;
    uint64_t cookie;
#endif
#ifdef EXPECTED_RETURN_PADDING
    unsigned char padding[EXPECTED_RETURN_PADDING];
#endif
} _expected_return;
//------------------------------------------------------------------------------

/* Struct which is pushed on target stack upon dcall such that it knows where to return to */
typedef struct _return_did {
#ifdef ADDITIONAL_DEBUG_CHECKS
    uint64_t cookie1;
#endif
    int64_t did;
#ifdef ADDITIONAL_DEBUG_CHECKS
    uint64_t cookie2;
#endif
} _return_did;
//------------------------------------------------------------------------------

/* Struct for maintaining a domain's protection keys */
typedef struct __attribute__((packed)) {
    vkey_t   vkey;            // Virtual protection key
    pkey_t   pkey;            // Arch specific protection key
    bool     owner : 1;       // Key is owned, i.e., it can be used for mmap/munmap/(pkey_)mprotect/pkey_free
    int      perm  : 4;       // Page permissions
    bool     used  : 1;       // Is key slot used
    int      _reserved : 10;
} pk_key_t;
//------------------------------------------------------------------------------

/* Struct representing a domain */
typedef struct _pk_domain {
    int           used;       // Is domain slot used
    int           parent_did; // did of domain which created this domain, or -1 if none

    pk_key_t      keys[NUM_KEYS_PER_DOMAIN];

    pkru_config_t default_config; // Caches pkru config. For RISC-V, it is loaded only at domain transitions, for x86 it is always loaded into dkru when leaving PK_CODE
    int           previous_slot;  // For RISC-V, maintains the previous key slot for round-robin key scheduling in dkru

    int           allowed_source_domains[NUM_SOURCE_DOMAINS]; // List of domains that can call into our domain
    size_t        allowed_source_domains_count;               // Number of valid domains in allowed_source_domains
} _pk_domain;
//------------------------------------------------------------------------------

/* Struct for storing stack information in TLS */
typedef struct _pk_thread_domain {
    _expected_return * expected_return; // points to the stack where the struct lives in case a dcall is pending (waiting for return), or null.
    uint64_t *         user_stack_base; // base address of user stack
    size_t             user_stack_size; // size in bytes
} _pk_thread_domain;
//------------------------------------------------------------------------------

/* Struct for keeping trusted data in TLS */
typedef struct __attribute__((packed)) {
#ifdef TLS_MISALIGNMENT_BUG
    char padding1[PAGESIZE];
#endif
    uint64_t * backup_user_stack;    // This must be the first element for asm code to work. holds user stack pointer during exception handling
    uint64_t * exception_stack;      // This must be the second element for asm code to work. top of exception stack, used for exception handling
    uint64_t * exception_stack_base; // base address of exception stack
    pkru_config_t current_pkru;      // This must be the fourth element for asm code to work. holds current pkru config for this thread and is also needed for _pk_domain_is_key_loaded_arch

    _pk_thread_domain thread_dom_data[NUM_DOMAINS]; // User stacks for all domains this thread visits
                                                    //TODO this needs to be aligned. (despite packed)

    int current_did;                 // domain ID in which thread is currently executing
    int tid;                         // thread ID

    bool init;                       // Is the thread already initialized by our library? If not, current_did and other fields are invalid, and CURRENT_DID might not be used

    // Fill struct up to a multiple of PAGESIZE
    #define __TLS_STRUCT_SIZE_ABOVE (sizeof(uint64_t*) * 3 + sizeof(pkru_config_t) + sizeof(bool) + sizeof(int) * 2 + sizeof(_pk_thread_domain) * NUM_DOMAINS)
    unsigned char unused[PAGESIZE - __TLS_STRUCT_SIZE_ABOVE % PAGESIZE];
    #undef __TLS_STRUCT_SIZE_ABOVE
#ifdef TLS_MISALIGNMENT_BUG
    char padding2[PAGESIZE];
#endif
} _pk_tls;
//------------------------------------------------------------------------------

C_STATIC_ASSERT((sizeof(_pk_domain) % 8) == 0);
C_STATIC_ASSERT(sizeof(pk_key_t) == 8);
C_STATIC_ASSERT((sizeof(_pk_tls) % PAGESIZE) == 0);
C_STATIC_ASSERT((sizeof(pkru_config_t) % WORDSIZE) == 0);
//------------------------------------------------------------------------------

/* Struct for book-keeping memory mappings */
typedef struct mprotect_t {
    void *   addr;  // start address
    size_t   len;   // length in bytes
    int      prot;  // page permissions, according to mmap/mprotect
    vkey_t   vkey;  // virtual protection key
    pkey_t   pkey;  // physical protection key
    bool   used;    // shows whether this mprotect_t slot is in use or not
} mprotect_t;
//------------------------------------------------------------------------------

/* Struct for temporarily passing pthread_create arguments from parent to child */
typedef struct {
  void* exception_stack;
  void* exception_stack_top;
  void* start_routine;
  void* arg;
  int current_did;
} pthread_arg_t;
//------------------------------------------------------------------------------

/* Global struct for all essential data */
typedef struct _pk_data {
    int             initialized;
    pthread_mutex_t mutex;                              // Global PK mutex
    pthread_mutex_t condmutex;                          // Mutex for cond
    pthread_cond_t  cond;                               // Condition variable for syncing pthread creation
    int             pagesize;                           // System's page size
    size_t          stacksize;                          // Size of user stacks we lazily allocating pthread stacks
    pthread_arg_t   pthread_arg;                        // For passing pthread_create arguments from parent to child thread
    void            (*user_exception_handler)(void*);   // Forward pk exceptions to a user program (currently only for debugging)

    _pk_domain      domains[NUM_DOMAINS];               // List of all domains

    _pk_tls *       threads[NUM_THREADS];               // Pointers to TLS to manage threads which are currently not running
    mprotect_t      ranges[NUM_MPROTECT_RANGES];        // List of memory mappings
    size_t          stat_num_exceptions;                // Statistics for number of exceptions

} _pk_data;
//------------------------------------------------------------------------------

/* Struct for registered ecalls */
typedef struct _pk_ecall {
    void * entry;   // Ecall entry point
    int did;        // Ecall registered for this domain
} _pk_ecall;
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
// Variable declarations
//------------------------------------------------------------------------------
extern _pk_data pk_data;                  // Global pk data
extern __thread _pk_tls  pk_trusted_tls;  // Per-thread pk data
extern uint64_t _pk_ttls_offset;          // Offset of pk_trusted_tls from thread pointer (fs on x86, or tp on RISC-V)

//------------------------------------------------------------------------------
// Internal API functions
//------------------------------------------------------------------------------
int      PK_CODE _pk_init(void);
int      PK_CODE _pk_deinit(void);
int      PK_CODE _pk_domain_create(unsigned int flags);
int      PK_CODE _pk_domain_free(int did);
int      PK_CODE _pk_domain_release_child(int did);
vkey_t   PK_CODE _pk_pkey_alloc(unsigned int flags, unsigned int access_rights);
int      PK_CODE _pk_pkey_free(vkey_t vkey);
int      PK_CODE _pk_domain_assign_pkey(int did, vkey_t vkey, int flags, int access_rights);
int      PK_CODE _pk_domain_default_key(int did);
int      PK_CODE _pk_pkey_mprotect(void *addr, size_t len, int prot, vkey_t vkey);
int      PK_CODE _pk_pkey_mprotect2(int did, void *addr, size_t len, int prot, vkey_t vkey);
void*    PK_CODE _pk_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void*    PK_CODE _pk_mmap2(int did, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void*    PK_CODE _pk_mmap3(vkey_t vkey, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int      PK_CODE _pk_munmap(void* addr, size_t len);
int      PK_CODE _pk_munmap2(int did, void* addr, size_t len);
int      PK_CODE _pk_mprotect(void *addr, size_t len, int prot);
int      PK_CODE _pk_mprotect2(int did, void *addr, size_t len, int prot);
int      PK_CODE _pk_domain_register_ecall(int ecall_id, void* entry);
int      PK_CODE _pk_domain_register_ecall2(int did, int ecall_id, void* entry);
int      PK_CODE _pk_domain_allow_caller(int caller_did, unsigned int flags);
int      PK_CODE _pk_domain_allow_caller2(int did, int caller_did, unsigned int flags);
int      PK_CODE _pk_domain_load_key(vkey_t vkey, int slot, unsigned int flags);
int      PK_CODE _pk_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                                    void *(*start_routine) (void *), void *arg);
void     PK_CODE _pk_pthread_exit(void* retval);
int      PK_CODE _pk_register_exception_handler(void (*handler)(void*));

//------------------------------------------------------------------------------
// Internal functions
//------------------------------------------------------------------------------
int      PK_CODE _pk_exception_key_mismatch_unlocked(void * bad_addr);
uint64_t PK_CODE _pk_exception_handler_unlocked(uint64_t data, uint64_t id, uint64_t type, uint64_t * stack_of_caller, void * reentry);
void*    PK_CODE _pk_mmap_internal(int did, vkey_t vkey, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int      PK_CODE _pk_pkey_mprotect_unlocked(int did, void *addr, size_t len, int prot, vkey_t vkey);
int      PK_CODE _pk_pkey_mprotect_unlocked_nodid_check(int did, void *addr, size_t len, int prot, vkey_t vkey);
int      PK_CODE _pk_pkey_munprotect_unlocked(int did, void *addr, size_t len, int prot);
vkey_t   PK_CODE _pk_pkey_alloc_unlocked(int did, unsigned int flags, unsigned int access_rights);
int      PK_CODE _pk_current_did(void);
int      PK_CODE _pk_simple_api_call(int a, int b, int c, int d, int e, int f);
void     PK_CODE _pk_print_debug_info();
void     PK_CODE _pthread_init_function_c(void * start_routine, void * current_user_stack);
int      PK_CODE _pk_domain_load_key_unlocked(int did, vkey_t vkey, int slot, unsigned int flags);

int      PK_CODE _pk_domain_create_unlocked(unsigned int flags);
int      PK_CODE _pk_domain_assign_pkey_unlocked(int source_did, int target_did, vkey_t vkey, int flags, int access_rights);
void*    PK_CODE _pk_setup_thread_exception_stack(void);
int      PK_CODE _pk_init_thread(int did, void* exception_stack);

int      PK_CODE _pk_selfprotect(int did, vkey_t vkey);
int      PK_CODE _pk_selfunprotect();


//------------------------------------------------------------------------------
// Inline functions
//------------------------------------------------------------------------------

FORCE_INLINE int _pk_init_lock() {
  int ret;
  pthread_mutexattr_t attr;
  if (0 != pthread_mutexattr_init(&attr) ||
      0 != pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)) {
    ERROR("Unable to initialize mutex attributes");
    errno = EINVAL;
    return -1;
  }
  ret = pthread_mutex_init(&pk_data.mutex, &attr);
  if (ret) {
    ERROR("Unable to initialize mutex");
    errno = EINVAL;
    return -1;
  }
  assert(0 == pthread_mutexattr_destroy(&attr));

  ret = pthread_mutex_init(&pk_data.condmutex, NULL);
  if (ret) {
    ERROR("Unable to initialize cond-mutex");
    errno = EINVAL;
    return -1;
  }

  ret = pthread_cond_init(&pk_data.cond, NULL);
  if (ret) {
    ERROR("Unable to initialize condition variable");
    errno = EINVAL;
    return -1;
  }

  return 0;
}
//------------------------------------------------------------------------------

FORCE_INLINE void _pk_acquire_lock() {
#ifndef PROXYKERNEL
  DEBUG_MPK("start %p", (void*)pthread_self());
  assert(0 == pthread_mutex_lock(&pk_data.mutex));
  DEBUG_MPK("end");
#endif /* PROXYKERNEL */
}
//------------------------------------------------------------------------------

FORCE_INLINE void _pk_release_lock() {
#ifndef PROXYKERNEL
  DEBUG_MPK("start %p", (void*)pthread_self());
  int ret = pthread_mutex_unlock(&pk_data.mutex);
  DEBUG_MPK("res: %d: %s", ret, strerror(ret));
  assert(0 == ret);
  DEBUG_MPK("end");
#endif /* PROXYKERNEL */
}
//------------------------------------------------------------------------------

FORCE_INLINE void _pk_wait_cond() {
#ifndef PROXYKERNEL
  DEBUG_MPK("lock");
  assert(0 == pthread_mutex_lock(&pk_data.condmutex));
  DEBUG_MPK("wait");
  assert(0 == pthread_cond_wait(&pk_data.cond, &pk_data.condmutex));
  DEBUG_MPK("unlock");
  assert(0 == pthread_mutex_unlock(&pk_data.condmutex));
  DEBUG_MPK("end");
#endif
}
//------------------------------------------------------------------------------

FORCE_INLINE void _pk_signal_cond() {
#ifndef PROXYKERNEL
  DEBUG_MPK("start");
  assert(0 == pthread_cond_signal(&pk_data.cond));
  DEBUG_MPK("end");
#endif
}
//------------------------------------------------------------------------------

FORCE_INLINE const char * type_str(int type)
{
    if(type >= 4 || type < 0){
        type = 4;
    }
    static const char * pk_type_str[] = {"RET", "CALL", "API", "EXCEPTION", "__???????__"};
    return pk_type_str[type];
}
//------------------------------------------------------------------------------

#ifdef __cplusplus
}
#endif

#endif // __ASSEMBLY__
