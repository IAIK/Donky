#define _GNU_SOURCE 1 //Needed for pthread_getattr_np and for link.h
#include <pthread.h>
#include <link.h>

#include "pk.h"
#include "pk_internal.h"

#include <sys/resource.h> // getrlimit
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include "mprotect.h"
#include "limits.h"

#include "sysfilter.h"
#include <sys/ioctl.h>
#include <sys/syscall.h>


#define PK_CODE_INLINE __attribute__((always_inline)) static inline PK_CODE 

//------------------------------------------------------------------------------
// Internal globals
//------------------------------------------------------------------------------
//For attributes: See also https://github.com/riscv/riscv-elf-psabi-doc/blob/master/riscv-elf.md#thread-local-storage
#ifdef SHARED
__thread  PK_API _pk_tls pk_trusted_tls __attribute__((aligned(PAGESIZE))) = {0,};
#else
__thread  _pk_tls pk_trusted_tls __attribute__((tls_model ("local-exec"))) __attribute__((aligned(PAGESIZE))) = {0,};
#endif
uint64_t PK_DATA _pk_ttls_offset = 0;


int       PK_DATA did_root;
int       PK_DATA did_for_exception_handler;
int       PK_DATA rokey_for_exception_handler = VKEY_INVALID; //read-only key that is given to all domains
_pk_ecall PK_DATA pk_registered_ecalls[NUM_REGISTERED_ECALLS];
_pk_data  PK_DATA pk_data = {0,};
int       PK_DATA pk_shared_pkeys[PK_NUM_KEYS] = {0,};
vkey_t    PK_DATA pk_vkey_cnt = 1;
bool      PK_DATA pk_sysfilter = false;

int PK_DATA block_syscalls[] = {
  SYS_mmap,
  SYS_mprotect,
  SYS_mremap,
  SYS_munmap,
  SYS_pkey_alloc,
  SYS_pkey_free,
  SYS_pkey_mprotect,
  /*
  SYS_prctl,
  SYS_seccomp,
  SYS_clone,
  SYS_fork,
  SYS_vfork,
  SYS_execve,
  SYS_execveat,
  */
  0
};


//------------------------------------------------------------------------------
// DL Hooking
//------------------------------------------------------------------------------

// If the pku_lib is preloaded, we need to prevent it from also hooking
// pk_lib, otherwise we would get recursion
// To do so, we find the original symbols, bypassing pku_lib preloading.

#ifdef DL_HOOKING
#include <dlfcn.h>

void *(*real_mmap)(void *, size_t, int, int, int, off_t) = NULL;
int   (*real_munmap)(void *addr, size_t length) = NULL;
int   (*real_mprotect)(void *, size_t, int) = NULL;
int   (*real_pkey_alloc)(unsigned int flags, unsigned int access_rights) = NULL;
int   (*real_pkey_free)(int pkey) = NULL;
int   (*real_pkey_mprotect)(void *addr, size_t len, int prot, int pkey) = NULL;
int   (*real_pthread_create)(pthread_t *thread, const pthread_attr_t *attr,
                        void *(*start_routine) (void *), void *arg) = NULL;

#define MMAP             real_mmap
#define MUNMAP           real_munmap
#define MPROTECT         real_mprotect
#define PKEY_ALLOC       pkey_alloc
#define PKEY_FREE        pkey_free
#define PKEY_MPROTECT    pkey_mprotect
#define PTHREAD_CREATE   real_pthread_create


int PK_CODE _pk_dl_libresolve_phdr(struct dl_phdr_info *info, size_t size, void* data)
{
  const char** name = (const char**)data;
  DEBUG_MPK("Searching for %s", *name);
  DEBUG_MPK("Resolving module %s", info->dlpi_name);
  if (strstr(info->dlpi_name, *name)) {
    *name = info->dlpi_name;
    return 1;
  }
  return 0;
}
//------------------------------------------------------------------------------

const char* PK_CODE _pk_dl_libresolve(const char* search){
  DEBUG_MPK("_pk_dl_libresolve(%p=%s)", search, search);
  const char* name = search;
  dl_iterate_phdr(_pk_dl_libresolve_phdr, &name);
  DEBUG_MPK("_pk_dl_libresolve found %s)", name);
  return name;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_dl_hooking(){
  // We hook to find the original libc functions
  // I.e. we want to bypass pku_lib preloading to avoid recursion, and
  // instead directly call to libc

  // Search for full library path
  const char* libc_path = _pk_dl_libresolve("libc.");
  const char* libpthread_path = _pk_dl_libresolve("libpthread.");

  // Open the already loaded libraries
  void* libc_handle = dlopen(libc_path, RTLD_LAZY | RTLD_NOLOAD);
  if (!libc_handle) {
    ERROR("libc could not be dlopened under %s", libc_path);
    return -1;
  }
  void* libpthread_handle = dlopen(libpthread_path, RTLD_LAZY | RTLD_NOLOAD);
  if (!libpthread_handle) {
    ERROR("libpthread could not be dlopened under %s", libpthread_path);
    return -1;
  }

  // Do symbol resolution
  if (!real_mmap) {
    DEBUG_MPK("Hooking mmap\n");
    real_mmap = dlsym(libc_handle, "mmap");
    DEBUG_MPK("real_mmap: %p", real_mmap);
  }
  if (!real_munmap) {
    DEBUG_MPK("Hooking munmap\n");
    real_munmap = dlsym(libc_handle, "munmap");
    DEBUG_MPK("real_munmap: %p", real_munmap);
  }
  if (!real_mprotect) {
    DEBUG_MPK("Hooking mprotect\n");
    real_mprotect = dlsym(libc_handle, "mprotect");
    DEBUG_MPK("real_mprotect: %p", real_mprotect);
  }
  if (!real_pthread_create) {
    DEBUG_MPK("Hooking pthread_create\n");
    real_pthread_create = dlsym(libpthread_handle, "pthread_create");
    DEBUG_MPK("real_pthread_create: %p", real_pthread_create);
  }
  if (!real_mmap ||
      !real_munmap ||
      !real_mprotect ||
      !real_pthread_create
      ) {
  
    errno = EACCES;
    return -1;
  }
  return 0;
}

#else // DL_HOOKING

#define MMAP             mmap
#define MUNMAP           munmap
#define MPROTECT         mprotect
#define PKEY_ALLOC       pkey_alloc
#define PKEY_FREE        pkey_free
#define PKEY_MPROTECT    pkey_mprotect
#define PTHREAD_CREATE   pthread_create

#endif // DL_HOOKING

//------------------------------------------------------------------------------
// Internal functions
//------------------------------------------------------------------------------

void PK_CODE_INLINE _debug_key(pk_key_t* key) {
    assert(key);
    DEBUG_MPK("pk_key_t {");
    DEBUG_MPK("  used =%d", key->used);
    DEBUG_MPK("  vkey =%d", key->vkey);
    DEBUG_MPK("  pkey =%d", key->pkey);
    DEBUG_MPK("  owner=%d", key->owner);
    DEBUG_MPK("  perm =%d", key->perm);
    DEBUG_MPK("}");
}
//-------------------------------------------------------------------------------

void PK_CODE_INLINE _debug_range(int rid) {
    DEBUG_MPK("mprotect_t {");
    DEBUG_MPK("  used=%d  ", pk_data.ranges[rid].used);
    DEBUG_MPK("  addr=%p  ", pk_data.ranges[rid].addr);
    DEBUG_MPK("  len =%zu ", pk_data.ranges[rid].len);
    DEBUG_MPK("  prot=%d  ", pk_data.ranges[rid].prot);
    DEBUG_MPK("  vkey=%d  ", pk_data.ranges[rid].vkey);
    DEBUG_MPK("  pkey=%d  ", pk_data.ranges[rid].pkey);
    DEBUG_MPK("}");
}
//-------------------------------------------------------------------------------

size_t PK_CODE_INLINE _get_default_stack_size() {
    struct rlimit rlim;
    size_t stack_size = 0;
    if(getrlimit(RLIMIT_STACK, &rlim) != 0){
        WARNING("getrlimit failed");
        stack_size = 1024*pk_data.pagesize; // 1MB
    }else{
        stack_size = rlim.rlim_cur;
    }
    DEBUG_MPK("stack size = %zu KB", stack_size/1024);
    return stack_size;
}
//------------------------------------------------------------------------------

ssize_t PK_CODE_INLINE _find_in_array(int val, int* array, size_t array_count){
    for (size_t i = 0; i < array_count; i++){
        if(array[i] == val){
            return i;
        }
    }
    return -1;
}
//------------------------------------------------------------------------------

bool PK_CODE_INLINE _domain_exists(int did){
    return (did >= 0 && did < NUM_DOMAINS && pk_data.domains[did].used);
}
//------------------------------------------------------------------------------

bool PK_CODE_INLINE _domain_is_current_or_child(int did){
    if (!_domain_exists(did)) {
      return false;
    }
    return (CURRENT_DID == did || 
            CURRENT_DID == pk_data.domains[did].parent_did);
}
//------------------------------------------------------------------------------

bool PK_CODE_INLINE _domain_is_child(int did){
    if (!_domain_exists(did)) {
      return false;
    }
    return (CURRENT_DID == pk_data.domains[did].parent_did);
}
//------------------------------------------------------------------------------

ssize_t PK_CODE_INLINE _domain_get_vkey_id(int did, vkey_t vkey){
    if (!_domain_exists(did)) {
      return -1;
    }

    for (size_t key_id = 0; key_id < NUM_KEYS_PER_DOMAIN; key_id++){
        pk_key_t * pk_key = &(pk_data.domains[did].keys[key_id]);
        if (pk_key->used && pk_key->vkey == vkey) {
            return key_id;
        }
    }
    return -1;
}
//------------------------------------------------------------------------------

bool PK_CODE_INLINE _domain_has_vkey_nodidcheck(int did, vkey_t vkey){
    assert_ifdebug(_domain_exists(did));

    for (size_t key_id = 0; key_id < NUM_KEYS_PER_DOMAIN; key_id++){
        if (pk_data.domains[did].keys[key_id].used &&
            pk_data.domains[did].keys[key_id].vkey == vkey) {
            return true;
        }
    }
    return false;
}
//------------------------------------------------------------------------------

bool PK_CODE_INLINE _domain_owns_vkey_nodidcheck(int did, vkey_t vkey){
    assert_ifdebug(_domain_exists(did));

    for (size_t key_id = 0; key_id < NUM_KEYS_PER_DOMAIN; key_id++){
        if (pk_data.domains[did].keys[key_id].used &&
            pk_data.domains[did].keys[key_id].vkey == vkey &&
            pk_data.domains[did].keys[key_id].owner) {
            return true;
        }
    }
    return false;
}
//------------------------------------------------------------------------------

pkey_t PK_CODE_INLINE _vkey_to_pkey(int did, vkey_t vkey){
    //DEBUG_MPK("_vkey_to_pkey(%d, %d)", did, vkey);
    if (!_domain_exists(did) || VKEY_INVALID == vkey) {
      return (pkey_t)-1;
    }

    for (size_t key_id = 0; key_id < NUM_KEYS_PER_DOMAIN; key_id++){
        if (pk_data.domains[did].keys[key_id].used &&
            pk_data.domains[did].keys[key_id].vkey == vkey) {
                return pk_data.domains[did].keys[key_id].pkey;
        }
    }
    assert(false);
}
//------------------------------------------------------------------------------

bool PK_CODE_INLINE _is_allowed_source_nodidcheck(int source_did, int target_did){
    assert_ifdebug(_domain_exists(source_did));
    assert_ifdebug(_domain_exists(target_did));

    return (-1 != _find_in_array(
        source_did,
        pk_data.domains[(target_did)].allowed_source_domains,
        pk_data.domains[(target_did)].allowed_source_domains_count)
    );
}
//------------------------------------------------------------------------------

bool PK_CODE_INLINE _transition_allowed_nodidcheck(int target_did){
    if (CURRENT_DID == 0){
        DEBUG_MPK("transition allowed because current did = 0");
        return true;
    }
    if(_is_allowed_source_nodidcheck(CURRENT_DID, target_did)){
        DEBUG_MPK("current did (%d) is allowed to transition to %d", CURRENT_DID, target_did);
        return true;
    }
    return false;
}
//------------------------------------------------------------------------------
vkey_t PK_CODE_INLINE _get_default_vkey(int did){
    if (!_domain_exists(did)) {
        ERROR("Invalid did");
        return VKEY_INVALID;
    }

    // first slot holds default key
    if (!pk_data.domains[did].keys[0].used) {
        ERROR("Default key[0] is unused");
        return VKEY_INVALID;
    }

    if (!pk_data.domains[did].keys[0].owner) {
        ERROR("Default key[0] has no owner permission");
        return VKEY_INVALID;
    }

    assert_ifdebug(pk_data.domains[did].keys[0].pkey != 0);
    return pk_data.domains[did].keys[0].vkey;
}

//------------------------------------------------------------------------------

PK_CODE void * _allocate_stack(size_t stack_size) {
    DEBUG_MPK("Allocating stack with size %zu", stack_size);
    int ret;

    void * stack_base = MMAP(NULL, stack_size + 2*PAGESIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
    if(stack_base == MAP_FAILED){
        ERROR("_allocate_stack: mmap failed");
        // errno is set by mmap
        return NULL;
    }

    // stack_addr due to guard page
    void * stack_addr = (void*)((uintptr_t)stack_base + PAGESIZE);

    DEBUG_MPK("Allocated stack @ %p size 0x%zx", stack_addr, stack_size);

    // first guard page
    ret = MPROTECT(stack_base, PAGESIZE, PROT_NONE);
    if(ret != 0){
        WARNING("_allocate_stack: mprotect on first guard page failed");
        // we continue here
    }
    DEBUG_MPK("Protected bottom stack guard page @ %p", stack_base);

    // second guard page
    ret = MPROTECT((char*)stack_addr + stack_size, PAGESIZE, PROT_NONE);
    if(ret != 0){
        WARNING("_allocate_stack: mprotect on last guard page failed");
        // we continue here
    }
    DEBUG_MPK("Protected top stack guard page @ %p", (char*)stack_addr + stack_size);

    return stack_addr;
}

//------------------------------------------------------------------------------

PK_CODE_INLINE _pk_tls * _get_thread_data(void) {
    assert_ifdebug(pk_trusted_tls.init);
    assert_ifdebug(pk_trusted_tls.current_did != DID_INVALID);
    assert_ifdebug(pk_trusted_tls.exception_stack_base != 0);
    assert_ifdebug(pk_trusted_tls.exception_stack != 0);
    assert_ifdebug(pk_trusted_tls.tid >= 0 && pk_trusted_tls.tid < NUM_THREADS);
    assert_ifdebug(pk_data.threads[pk_trusted_tls.tid]->tid == pk_trusted_tls.tid);

    return &pk_trusted_tls;
}
//------------------------------------------------------------------------------

PK_CODE_INLINE int _protect_user_stack(int did, _pk_thread_domain * data) {
    assert(data->user_stack_size);
    assert(data->user_stack_base);

    // Protect user stack
    DEBUG_MPK("Protect user stack for domain %d\n", did);
    int prot = PROT_WRITE | PROT_READ;
    //#ifndef PROXYKERNEL
    //prot |= PROT_GROWSDOWN;
    //#endif
    int ret = _pk_pkey_mprotect_unlocked_nodid_check(did, data->user_stack_base, data->user_stack_size, prot, PK_DEFAULT_KEY);
    if(ret != 0){
        ERROR("_protect_user_stack: failed to protect user stack");
    }
    return ret;
}

PK_CODE_INLINE int pk_pthread_attr_getstack(const pthread_attr_t *attr, void **stackaddr, size_t *stacksize) {
    if(pk_data.initialized){
        return pthread_attr_getstack(attr, stackaddr, stacksize);
    }

    char line[2048];
    FILE * fp = fopen("/proc/self/maps", "r");
    if(fp == NULL){
        ERROR_FAIL("Failed to fopen /proc/self/maps");
    }
    while (fgets(line, 2048, fp) != NULL) {
        if (strstr(line, "[stack]") == NULL)
            continue;

        DEBUG_MPK("line = %s", line);
        char * end1 = strstr(line, "-");
        char * end2 = strstr(line, " ");
        if(end1 == NULL || end2 == NULL){
            ERROR_FAIL("strstr failed.");
        }
        *end1 = '\0';
        *end2 = '\0';
        long int number1 = strtol(line,     NULL, 16);
        long int number2 = strtol(end1 + 1, NULL, 16);
        if(number1 == LONG_MIN || number1 == LONG_MAX){
            ERROR_FAIL("Could not parse number1.");
        }
        if(number2 == LONG_MIN || number2 == LONG_MAX){
            ERROR_FAIL("Could not parse number2.");
        }

        *stackaddr = (void*)number1;
        *stacksize = (uintptr_t)number2 - (uintptr_t)number1;
        assert(*stacksize > 0);
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return EINVAL;
}

PK_CODE_INLINE int _prepare_user_stack_pthread(int did, _pk_thread_domain * data) {

    size_t stacksize = 0;
    unsigned char * stackaddr = 0;

    #ifdef PROXYKERNEL
        syscall(1337, &stackaddr, &stacksize);
        WARNING("stacksize = %zu", stacksize);
        assert(stackaddr >= (unsigned char *)0x70000000ULL);
        assert(stacksize >= 4096*100);
    #else
        pthread_attr_t attr;
        int s = pthread_getattr_np(pthread_self(), &attr);
        assert(s == 0);
        s = pk_pthread_attr_getstack(&attr, (void*)&stackaddr, &stacksize);
        assert(s == 0);
        DEBUG_MPK("pthread whole stack (incl. red zone): %p-%p (len = %zu = 0x%zx)", stackaddr, stackaddr + stacksize, stacksize, stacksize);

        // clip off red zone (one page)
        // http://rachid.koucha.free.fr/tech_corner/problem_of_thread_creation.html
        stackaddr += PAGESIZE;
        stacksize -= PAGESIZE;

        DEBUG_MPK("pthread stack: %p-%p (len = %zu = 0x%zx)", stackaddr, stackaddr + stacksize, stacksize, stacksize);
    #endif

    data->user_stack_size = stacksize;
    data->user_stack_base = (void*)stackaddr;
    assert(data->user_stack_size);
    assert(data->user_stack_base);
    DEBUG_MPK("retrieved pthread user_stack_base %p, size %zu", data->user_stack_base, data->user_stack_size);

    // Protect user stack
    int ret = _protect_user_stack(did, data);
    assert(ret == 0);
    return 0;
}

PK_CODE int _allocate_user_stack(int did, _pk_thread_domain * data) {
    DEBUG_MPK("Allocating stack for thread and domain %d", did);
    assert_ifdebug(data->expected_return == 0);
    assert_ifdebug(data->user_stack_size == 0);
    assert_ifdebug(data->user_stack_base == 0);
    assert_ifdebug(pk_data.pagesize >= 4096); //make sure pk_data.pagesize is properly initialized
    assert_ifdebug(pk_data.stacksize >= (size_t)100*pk_data.pagesize); //make sure pk_data.stacksize is properly initialized

    assert_ifdebug(did != DID_FOR_ROOT_DOMAIN);
    assert_ifdebug(did != DID_FOR_EXCEPTION_HANDLER);

    // Create new user stack
    data->user_stack_size = pk_data.stacksize;
    data->user_stack_base = _allocate_stack(pk_data.stacksize);

    assert(data->user_stack_size);
    assert(data->user_stack_base);

    // Protect user stack
    int ret = _protect_user_stack(did, data);
    return ret;
}

//------------------------------------------------------------------------------

PK_CODE_INLINE _pk_thread_domain * _get_thread_domain_data_nodidcheck(int did) {
    assert_ifdebug(_domain_exists(did));


    //get data
    _pk_thread_domain * data = &(_get_thread_data()->thread_dom_data[did]);
    assert_ifdebug( (uintptr_t)data % WORDSIZE == 0); //check that pointer to member within a packed struct is aligned. TODO move this to a assert that only happens once during init or during compile time

    // initialize lazily/on demand
    if(likely(data->user_stack_base != 0)){
        assert_ifdebug(data->user_stack_size != 0);
        return data;
    }

    int ret = _allocate_user_stack(did, data);
    if(ret != 0){
        ERROR_FAIL("_allocate_user_stack failed");
    }

    return data;
}
//------------------------------------------------------------------------------

bool PK_CODE_INLINE _user_stack_push_allowed(_pk_thread_domain * data, uintptr_t stack_pointer, size_t size) {

    assert_ifdebug(data->user_stack_size);
    assert_ifdebug(data->user_stack_base);
    assert_ifdebug(size < data->user_stack_size);

    if(unlikely(
        stack_pointer - size <  (uintptr_t)data->user_stack_base ||
        stack_pointer        >= (uintptr_t)data->user_stack_base + data->user_stack_size
    )){
        WARNING("Push not allowed: stack frame= (0x%lx, 0x%lx), stack = (%p,0x%lx)", 
            stack_pointer, size, data->user_stack_base, data->user_stack_size);
        return false;
    }
    return true;
}
//------------------------------------------------------------------------------

bool PK_CODE_INLINE _user_stack_pop_allowed(_pk_thread_domain * data, uintptr_t stack_pointer, size_t size) {

    assert_ifdebug(data->user_stack_size);
    assert_ifdebug(data->user_stack_base);
    assert_ifdebug(size < data->user_stack_size);

    if(unlikely(
        stack_pointer        <  (uintptr_t)data->user_stack_base ||
        stack_pointer + size >= (uintptr_t)data->user_stack_base + data->user_stack_size
    )){
        WARNING("Pop not allowed: stack frame= (0x%lx, 0x%lx), stack = (%p,0x%lx)", 
            stack_pointer, size, data->user_stack_base, data->user_stack_size);
        return false;
    }
    return true;
}
//------------------------------------------------------------------------------

bool PK_CODE_INLINE _memory_overlaps(void* addr1, size_t len1, void* addr2, size_t len2) {
    return ((uintptr_t)addr1 < (uintptr_t)addr2 + len2) &&
          ((uintptr_t)addr1 + len1 > (uintptr_t)addr2);
}
//------------------------------------------------------------------------------

bool PK_CODE_INLINE _address_overlaps(void* addr1, void* addr2, size_t len2) {
    return (char*)addr1 >= (char*)addr2 && 
          (char*)addr1 < (char*)addr2 + len2;
}
//-------------------------------------------------------------------------------
/**
 * Unassigned memory can be owned by anyone. 
 * TODO: root domain needs to mprotect all shared libs to get their memory
 * tracked and assigned a key (0). Thus, only root domain can own it.
 */
bool PK_CODE_INLINE _domain_owns_memory(int did, void * addr, size_t len) {
    // DEBUG_MPK("_domain_owns_memory(%d, %p, %zu)", did, addr, len);
    if (did == DID_FOR_EXCEPTION_HANDLER) {
        return true;
    }
    if (!_domain_exists(did)) {
        return false;
    }
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (!pk_data.ranges[rid].used) {
          continue;
        }
        if (!_domain_owns_vkey_nodidcheck(did, pk_data.ranges[rid].vkey)) {
            // Domain does not own vkey of this memory range
            // Check that it does not overlap
            // DEBUG_MPK("Found foreign vkey on range: %p-%p, %zu", pk_data.ranges[rid].addr, (char*)pk_data.ranges[rid].addr+pk_data.ranges[rid].len, pk_data.ranges[rid].len);
            if (_memory_overlaps(addr, len, pk_data.ranges[rid].addr, pk_data.ranges[rid].len)) {
                // DEBUG_MPK("overlap");
                return false;
            }
            // DEBUG_MPK("no overlap");
        }
    }
    return true;
}
//-------------------------------------------------------------------------------

// returns -1 on error
vkey_t PK_CODE_INLINE _vkey_for_address_nodidcheck(int did, void * addr) {
    // DEBUG_MPK("_key_for_address(%d, %p)", did, addr);
    assert_ifdebug(_domain_exists(did));
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (!pk_data.ranges[rid].used) {
          continue;
        }
        vkey_t vkey = pk_data.ranges[rid].vkey;
        assert_ifdebug(VKEY_INVALID != vkey);
        if (_domain_has_vkey_nodidcheck(did, vkey)) {
            // Domain has key of this memory range
            // Check that it overlaps
            //DEBUG_MPK("Testing vkey on range: %p-%p, %zu", pk_data.ranges[rid].addr, (char*)pk_data.ranges[rid].addr+pk_data.ranges[rid].len, pk_data.ranges[rid].len);
            if (_address_overlaps(addr, pk_data.ranges[rid].addr, pk_data.ranges[rid].len)) {
                //DEBUG_MPK("Found vkey for requested range: %d", vkey);
                return vkey;
            }
            //DEBUG_MPK("no overlap");
        }
    }
    return VKEY_INVALID;
}
//------------------------------------------------------------------------------

/**
 * @brief This function handles missing-key-exception
 * 
 * TODO: write me
 */
int PK_CODE _pk_exception_key_mismatch_unlocked(void * bad_addr){
    DEBUG_MPK("_pk_exception_key_mismatch_unlocked(%p)", bad_addr);
    // keys are assigned on a page granularity
    // Yet, bad_addr could span two different keys on a page border
    // Load both of them
    static PK_DATA void * pk_previous_badaddr = NULL;
    static PK_DATA size_t pk_previous_badctr = 0;

    if (pk_previous_badaddr == bad_addr) {
        pk_previous_badctr++;
        if (pk_previous_badctr >= 3) {
            ERROR("Triple fault. Giving up");
            pk_previous_badctr = 0;
            errno = EPERM;
            return -1;
        }
    } else {
        pk_previous_badctr = 1;
        pk_previous_badaddr = bad_addr;
    }

    vkey_t vkey1 = _vkey_for_address_nodidcheck(CURRENT_DID, bad_addr);
    char* top_addr = (char*)bad_addr+WORDSIZE-1;
    // TODO optimize: if top_addr is on same page as bad_addr, reuse vkey2
    vkey_t vkey2 = _vkey_for_address_nodidcheck(CURRENT_DID, top_addr);
    if (VKEY_INVALID == vkey1 || VKEY_INVALID == vkey2) {
        ERROR("domain does not own pkeys for [%p-%p]", bad_addr, top_addr);
        errno = EPERM;
        return -1;
    }
    if ( 0 != _pk_domain_load_key_unlocked(CURRENT_DID, vkey1, PK_SLOT_ANY, 0) ){
        ERROR("failed to load vkey1");
        // errno is set by _pk_domain_load_key
        return -1;
    }
    if (vkey2 != vkey1 && 0 != _pk_domain_load_key_unlocked(CURRENT_DID, vkey2, PK_SLOT_ANY, 0) ){
        ERROR("failed to load vkey2");
        // errno is set by _pk_domain_load_key
        return -1;
    }
    return 0;
}
//------------------------------------------------------------------------------

/**
 * @brief This function handles ecalls and returns.
 * 
 * @param type
 *        @c TYPE_ECALL: Stores return information such as the @p reentry
 *            point in an @c _expected_return frame on the caller's stack
 *            The caller DID is pushed on the target's stack.
 *        @c TYPE_RET: Retrieves the original caller DID from current user
 *            stack, and recover the @c _expected_return frame from the
 *            original caller stack
 * @return
 *        Returns the @p type again
 */
uint64_t PK_CODE _pk_exception_handler_unlocked(uint64_t data, uint64_t id, uint64_t type, uint64_t * current_stack, void * reentry){
    DEBUG_MPK("_pk_exception_handler_c(id=%zu, type=%zu=%s, reentry=%p)",
        id, type, type_str(type), reentry);
    assert_ifdebug(pk_data.initialized);

    #if defined(TIMING) && defined(DEBUG)
    pk_data.stat_num_exceptions = pk_data.stat_num_exceptions + 1;
    #endif

    //Note: the reentry argument is only valid for type == TYPE_CALL

    int    current_did = CURRENT_DID;
    DEBUG_MPK("\tcurrent_did=0x%x", current_did);

    if(type == TYPE_CALL){
        // Resolve ecall ID
        if(unlikely(id >= NUM_REGISTERED_ECALLS)){
            ERROR_FAIL("ecall %zu not registered (out of range)", id);
        }
        void * entry      = pk_registered_ecalls[id].entry;
        int    target_did = pk_registered_ecalls[id].did;
        DEBUG_MPK("\ttarget_did=0x%x", target_did);

        // check if id is registered
        if(unlikely(entry == 0)){
            ERROR_FAIL("ecall %zu not registered!", id);
        }
        // Since entry exists, also target_did is valid

        // check arguments
        assert_ifdebug(reentry              != 0);
        assert_ifdebug(current_stack        != 0);

        // check if call transition allowed
        if(unlikely(!_transition_allowed_nodidcheck(target_did))){
            ERROR_FAIL("call transition from %d to %d not allowed", current_did, target_did);
        }

        //get thread-domain data
        _pk_thread_domain * target_thread_domain  = _get_thread_domain_data_nodidcheck(target_did);

        // Load target stack pointer
        uint64_t * target_stack = 0;
        if(unlikely(target_thread_domain->expected_return)){
            // this is a nested call
            // stack is exactly where the last excepted_return struct lies
            target_stack = (uint64_t *) target_thread_domain->expected_return;
        }else{
            // not a nested call
            target_stack = (uint64_t *) GET_STACK_TOP(target_thread_domain);
        }
#ifdef __x86_64__
        assert_ifdebug(((uintptr_t)target_stack % 16) == 0); // target_stack must be aligned
#endif
        assert_ifdebug(target_stack != 0);

        // Check if there's enough space on target stack for pushing _return_did
        if(unlikely(!_user_stack_push_allowed(target_thread_domain, (uintptr_t)target_stack, sizeof(_return_did)))) {
            ERROR_FAIL("invalid target stack pointer, or not enough space");
        }

        _pk_thread_domain * current_thread_domain = &(pk_trusted_tls.thread_dom_data[current_did]);
        // Check if there's enough space on current stack
        // for pushing expected_return struct
        if(unlikely(!_user_stack_push_allowed(current_thread_domain, (uintptr_t)current_stack, sizeof(_expected_return)))) {
            ERROR_FAIL("invalid current stack pointer or not enough space");
        }

        // At this point, all the checks are passed. we're allowed to make the ecall

        // Push expected_return struct onto current stack
        _expected_return* expected_return = (_expected_return*)current_stack - 1;
#ifdef __x86_64__
        assert_ifdebug(((uintptr_t)expected_return % 16) == 0); // expected_return must be aligned
#endif
        expected_return->did      = target_did;
        expected_return->reentry  = reentry;
        expected_return->previous = current_thread_domain->expected_return;
        #ifdef ADDITIONAL_DEBUG_CHECKS
            expected_return->sp     = current_stack;
            expected_return->cookie = 0xDEADC0FEULL;
        #endif
        current_thread_domain->expected_return = expected_return;


        // Push caller DID onto target stack.
        // This is needed so that we know to which domain we want to return to.
        _return_did * ret_did = (_return_did*)target_stack - 1; //allocate _return_did struct on target stack
        target_stack = (uint64_t*)ret_did;
        ret_did->did = current_did;
        #ifdef ADDITIONAL_DEBUG_CHECKS
            ret_did->cookie1 = 0xDEADC0DEULL;
            ret_did->cookie2 = 0xDEADC0CEULL;
        #endif

        // Load new config of target domain
        pkru_config_t config = pk_data.domains[target_did].default_config;
        #ifdef ADDITIONAL_DEBUG_CHECKS
            assert_warn(current_did != target_did);
        #endif
        // Switch stacks and protection keys and prepare entry address
        _pk_domain_switch_arch(type, target_did, config, entry, target_stack);
        // update current_pkru in TLS to reflect pkru modifications
        pk_trusted_tls.current_pkru = _read_pkru();

    //--------------------------------------------------------------------------
    }else if(type == TYPE_RET){

        //get thread-domain data
        _pk_thread_domain * current_thread_domain = &(pk_trusted_tls.thread_dom_data[current_did]);


        // Discard 1 element from the stack, which is the return address that we no longer need
        // Check if current stack is valid for popping return address
        if(unlikely(!_user_stack_pop_allowed(current_thread_domain, (uintptr_t)current_stack, sizeof(*current_stack)))) {
            ERROR_FAIL("invalid current stack pointer");
        }
        #ifdef ADDITIONAL_DEBUG_CHECKS
            //The discarded element should be the original return value from the ecall.
            //It should be very close to the original entry point of the ecall
            assert((uintptr_t)*current_stack > (uintptr_t)pk_registered_ecalls[id].entry && (uintptr_t)*current_stack < (uintptr_t)pk_registered_ecalls[id].entry + 100);
        #endif
        current_stack += 1;

        // Check if current stack is valid for popping _return_did
        if(unlikely(!_user_stack_pop_allowed(current_thread_domain, (uintptr_t)current_stack, sizeof(_return_did)))) {
            ERROR_FAIL("invalid stack pointer");
        }

        // When returning, the stack pointer should now point to the _return_did struct
        _return_did * ret_did = (_return_did*)current_stack;
        int target_did = ret_did->did;
        #ifdef ADDITIONAL_DEBUG_CHECKS
            assert(ret_did->cookie1 == 0xDEADC0DEULL);
            assert(ret_did->cookie2 == 0xDEADC0CEULL);
        #endif
        DEBUG_MPK("\ttarget_did=0x%x", target_did);

        // check if target_did is valid
        if(unlikely(!_domain_exists(target_did))){
            ERROR_FAIL("Target domain does not exist");
        }

        // get thread-domain data for target did
        _pk_thread_domain * target_thread_domain = &(pk_trusted_tls.thread_dom_data[target_did]);

        // check if target stack is valid
        _expected_return* expected_return = target_thread_domain->expected_return;
        if(unlikely(expected_return == 0)){
            ERROR_FAIL("Target domain is not expecting a return");
        }

        // Check if target stack is valid for popping _expected_return struct
        // This is very unlikely to fail, because this is already checked when making the ECALL
        if(unlikely(!_user_stack_pop_allowed(target_thread_domain, (uintptr_t)expected_return, sizeof(_expected_return)))) {
            ERROR_FAIL("invalid target stack pointer");
        }

        // check if return transition allowed
        if(unlikely(expected_return->did != current_did)) {
            ERROR_FAIL("Target domain (%d) is not expecting a return from the current domain (%d) ", target_did, current_did);
        }

        // Retrieve original reentry point and stack pointer
        void *     reentry         = expected_return->reentry;          // Warning: shadowing function argument with same name
        uint64_t * target_stack    = (uint64_t *)(expected_return + 1); // sp = where expected_return was, "minus" the struct itself
        assert_ifdebug(target_stack != 0);
        #ifdef ADDITIONAL_DEBUG_CHECKS
            assert(expected_return->cookie == 0xDEADC0FEULL);
            assert(expected_return->sp     == expected_return + 1);
            assert(expected_return->sp     == target_stack);
        #endif

        // Restore previous expected_return frame
        target_thread_domain->expected_return = expected_return->previous;

        #ifdef ADDITIONAL_DEBUG_CHECKS
            assert_warn(current_did != target_did);
        #endif

        // Load new config of target domain
        pkru_config_t config = pk_data.domains[target_did].default_config;
        // Switch stacks and protection keys and prepare reentry address
        _pk_domain_switch_arch(type, target_did, config, reentry, target_stack);
        // update current_pkru in TLS to reflect pkru modifications
        pk_trusted_tls.current_pkru = _read_pkru();

    }else if(type == TYPE_API){
        ERROR_FAIL("TYPE_API should have been handled in assembly already");
    }else{
        ERROR_FAIL("Unhandled case in pk_exception_handler_c");
    }

    return type;
}
//------------------------------------------------------------------------------
void PK_CODE_INLINE _init_debug(){

    #ifdef DEBUG
        /*Otherwise some output might not be displayed*/
        setbuf(stdout, NULL);
        setbuf(stderr, NULL);
    #endif

    assert(WORDSIZE == sizeof(uint64_t));

    #ifndef SHARED
    #ifdef ADDITIONAL_DEBUG_CHECKS
        #define IN_RANGE(start,x,end) ((start) <= (x) && (x) < (end))
        #define IN_PK_CODE(x) IN_RANGE((uint64_t)__start_pk_code, (uint64_t)(x), (uint64_t)__stop_pk_code)

        /*
        _pk_.* some of these have respective API wrapper functions without underscore
        _[^p][^k]_.* are protected internal functions
        pk_.* are protected and don't have a wrapper
            ... except for a few which are unprotected and have no wrapper
                because we don't use them internally and they don't have to
                access priviledged pk data
        */
        assert(IN_PK_CODE(_pk_init                    ));
        assert(IN_PK_CODE(_pk_domain_create_unlocked  ));
        //assert(IN_PK_CODE(_pk_exception_handler       ));
        assert(IN_PK_CODE(_pk_exception_handler_arch_c));
        assert(IN_PK_CODE(_pk_exception_handler_unlocked  ));
        assert(IN_PK_CODE(_pk_setup_exception_handler_arch));
        assert(IN_PK_CODE(_pk_setup_exception_stack_arch));
        assert(IN_PK_CODE(_pk_setup_domain_arch));
        assert(IN_PK_CODE(_pk_init_arch               ));
        assert(IN_PK_CODE(_pk_setup_thread_exception_stack));
        assert(IN_PK_CODE(_pk_init_thread             ));

        assert(IN_PK_CODE(_pk_domain_switch_arch      ));
        assert(IN_PK_CODE(_get_default_vkey           ));
        assert(IN_PK_CODE(_transition_allowed_nodidcheck));
        assert(IN_PK_CODE(_get_default_stack_size     ));


        // API functions internal
        assert(IN_PK_CODE(_pk_init                    ));
        assert(IN_PK_CODE(_pk_domain_create           ));
        assert(IN_PK_CODE(_pk_domain_free             ));
        assert(IN_PK_CODE(_pk_pkey_alloc              ));
        assert(IN_PK_CODE(_pk_pkey_free               ));
        assert(IN_PK_CODE(_pk_domain_assign_pkey      ));
        assert(IN_PK_CODE(_pk_pkey_mprotect           ));
        assert(IN_PK_CODE(_pk_pkey_mprotect2          ));
        assert(IN_PK_CODE(_pk_mmap                    ));
        assert(IN_PK_CODE(_pk_munmap                  ));
        assert(IN_PK_CODE(_pk_domain_register_ecall   ));
        assert(IN_PK_CODE(_pk_domain_register_ecall2  ));
        assert(IN_PK_CODE(_pk_domain_allow_caller     ));
        assert(IN_PK_CODE(_pk_domain_allow_caller2    ));
        assert(IN_PK_CODE(_pk_current_did             ));
        assert(IN_PK_CODE(_pk_print_debug_info        ));
        assert(IN_PK_CODE(_pk_pthread_create          ));
        assert(IN_PK_CODE(_pk_pthread_exit            ));

        // API functions external
        assert(! IN_PK_CODE(pk_print_current_reg       ));

        assert(! IN_PK_CODE(pk_init                    ));
        assert(! IN_PK_CODE(pk_domain_create           ));
        assert(! IN_PK_CODE(pk_domain_free             ));
        assert(! IN_PK_CODE(pk_pkey_alloc              ));
        assert(! IN_PK_CODE(pk_pkey_free               ));
        assert(! IN_PK_CODE(pk_domain_assign_pkey      ));
        assert(! IN_PK_CODE(pk_pkey_mprotect           ));
        assert(! IN_PK_CODE(pk_pkey_mprotect2          ));
        assert(! IN_PK_CODE(pk_mmap                    ));
        assert(! IN_PK_CODE(pk_munmap                  ));
        assert(! IN_PK_CODE(pk_domain_register_ecall   ));
        assert(! IN_PK_CODE(pk_domain_register_ecall2  ));
        assert(! IN_PK_CODE(pk_domain_allow_caller     ));
        assert(! IN_PK_CODE(pk_domain_allow_caller2    ));
        assert(! IN_PK_CODE(pk_current_did             ));
        assert(! IN_PK_CODE(pk_print_debug_info        ));
        assert(! IN_PK_CODE(pk_pthread_create          ));
        assert(! IN_PK_CODE(pk_pthread_exit            ));

    #endif
    #endif
    print_maps();

}
//------------------------------------------------------------------------------

void* PK_CODE _pk_setup_thread_exception_stack(){
    DEBUG_MPK("_pk_setup_thread_exception_stack");

    // protect exception handler stack for this thread
    DEBUG_MPK("Allocating exception stack");
    void * exception_stack = _allocate_stack(EXCEPTION_STACK_WORDS * WORDSIZE);
    if (!exception_stack) {
      DEBUG_MPK("_pk_setup_thread_exception_stack failed to allocate stack");
      return NULL;
    }
    DEBUG_MPK("Protecting exception stack");
    int ret = _pk_pkey_mprotect_unlocked_nodid_check(DID_FOR_EXCEPTION_HANDLER, exception_stack, EXCEPTION_STACK_WORDS * WORDSIZE, PROT_WRITE | PROT_READ, PK_DEFAULT_KEY);
    assert(ret == 0);
    return exception_stack;
}
//------------------------------------------------------------------------------

// This function init-protects the currently running thread (TLS, etc)
// It must not use CURRENT_DID but only @p did
int PK_CODE _pk_init_thread(int did, void* exception_stack){
    DEBUG_MPK("_pk_init_thread");
    #if !defined(RELEASE) && __riscv
    pk_print_current_reg();
    PRINT_UREGS();
    #endif

    pk_trusted_tls.current_did = DID_INVALID;

    // search for free tid slot
    size_t tid = 0;
    for (size_t tid = 0; tid < NUM_THREADS; tid++) {
      if (!pk_data.threads[tid]) {
        break;
      }
    }
    if (NUM_THREADS == tid) {
        ERROR("_pk_init_thread: No more threads available");
        errno = ENOMEM;
        return -1;
    }

    // protect user stack
    // Since the new TLS  is not yet protected, we need a local copy of the thread-domain-data
    _pk_thread_domain data = {0};

    // we need to mprotect user stack before trusted TLS, since trusted TLS
    // can reside within the stack range, but has more strict permission
    int ret = _prepare_user_stack_pthread(did, &data);
    if(ret != 0){
        ERROR("_pk_init_thread: _prepare_user_stack_pthread failed");
        errno = EACCES;
        return -1;
    }

    #define PAGEMASK (PAGESIZE-1)
    #define ROUNDUP(x) (((uintptr_t)(x) + PAGESIZE-1) & ~(uintptr_t)PAGEMASK)
    #define ROUNDDOWN(x) (((uintptr_t)(x)) & ~(uintptr_t)PAGEMASK)
    #define TCB_SIZE (0x700) // TODO: determine

    DEBUG_MPK("tls:   %p", (void*)GET_TLS_POINTER);
    DEBUG_MPK("ttls:  %p", &pk_trusted_tls);
    DEBUG_MPK("TLS offset = 0x%lx (%ld)", _pk_ttls_offset, _pk_ttls_offset);

    assert(_pk_ttls_offset == (uint64_t)&pk_trusted_tls.backup_user_stack - GET_TLS_POINTER);

#ifdef FAKE_TLS_SWAP
#ifndef SHARED
    // Determine size of static TLS and TCB
#ifdef __x86_64
    uintptr_t static_tls_size = ROUNDUP(__tls_static_end) - ROUNDDOWN(__tls_static_start);  // multiples of a page
    uintptr_t static_tls_start = ROUNDDOWN(GET_TLS_POINTER - static_tls_size);
    uintptr_t static_tls_end = ROUNDUP(GET_TLS_POINTER + TCB_SIZE); // TLS pointer is inbetween TLS and TCB
#else // RISC-V
    uintptr_t static_tls_size = ROUNDUP(__tls_static_end) - ROUNDDOWN(__tls_static_start);  // multiples of a page
    uintptr_t static_tls_start = ROUNDDOWN(GET_TLS_POINTER);
    uintptr_t static_tls_end = ROUNDUP(GET_TLS_POINTER + static_tls_size + TCB_SIZE);
#endif /* __x86_64 / RISC-V */
    DEBUG_MPK("static tls size:  0x%lx\n", static_tls_size);
    DEBUG_MPK("static tls start: 0x%lx", static_tls_start);
    DEBUG_MPK("       tls end:   0x%lx", static_tls_end);
    assert((uintptr_t)&pk_trusted_tls >= static_tls_start && (uintptr_t)&pk_trusted_tls <= (uintptr_t)static_tls_end);

    // Unprotect TLS such that one thread can access it in all domains
    //Note: PKEY_MPROTECT doesn't track memory. (nobody can claim it)
    ret = PKEY_MPROTECT((void*)static_tls_start, static_tls_end - static_tls_start, PROT_WRITE | PROT_READ, KEY_FOR_UNPROTECTED);
    if(ret != 0){
        ERROR_FAIL("_pk_init_thread: pkey_mprotect failed");
    }

#else // SHARED
    // If shared, TLS is not located in user stack which we just protected
    // So there is no need to unprotect it
#endif // !SHARED
#else // FAKE_TLS_SWAP
    #error "Implement me"
    // TODO: implement TLS swap (fs for x86, tp for RISC-V)
    // TODO: protect user TLS
#endif // FAKE_TLS_SWAP

    // protect trusted TLS
    uintptr_t ttls_start = (uintptr_t)&pk_trusted_tls.backup_user_stack;
    uintptr_t ttls_end  = (uintptr_t)(&pk_trusted_tls+1);
#ifdef TLS_MISALIGNMENT_BUG
    DEBUG_MPK("Misaligned TTLS from %p to %p", (void*)ttls_start, (void*)ttls_end);
    ttls_start = ROUNDUP(ttls_start);
    ttls_end = ROUNDDOWN(ttls_end-2);  // We need to misalign it from a page boundary, otherwise compiler will optimize ROUNDDOWN away
#endif
    DEBUG_MPK("protecting TTLS from %p to %p", (void*)ttls_start, (void*)ttls_end);
    ret = _pk_pkey_mprotect_unlocked_nodid_check(DID_FOR_EXCEPTION_HANDLER, (void*)ttls_start, ttls_end - ttls_start, PROT_WRITE | PROT_READ, KEY_FOR_EXCEPTION_HANDLER);
    assert(ret == 0);

    // initialize trusted TLS
    pk_data.threads[tid] = &pk_trusted_tls;
    pk_trusted_tls.tid = tid;
    pk_trusted_tls.thread_dom_data[did] = data;
    pk_trusted_tls.current_did = did; // Now we can use CURRENT_DID
    pk_trusted_tls.init = true;
    assert(did == CURRENT_DID);

    // architecture-specific per-thread code
    _pk_setup_exception_stack_arch(exception_stack);
    _pk_setup_exception_handler_arch();

    return 0;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_create_unlocked(unsigned int flags){
    DEBUG_MPK("_pk_domain_create_unlocked");
    int ret;

    if (flags & ~(PK_KEY_SHARED | PK_KEY_INHERIT | PK_KEY_COPY | PK_KEY_OWNER)){
        ERROR("_pk_domain_create_unlocked: Invalid flags");
        errno = EINVAL;
        return -1;
    }

    if (flags & (PK_KEY_COPY | PK_KEY_OWNER) &&
        !(flags & PK_KEY_INHERIT)){
        ERROR("_pk_domain_create_unlocked: PK_KEY_COPY | PK_KEY_OWNER are only allowed in combination with PK_KEY_INHERIT");
        errno = EINVAL;
        return -1;
    }

    // allocate domain (did)
    int did = -1;
    for (int d = 0; d < NUM_DOMAINS; d++) {
        if(!pk_data.domains[d].used) {
            did = d;
            break;
        }
    }
    if (PK_DOMAIN_CURRENT == did) {
        ERROR("_pk_domain_create_unlocked could not allocate domain");
        errno = ENOMEM;
        return -1;
    }

    // claim domain
    _pk_domain * new_domain = &(pk_data.domains[did]);
    new_domain->used = true;

    // remember who created the domain
    if (pk_trusted_tls.init) {
        new_domain->parent_did = CURRENT_DID;
    } else {
        new_domain->parent_did = DID_INVALID;
    }

    // Allocate domain's default key
    vkey_t vkey = _pk_pkey_alloc_unlocked(did, flags & PK_KEY_SHARED, 0);
    if(vkey < 0){
        new_domain->used = false;
        ERROR("_pk_create_domain_simple could not allocate vkey");
        // errno is set by _pk_pkey_alloc_unlocked
        goto cleanup1;
    }
    assert_ifdebug(vkey == KEY_FOR_EXCEPTION_HANDLER || did != DID_FOR_EXCEPTION_HANDLER);

    // Do arch-specific domain setup
    pkey_t pkey = _vkey_to_pkey(did, vkey);
    _pk_setup_domain_arch(did, pkey);

#ifdef SHARED
    // Give read-only access to certain pk data needed for, e.g.:
    // dl_iterate_phdr (c++ exception handling, libc destructors, etc.
    // This needs to access .plt and likewise
    if (rokey_for_exception_handler != VKEY_INVALID) {
        ret = _pk_domain_assign_pkey_unlocked(DID_FOR_EXCEPTION_HANDLER, did, rokey_for_exception_handler, PK_KEY_COPY, PKEY_DISABLE_WRITE);
        if (0 != ret) {
            ERROR("_pk_create_domain_simple could not assign read-only key");
            // errno is set by _pk_domain_assign_pkey_unlocked
            goto cleanup2;
        }
    }
#endif

    // Inherit default key if requested
    if (flags & PK_KEY_INHERIT) {
        ret = _pk_domain_assign_pkey_unlocked(did, CURRENT_DID, vkey, flags & (PK_KEY_COPY | PK_KEY_OWNER), 0);
        if (0 != ret) {
            // errno is set by _pk_domain_assign_pkey_unlocked
            goto cleanup2;
        }
    }

    //Note that creating (and protecting) the stack for each new domain
    //happens per thread (and only on demand).

    return did;

cleanup2:
    assert(pkey >= 0 && pkey < PK_NUM_KEYS);
    if (0 != PKEY_FREE(pkey)) {
        WARNING("Unable to free protection key! Ignoring.");
    }
cleanup1:
    memset(new_domain, 0, sizeof(*new_domain));
    return -1;
}
//------------------------------------------------------------------------------

bool PK_CODE _untrack_memory(void *addr, size_t len) {
    //DEBUG_MPK("_untrack_memory(%p, %zu)", addr, len);

    assert(((uintptr_t)addr % PAGESIZE) == 0);
    assert((len % PAGESIZE) == 0);

    mprotect_t splittail = { .used = false };
    size_t split_rid = SIZE_MAX;

    // truncate/split potential overlapping ranges
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (_memory_overlaps(addr, len, pk_data.ranges[rid].addr, pk_data.ranges[rid].len)) {
            //DEBUG_MPK("memory overlaps with %p (0x%lx)", pk_data.ranges[rid].addr, pk_data.ranges[rid].len);
            // Distinguish cases of old range (O) and new range (N)
            if (_address_overlaps(pk_data.ranges[rid].addr, addr, len)) {
                // old range-start is within delete range
                if (_address_overlaps((char*)pk_data.ranges[rid].addr+pk_data.ranges[rid].len-1, addr, len)) {
                    //DEBUG_MPK("_untrack_memory: case 1: overlapping range fully covered. Deleting it");
                    // old range-end is within delete range
                    // DDDDDDDDDD
                    //     OOOO
                    // discard old range completely
                    pk_data.ranges[rid].used = 0;
                } else {
                    // DEBUG_MPK("_untrack_memory: case 2: overlapping range right-overlap. Truncating it");
                    // DEBUG_MPK("Original: %p (0x%zu)", pk_data.ranges[rid].addr, pk_data.ranges[rid].len);
                    // old range-end is outside delete range
                    // DDDDDDDDDD
                    //     OOOOOOOOO
                    // truncate old range
                    //           OOO
                    char* end = (char*)pk_data.ranges[rid].addr + pk_data.ranges[rid].len;
                    pk_data.ranges[rid].addr = (char*)addr + len;
                    assert_ifdebug((char*)end >= (char*)pk_data.ranges[rid].addr);
                    pk_data.ranges[rid].len = (size_t)((char*)end - (char*)pk_data.ranges[rid].addr);
                    assert_ifdebug((pk_data.ranges[rid].len % PAGESIZE) == 0);
                    assert_ifdebug(pk_data.ranges[rid].len > 0);
                    // DEBUG_MPK("Truncated: %p (0x%zu)", pk_data.ranges[rid].addr, pk_data.ranges[rid].len);
                }
            } else {
                // old range-start is outside delete range
                if (_address_overlaps((char*)pk_data.ranges[rid].addr+pk_data.ranges[rid].len-1, addr, len)) {
                    // DEBUG_MPK("_untrack_memory: case 3: overlapping range left-overlap. Truncating it");
                    // DEBUG_MPK("Original: %p (0x%zu)", pk_data.ranges[rid].addr, pk_data.ranges[rid].len);
                    // old range-end is within delete range
                    //     DDDDDDDD
                    // OOOOOOOO
                    // truncate old range
                    // OOOO
                    assert_ifdebug((char*)addr >= (char*)pk_data.ranges[rid].addr);
                    pk_data.ranges[rid].len = (size_t)((char*)addr - (char*)pk_data.ranges[rid].addr);
                    assert_ifdebug((pk_data.ranges[rid].len % PAGESIZE) == 0);
                    assert_ifdebug(pk_data.ranges[rid].len > 0);
                    // DEBUG_MPK("Truncated: %p (0x%zu)", pk_data.ranges[rid].addr, pk_data.ranges[rid].len);
                } else {
                    // DEBUG_MPK("_untrack_memory: case 4: overlapping range covers new. Splitting it");
                    // old range-end is outside delete range
                    //     DDDDDDDD
                    // OOOOOOOOOOOOOOO
                    // we have to split original range into two
                    // OOOO        OOO
                    // for this we need at least 1 free range

                    // search for a free range
                    for (split_rid = 0; split_rid < NUM_MPROTECT_RANGES; split_rid++) {
                        if (!pk_data.ranges[split_rid].used) {
                            break;
                        }
                    }
                    if (split_rid >= NUM_MPROTECT_RANGES) {
                        ERROR("_untrack_memory has too few ranges available for a split");
                        return false;
                    }
                    // Now do the split
                    // First, truncate beginning
                    // OOOO
                    assert_ifdebug((char*)addr >= (char*)pk_data.ranges[rid].addr);
                    char* tailend = (char*)pk_data.ranges[rid].addr + pk_data.ranges[rid].len;
                    pk_data.ranges[rid].len = (size_t)((char*)addr - (char*)pk_data.ranges[rid].addr);
                    assert_ifdebug((pk_data.ranges[rid].len % PAGESIZE) == 0);
                    assert_ifdebug(pk_data.ranges[rid].len > 0);
                    // Second, store truncated old tail in splittail for later insertion into split_rid
                    // OOOO        OOO
                    splittail.addr = (char*)addr + len;
                    assert_ifdebug((char*)tailend >= (char*)splittail.addr);
                    splittail.len  = (size_t)((char*)tailend - (char*)splittail.addr);
                    assert_ifdebug((splittail.len % PAGESIZE) == 0);
                    assert_ifdebug(((uintptr_t)splittail.addr % PAGESIZE) == 0);
                    splittail.prot = pk_data.ranges[rid].prot;
                    splittail.vkey = pk_data.ranges[rid].vkey;
                    splittail.pkey = pk_data.ranges[rid].pkey;
                    splittail.used = true;
                }
            }
        }
    }

    if (splittail.used) {
        // we insert split tail at the end
        assert(split_rid != SIZE_MAX);
        assert(!pk_data.ranges[split_rid].used);
        pk_data.ranges[split_rid] = splittail;
    }
    //_pk_print_debug_info();
#ifdef ADDITIONAL_DEBUG_CHECKS
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (pk_data.ranges[rid].used) {
            assert(!_memory_overlaps(pk_data.ranges[rid].addr, pk_data.ranges[rid].len, addr, len));
        }
    }
#endif // ADDITIONAL_DEBUG_CHECKS

    return true;
}
//------------------------------------------------------------------------------

bool PK_CODE _track_memory(void *addr, size_t len, int prot, vkey_t vkey, pkey_t pkey) {
    //DEBUG_MPK("_track_memory(%p, %zu, %d, %d, %d)", addr, len, prot, vkey, pkey);

    assert(((uintptr_t)addr % PAGESIZE) == 0);
    assert((len % PAGESIZE) == 0);

    // count free ranges
    int free_rids_required = 2;
    int free_rids = 0;
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (!pk_data.ranges[rid].used) {
            free_rids++;
            if(free_rids >= free_rids_required){
                break;
            }
        }
    }

    if (free_rids < free_rids_required) {
        ERROR("_track_memory has too few ranges available for a potential split");
        return false;
    }

    // truncate existing memory that overlaps with new range
    if (!_untrack_memory(addr, len)) {
      ERROR("_track_memory: Unable to truncate existing memory");
      return false;
    }

#ifdef ADDITIONAL_DEBUG_CHECKS
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (pk_data.ranges[rid].used) {
            assert(!_memory_overlaps(pk_data.ranges[rid].addr, pk_data.ranges[rid].len, addr, len));
        }
    }
#endif // ADDITIONAL_DEBUG_CHECKS

    // DEBUG_MPK("_track_memory: inserting new range");
    // insert new range
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (!pk_data.ranges[rid].used) {
            pk_data.ranges[rid].addr = addr;
            pk_data.ranges[rid].len  = len;
            pk_data.ranges[rid].prot = prot;
            pk_data.ranges[rid].vkey  = vkey;
            pk_data.ranges[rid].pkey = pkey;
            pk_data.ranges[rid].used = true;
            return true;
        }
    }
    ERROR("_track_memory has too few ranges available."
          "We're potentially in an inconsistent state.");
    return false;
}
//------------------------------------------------------------------------------

/**
 * This function must not use CURRENT_DID, as it might not be available yet.
 */
int PK_CODE _pk_pkey_mprotect_unlocked_nodid_check(int did, void *addr, size_t len, int prot, vkey_t vkey){
    DEBUG_MPK("_pk_pkey_mprotect_unchecked(%d, addr=%p, len=0x%zx, %d, %d)", did, addr, len, prot, vkey);

    if ((uintptr_t)addr % PAGESIZE || len % PAGESIZE) {
      ERROR("_pk_pkey_mprotect_unlocked: memory range is not page-aligned");
      errno = EINVAL;
      return -1;
    }

    if (!_domain_exists(did)){
        ERROR("_pk_pkey_mprotect_unlocked domain does not exist");
        errno = EINVAL;
        return -1;
    }

    if(PK_DEFAULT_KEY == vkey){
        vkey = _get_default_vkey(did);
        if (PK_DEFAULT_KEY == vkey) {
          ERROR("_pk_pkey_mprotect_unlocked domain has no default vkey");
          errno = EACCES;
          return -1;
        }
    }

    if (!_domain_owns_vkey_nodidcheck(did, vkey)){
        ERROR("_pk_pkey_mprotect_unlocked: domain does not own vkey");
        errno = EACCES;
        return -1;
    }

    pkey_t pkey = _vkey_to_pkey(did, vkey);

    if (!_domain_owns_memory(did, addr, len)) {
        ERROR("_pk_pkey_mprotect_unlocked: domain does not own memory range");
        errno = EACCES;
        return -1;
    }

    int ret = PKEY_MPROTECT(addr, len, prot, pkey);
    if(ret != 0){
        ERROR("_pk_pkey_mprotect_unlocked: mprotect failed");
        perror("pkey_mprotect");
        // errno is set by pkey_mprotect
        return -1;
    }

    if (!_track_memory(addr, len, prot, vkey, pkey)) {
        ERROR("_pk_pkey_mprotect_unlocked cannot track more mprotect calls");
        errno = ENOMEM;
        return -1;
    }

    return 0;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_pkey_mprotect_unlocked(int did, void *addr, size_t len, int prot, vkey_t vkey){
    DEBUG_MPK("_pk_pkey_mprotect_unlocked(%d, addr=%p, len=0x%zx, %d, %d)", did, addr, len, prot, vkey);

    if(!_domain_is_current_or_child(did)){
        ERROR("_pk_pkey_mprotect_unlocked only allowed on current DID or child");
        ERROR("CURRENT_DID = %d", CURRENT_DID);
        errno = EACCES;
        return -1;
    }

    return _pk_pkey_mprotect_unlocked_nodid_check(did, addr, len, prot, vkey);
}
//------------------------------------------------------------------------------

int PK_CODE _pk_pkey_munprotect_unlocked(int did, void *addr, size_t len, int prot) {
    DEBUG_MPK("_pk_pkey_munprotect_unlocked(%d, addr=%p, len=0x%zx, %d)", did, addr, len, prot);

    if ((uintptr_t)addr % PAGESIZE || len % PAGESIZE) {
      ERROR("_pk_pkey_munprotect_unlocked: memory range is not page-aligned");
      errno = EINVAL;
      return -1;
    }

    if (!_domain_owns_memory(did, addr, len)) {
        ERROR("_pk_pkey_munprotect_unlocked: domain does not own memory range");
        errno = EACCES;
        return -1;
    }

    int ret = PKEY_MPROTECT(addr, len, prot, 0);
    if(ret != 0){
        ERROR("_pk_pkey_munprotect_unlocked: mprotect failed");
        perror("pkey_mprotect");
        // errno is set by pkey_mprotect
        return -1;
    }

    if (!_untrack_memory(addr, len)) {
        ERROR("_pk_pkey_munprotect_unlocked cannot untrack");
        errno = ENOMEM;
        return -1;
    }

    return 0;
}
//------------------------------------------------------------------------------

vkey_t PK_CODE _pk_pkey_alloc_unlocked(int did, unsigned int flags, unsigned int access_rights){
    DEBUG_MPK("_pk_pkey_alloc(%d, %d)", flags, access_rights);

    if (flags & ~(PK_KEY_SHARED) || (access_rights & ~(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE))) {
        ERROR("_pk_pkey_alloc invalid flags or access rights");
        errno = EINVAL;
        return -1;
    }

    if (!_domain_exists(did)) {
        ERROR("_pk_pkey_alloc domain does not exist");
        errno = EINVAL;
        return -1;
    }

    // find free key slot
    size_t key_id;
    for (key_id = 0; key_id < NUM_KEYS_PER_DOMAIN; key_id++) {
        if (!pk_data.domains[did].keys[key_id].used) {
            break;
        }
    }
    if (key_id >= NUM_KEYS_PER_DOMAIN) {
        ERROR("_pk_pkey_alloc could not allocate key slot for domain");
        errno = ENOMEM;
        return -1;
    }

    // check allocation of virtual protection key
    if (pk_vkey_cnt >= VKEY_MAX) {
        ERROR("_pk_pkey_alloc could not allocate vkey");
        errno = ENOSPC;
        return -1;
    }

    // allocate new protection key
    int pka = PKEY_ALLOC(flags & ~PK_KEY_SHARED, access_rights);
    pkey_t pkey;
    if (pka < 0) {
        // run out of regular protection keys
        if (flags & PK_KEY_SHARED) {
          // Find shared key with lowest shared-counter
          int cnt_min = INT_MAX;
          pkey_t pkey_min = 0;
          for (size_t i = 0; i < PK_NUM_KEYS; i++) {
            if (pk_shared_pkeys[i] > 0 && pk_shared_pkeys[i] < cnt_min) {
              cnt_min = pk_shared_pkeys[i];
              pkey_min = i;
            }
          }
          if (cnt_min >= INT_MAX) {
            ERROR("_pk_pkey_alloc could not allocate shared key");
            errno = ENOSPC;
            return -1;
          }
          if (pk_shared_pkeys[pkey_min] >= INT_MAX) {
            ERROR("_pk_pkey_alloc shared pkey cannot be re-shared");
            errno = ENOSPC;
            return -1;
          }
          pkey = pkey_min;
          pk_shared_pkeys[pkey_min]++;
          DEBUG_MPK("_pk_pkey_alloc reusing shared key %d with counter %d\n", pkey_min, cnt_min);
        } else {
          ERROR("_pk_pkey_alloc could not allocate key");
          // errno is set by pkey_alloc
          return -1;
        }
    } else {
      pkey = pka;
      if (flags & PK_KEY_SHARED) {
        // mark key as shareable by setting its shared-counter to 1
        assert(pkey >= 0 && pkey < PK_NUM_KEYS);
        assert(pk_shared_pkeys[pkey] == 0);
        pk_shared_pkeys[pkey] = 1;
      }
    }

    // allocate virtual protection key
    vkey_t vkey = pk_vkey_cnt++;

    #ifndef RELEASE
    if (!(flags & PK_KEY_SHARED)) {
        for (size_t i = 0; i < NUM_DOMAINS; i++) {
            if(! pk_data.domains[i].used) {
                continue;
            }
            for (size_t j = 0; j < NUM_KEYS_PER_DOMAIN; j++) {
                pk_key_t k = pk_data.domains[i].keys[j];
        
                //key already used by another domain.
                //double allocation
                assert(!(k.used && k.vkey == vkey));
                if (!(flags & PK_KEY_SHARED)) {
                  assert(!(k.used && k.pkey == pkey));
                }
            }
        }
    }
    #endif


    DEBUG_MPK("_pk_pkey_alloc: allocated pkey=%d,vkey=%d\n", pkey, vkey);
    // store key in domain's key slot
    pk_data.domains[did].keys[key_id].vkey  = vkey;
    pk_data.domains[did].keys[key_id].pkey  = pkey;
    pk_data.domains[did].keys[key_id].owner = true;
    pk_data.domains[did].keys[key_id].used  = true;
    pk_data.domains[did].keys[key_id].perm  = access_rights;

    
    return vkey;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_load_sysfilter_module() {
    int sysfilter_fd = open(SYSFILTER_DEVICE_PATH, O_RDONLY);
    if (sysfilter_fd < 0) {
        ERROR("_pk_load_sysfilter_module: Could not open sysfilter device: %s", SYSFILTER_DEVICE_PATH);
        // errno set by open
        return -1;
    }

    pk_sysfilter = true;

    if (-1 == ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_KILL_ON_VIOLATION, 1)) {
        // errno set by ioctl
        DEBUG_MPK("_pk_load_sysfilter_module: Could not configure kill-on-violation");
        return -1;
    }

    DEBUG_MPK("_pk_load_sysfilter_module: Apply sysfilter to current PID: %d", getpid());
    if (-1 == ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_PID, getpid())) {
        // errno set by ioctl
        DEBUG_MPK("_pk_load_sysfilter_module: Apply sysfilter to PID  %d failed", getpid());
        return -1;
    }

    for (size_t i = 0; block_syscalls[i] != 0; i++) {
        DEBUG_MPK("_pk_load_sysfilter_module: Block syscall number %d", block_syscalls[i]);
        if (-1 == ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_BLOCK, block_syscalls[i])) {
            DEBUG_MPK("_pk_load_sysfilter_module: Apply sysfilter to PID  %d failed", getpid());
            // errno set by ioctl
            return -1;
        }
    }
    close(sysfilter_fd);
    return 0;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_unload_sysfilter_module() {
    int sysfilter_fd = open(SYSFILTER_DEVICE_PATH, O_RDONLY);
    if (sysfilter_fd < 0) {
        ERROR("_pk_unload_sysfilter_module: Could not open sysfilter device: %s", SYSFILTER_DEVICE_PATH);
        // errno set by poen
        return -1;
    }

    for (size_t i = 0; block_syscalls[i] != 0; i++) {
        DEBUG_MPK("_pk_unload_sysfilter_module: Unblock syscall number %d", block_syscalls[i]);
        if (-1 == ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_UNBLOCK, block_syscalls[i])) {
            ERROR("_pk_unload_sysfilter_module: Unable to unblock syscall number %d", block_syscalls[i]);
            // errno set by ioctl
            return -1;
        }
    }

    DEBUG_MPK("_pk_unload_sysfilter_module: Disabling PID filter");
    if (-1 == ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_PID, 0)) {
        ERROR("_pk_unload_sysfilter_module: Disabling PID filter");
        // errno set by ioctl
        return -1;
    }
    close(sysfilter_fd);
    return 0;
}
//------------------------------------------------------------------------------

#ifdef SHARED

/**
 * Copied from RISCV-PK:
 * 
 * The protection flags are in the p_flags section of the program header.
 * But rather annoyingly, they are the reverse of what mmap expects.
 */
int PK_CODE_INLINE get_prot(uint32_t p_flags)
{
  int prot_x = (p_flags & PF_X) ? PROT_EXEC  : PROT_NONE;
  int prot_w = (p_flags & PF_W) ? PROT_WRITE : PROT_NONE;
  int prot_r = (p_flags & PF_R) ? PROT_READ  : PROT_NONE;

  return (prot_x | prot_w | prot_r);
}
//------------------------------------------------------------------------------

typedef struct {
  int did;
  vkey_t vkey;
} domain_t;
//------------------------------------------------------------------------------

int PK_CODE reprotect_phdr(domain_t* domain, struct dl_phdr_info *info, Elf64_Phdr* phdr) {
  uintptr_t start = info->dlpi_addr + phdr->p_vaddr;
  uintptr_t end = start + phdr->p_memsz;
  start &= ~PAGEMASK; // round down
  end = (end + PAGESIZE-1) & ~PAGEMASK; // round up
  // Mprotect with same permissions
  int prot = get_prot(phdr->p_flags);
  int ret = _pk_pkey_mprotect_unlocked_nodid_check(domain->did, (void*)start, end - start, prot, domain->vkey);
  if (-1 == ret) {
    perror("_pk_pkey_mprotect_unlocked_nodid_check failed");
    return -1;
  }
  return 0;
}
//------------------------------------------------------------------------------

int PK_CODE unprotect_phdr(struct dl_phdr_info *info, Elf64_Phdr* phdr) {
  uintptr_t start = info->dlpi_addr + phdr->p_vaddr;
  uintptr_t end = start + phdr->p_memsz;
  start &= ~PAGEMASK;                   // round down
  end = (end + PAGESIZE-1) & ~PAGEMASK; // round up
  // Mprotect with same permissions
  int prot = get_prot(phdr->p_flags);
  int ret = _pk_pkey_munprotect_unlocked(did_for_exception_handler, (void*)start, end - start, prot);
  if (-1 == ret) {
    perror("_pk_pkey_munprotect_unlocked failed");
    return -1;
  }
  return 0;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_selfprotect_phdr(struct dl_phdr_info *info, size_t size, void *data)
{
    int j;
    int ret;
    domain_t* domain = (domain_t*)data;

    // We grant global read-only access to all non-writable PT_LOAD sections
    assert(rokey_for_exception_handler != VKEY_INVALID);
    domain_t rokey = {
      .did = 0,
      .vkey = rokey_for_exception_handler,
    };

    if (domain) {
        DEBUG_MPK("_pk_selfprotect_phdr(%d, %d)", domain->did, domain->vkey);
        rokey.did = domain->did;
    } else {
        DEBUG_MPK("_pk_selfprotect_phdr()");
    }
    DEBUG_MPK("Module %s (%d segments)", info->dlpi_name, info->dlpi_phnum);

    // Search for module that contains our code
    uintptr_t self = (uintptr_t)((void*)&_pk_selfprotect_phdr); // Take an arbitrary pointer (code or data)
    for (j = 0; j < info->dlpi_phnum; j++) {
        Elf64_Phdr phdr = info->dlpi_phdr[j];
        if (phdr.p_type == PT_LOAD) {
            Elf64_Phdr phdr = info->dlpi_phdr[j];
            uintptr_t start = info->dlpi_addr + phdr.p_vaddr;
            uintptr_t end = start + phdr.p_memsz;
            if (self >= start && self < end) {
                DEBUG_MPK("Found PK module");
                break;
            }
        }
    }
    if (j >= info->dlpi_phnum) {
        // We're in the wrong module
        DEBUG_MPK("Skipping");
        return 0;
    }

    // Re-protect all PT_LOAD (+ GNU_RELRO) segments with did/vkey
    for (j = 0; j < info->dlpi_phnum; j++) {
        Elf64_Phdr phdr = info->dlpi_phdr[j];
        if (phdr.p_type == PT_LOAD) {
            DEBUG_MPK("Reprotecting PT_LOAD   %2d: address=%10p (0x%010lx) [flags 0x%x]", j, (void *) (info->dlpi_addr + phdr.p_vaddr), phdr.p_memsz, phdr.p_flags);
            if (domain) {
                if (phdr.p_flags & PF_W) {
                    ret = reprotect_phdr(domain, info, &phdr);
                } else {
                    ret = reprotect_phdr(&rokey, info, &phdr);
                }
                if (-1 == ret) {
                    // errno set by reprotect_phdr
                    return -1;
                }
            } else {
                if (-1 == unprotect_phdr(info, &phdr)) {
                    // errno set by unprotect_phdr
                    return -1;
                }
            }
        } else if (phdr.p_type == PT_GNU_RELRO) {
            DEBUG_MPK("Reprotecting GNU_RELRO %2d [%d]: address=%10p (0x%010lx) [flags 0x%x]", j, phdr.p_type, (void *) (info->dlpi_addr + phdr.p_vaddr), phdr.p_memsz, phdr.p_flags);
            if (domain) {
                if (phdr.p_flags & PF_W) {
                    ret = reprotect_phdr(domain, info, &phdr);
                } else {
                    ret = reprotect_phdr(&rokey, info, &phdr);
                }
                if (-1 == ret) {
                    // errno set by reprotect_phdr
                    return -1;
                }
            } else {
                if (-1 == unprotect_phdr(info, &phdr)) {
                    // errno set by unprotect_phdr
                    return -1;
                }
            }
        } else if (phdr.p_type == PT_TLS) {
            DEBUG_MPK("Ignoring     PT_TLS    %2d [%d]: address=%10p (0x%010lx) [flags 0x%x]", j, phdr.p_type, (void *) (info->dlpi_addr + phdr.p_vaddr), phdr.p_memsz, phdr.p_flags);
        } else {
            DEBUG_MPK("Ignoring header        %2d [%d]: address=%10p (0x%010lx) [flags 0x%x]", j, phdr.p_type, (void *) (info->dlpi_addr + phdr.p_vaddr), phdr.p_memsz, phdr.p_flags);
        }
    }
    return 0;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_selfprotect(int did, vkey_t vkey) {
  DEBUG_MPK("Selfprotecting PK\n");
  domain_t domain = {
    .did = did,
    .vkey = vkey,
  };
  //print_maps();
  int ret = dl_iterate_phdr(_pk_selfprotect_phdr, &domain);
  //print_maps();

  return ret;
}
//------------------------------------------------------------------------------
int PK_CODE _pk_selfunprotect() {

  //print_maps();
  DEBUG_MPK("Unprotecting PK\n");
  int ret = dl_iterate_phdr(_pk_selfprotect_phdr, NULL);
  //print_maps();

  return ret;
}
//------------------------------------------------------------------------------

#endif // SHARED

//------------------------------------------------------------------------------
// Public API functions
//------------------------------------------------------------------------------

int PK_CODE _pk_deinit(){
    int ret = 0;
    DEBUG_MPK("_pk_deinit");

#ifdef __x86_64__
    if (pk_sysfilter && -1 == _pk_unload_sysfilter_module()) {
      // errno set by _pk_unload_sysfilter_module
      ret |= -1;
    }
#endif
    // RISC-V uses hardware syscall delegation, so no need for sysfilter module

    #ifdef SHARED
    if (-1 == _pk_selfunprotect()) {
      // errno set by _pk_selfunprotect
      ERROR("_pk_deinit: unable to unprotect pk memory");
      ret |= -1;
    }
    #endif // SHARED


#ifdef TIMING
    //save stats file
    FILE* f = fopen("pk_stats.csv", "w");
    if (!f) {
        ERROR("Could not open stats file");
        // errno set by fopen
        ret |= -1;
    } else {
        fprintf(f, "pk_exception_counter, %zu\n", pk_data.stat_num_exceptions);
        fclose(f);
    }
#endif
    return ret;
}
//------------------------------------------------------------------------------

// This is the only function which is API visible for initialization, and
// part of protected PK_CODE
int PK_CODE _pk_init(){
    DEBUG_MPK("_pk_init");
    int ret = 0;

    if (_pk_init_lock()) {
      // errno is set by _pk_init_lock
      goto error;
    }

    _pk_acquire_lock();

    if(pk_data.initialized){
        ERROR("_pk_init: PK already initialized");
        errno = EACCES;
        goto error;
    }

#ifdef DL_HOOKING
    if (-1 == _pk_dl_hooking()) {
        ERROR("_pk_init: Unable to hook libc functions");
        errno = EACCES;
        goto error;
    }
#endif // DL_HOOKING

    _init_debug();

    // verify page size
    pk_data.pagesize = sysconf(_SC_PAGESIZE);
    if (-1 == pk_data.pagesize){
        ERROR("_pk_init: sysconf(_SC_PAGESIZE) failed");
        errno = EACCES;
        goto error;
    }
    if (PAGESIZE != pk_data.pagesize){
        ERROR("_pk_init: pagesize does not match");
        errno = EACCES;
        goto error;
    }

    // allocate DID for root domain
    did_root = _pk_domain_create_unlocked(0);
    if (-1 == did_root){
        // errno set by _pk_domain_create_unlocked
        goto error;
    }
    assert(did_root == DID_FOR_ROOT_DOMAIN);
    assert(_get_default_vkey(did_root) == KEY_FOR_ROOT_DOMAIN);

    // determine stack size for user code
    pk_data.stacksize = _get_default_stack_size();

    // allocate DID for exception handler
    did_for_exception_handler = _pk_domain_create_unlocked(0);
    if (-1 == did_for_exception_handler){
        goto error;
    }
    assert(did_for_exception_handler == DID_FOR_EXCEPTION_HANDLER);
    assert(_get_default_vkey(did_for_exception_handler) == KEY_FOR_EXCEPTION_HANDLER);

    // get trusted TLS offset
    _pk_ttls_offset = (uint64_t)&pk_trusted_tls.backup_user_stack - GET_TLS_POINTER;

    // Setup exception handler for current thread
    // Before calling _pk_setup_thread_unlocked we must make sure that we are
    // currently in the domain of the user stack that we want to protect
    void* exception_stack = _pk_setup_thread_exception_stack();
    ret = _pk_init_thread(did_root, exception_stack);
    if(ret != 0){
        ERROR("_pk_init: _pk_init_thread failed");
        // errno set by _pk_init_thread
        goto error;
    }

    // initialize architecture
    if (_pk_init_arch()) {
        ERROR("_pk_init: _pk_init_arch failed");
        errno = EACCES;
        goto error;
    }

#ifdef SHARED
    // allocate read-only key for exception handler memory that can be
    // read by all domains but not written/manipulated
    rokey_for_exception_handler = _pk_pkey_alloc_unlocked(did_for_exception_handler, 0, 0);
    if (rokey_for_exception_handler < 0) {
        ERROR("failed to allocate read-only key");
        // errno set by _pk_pkey_alloc_unlocked
        goto error;
    }
    if (-1 == _pk_domain_assign_pkey_unlocked(DID_FOR_EXCEPTION_HANDLER, DID_FOR_ROOT_DOMAIN, rokey_for_exception_handler, PK_KEY_COPY, PKEY_DISABLE_WRITE)) {
        ERROR("failed to assign read-only key to root domain");
        // errno set by _pk_domain_assign_pkey_unlocked
        goto error;
    }
#endif // SHARED

    DEBUG_MPK("protecting pk data");

    #ifndef SHARED

    size_t pk_data_size = (size_t)((uintptr_t)__stop_pk_data - (uintptr_t)__start_pk_data);
    ret = _pk_pkey_mprotect_unlocked_nodid_check(did_for_exception_handler, (void *)__start_pk_data, pk_data_size, PROT_WRITE | PROT_READ, PK_DEFAULT_KEY);
    if(ret != 0){
        ERROR("_pk_init: failed to mprotect pk data");
        // errno set by _pk_pkey_mprotect_unlocked_nodid_check
        goto error;
    }
    DEBUG_MPK("protecting pk code");
    size_t pk_code_size = (size_t)((uintptr_t)__stop_pk_code - (uintptr_t)__start_pk_code);
    ret = _pk_pkey_mprotect_unlocked_nodid_check(did_for_exception_handler, (void *)__start_pk_code, pk_code_size,  PROT_EXEC | PROT_READ, PK_DEFAULT_KEY);
    if(ret != 0){
        ERROR("_pk_init: failed to mprotect pk code");
        // errno set by _pk_pkey_mprotect_unlocked_nodid_check
        goto error;
    }

    #else // SHARED

    ret = _pk_selfprotect(did_for_exception_handler, PK_DEFAULT_KEY);
    if (ret != 0) {
        ERROR("_pk_init: failed to mprotect pk code/data");
        // errno set by _pk_selfprotect
        goto error;
    }

    #endif // SHARED

    // initialize syscall interposition
#ifdef __x86_64__
    if (_pk_load_sysfilter_module()) {
        WARNING("Unable to load syscall filter. Did you load sysfilter.ko?");
        WARNING("Proceeding without syscall filter");
    }
#endif
    // RISC-V uses hardware syscall delegation, so no need for sysfilter module

    // TODO register signal handler via sigaction

    assert(CURRENT_DID == DID_FOR_ROOT_DOMAIN);
    
    pk_data.initialized = 1; // this is for internal use (protected in PK_DATA)

    DEBUG_MPK("_pk_init done");
    _pk_release_lock();
    return 0;

error:
    DEBUG_MPK("_pk_init error");
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_create(unsigned int flags){
    DEBUG_MPK("_pk_domain_create(0x%x)", flags);
    assert(pk_data.initialized);

    _pk_acquire_lock();
    int ret = _pk_domain_create_unlocked(flags);
    _pk_release_lock();

    return ret;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_free(int did){
    DEBUG_MPK("_pk_domain_free(%d)", did);
    assert(pk_data.initialized);

    _pk_acquire_lock();
    if (PK_DOMAIN_CURRENT == did) {
        did = CURRENT_DID;
    }

    // TODO: implement me
    WARNING("_pk_domain_free Implement me");

    errno = EINVAL;
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_release_child(int did){
    DEBUG_MPK("_pk_domain_release_child(%d)", did);
    assert(pk_data.initialized);

    _pk_acquire_lock();
    if (!_domain_is_child(did)) {
        ERROR("_pk_domain_release_child domain is not child");
        errno = EINVAL;
        goto error;
    }

    pk_data.domains[did].parent_did = DID_INVALID;
    _pk_release_lock();
    return 0;
error:
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

vkey_t PK_CODE _pk_pkey_alloc(unsigned int flags, unsigned int access_rights){
    DEBUG_MPK("_pk_pkey_alloc(%d, %d)", flags, access_rights);
    assert(pk_data.initialized);

    _pk_acquire_lock();
    vkey_t key = _pk_pkey_alloc_unlocked(CURRENT_DID, flags, access_rights);
    if (-1 == key) {
      ERROR("_pk_pkey_alloc_pk_domain_assign_pkey could not allocate key");
      //errno set by _pk_domain_load_key_unlocked
      key = -1;
    }

    int ret = _pk_domain_load_key_unlocked(CURRENT_DID, key, PK_SLOT_ANY, 0);
    if (-1 == ret) {
      ERROR("_pk_pkey_alloc_pk_domain_assign_pkey could not load newly assigned key");
      //errno set by _pk_domain_load_key_unlocked

      ret = _pk_pkey_free(key); 
      if (-1 == ret) {
        ERROR("_pk_pkey_free failed");
      }

      key = -1;
    }

    _pk_release_lock();

    return key;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_pkey_free(vkey_t vkey){
    DEBUG_MPK("_pk_pkey_free(%d)", vkey);
    assert(pk_data.initialized);
    int ret;

    _pk_acquire_lock();
    if (!_domain_exists(CURRENT_DID)) {
        ERROR("_pk_pkey_free domain does not exist");
        errno = EINVAL;
        goto error;
    }

    if (!_domain_owns_vkey_nodidcheck(CURRENT_DID, vkey)) {
        ERROR("_pk_pkey_free domain does not own vkey");
        errno = EACCES;
        goto error;
    }

    //unload key
    ret = _pk_domain_load_key_unlocked(CURRENT_DID, vkey, PK_SLOT_NONE, 0);
    if (-1 == ret) {
        ERROR("Unloading of the key failed.");
        //errno set by _pk_domain_load_key_unlocked
        goto error;
    }

    // check that vkey is unused
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (pk_data.ranges[rid].used && pk_data.ranges[rid].vkey == vkey) {
            ERROR("_pk_pkey_free range[%zu] addr %p len %zu still uses vkey", rid, pk_data.ranges[rid].addr, pk_data.ranges[rid].len);
            errno = EPERM;
            goto error;
        }
    }

    // check that pkey is not loaded
    // If pkey is allocated under more than one virtual key (vkey),
    // this check is omitted, since multiple vkeys
    // could legitimately be loaded under the same pkey
    pkey_t pkey = _vkey_to_pkey(CURRENT_DID, vkey);
    assert(pkey >= 0 && pkey < PK_NUM_KEYS);
    if (pk_shared_pkeys[pkey] <= 1) {
        bool ret = _pk_is_key_loaded_arch(pkey);
        if (ret) {
            ERROR("_pk_pkey_free: pkey is loaded. Unload it first");
            errno = EPERM;
            goto error;
        }
    }

    // revoke vkey in all domains
    for (size_t did = 0; did < NUM_DOMAINS; did++) {
        if (pk_data.domains[did].used) {
            _pk_domain * domain = &pk_data.domains[did];
            for (size_t key_id = 0; key_id < NUM_KEYS_PER_DOMAIN; key_id++) {
                if (domain->keys[key_id].used && domain->keys[key_id].vkey == vkey) {
                    domain->keys[key_id].used = false;
                    DEBUG_MPK("_pk_pkey_free: revoked domain[%zu].keys[%zu]\n", did, key_id);
                }
            }
        }
    }

    if (pk_shared_pkeys[pkey] >= 1) {
      // decrement sharing count down to zero
      pk_shared_pkeys[pkey]--;
      ret = 0;
    } else {
      // free pkey in the kernel
      ret = PKEY_FREE(pkey);
    }


    _pk_release_lock();
    return ret;

error:
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_assign_pkey_unlocked(int source_did, int target_did, vkey_t vkey, int flags, int access_rights){
    DEBUG_MPK("_pk_domain_assign_pkey_unlocked(%d, %d, %d, %d, %d)", source_did, target_did, vkey, flags, access_rights);

    if (!_domain_exists(source_did)) {
        ERROR("_pk_domain_assign_pkey source domain does not exist");
        errno = EINVAL;
        goto error;
    }

    if (!_domain_exists(target_did)) {
        ERROR("_pk_domain_assign_pkey target domain does not exist");
        errno = EINVAL;
        goto error;
    }

    _pk_domain* current = &pk_data.domains[source_did];
    int key_id = _domain_get_vkey_id(source_did, vkey);

    if (-1 == key_id) {
        ERROR("_pk_domain_assign_pkey domain does not have vkey");
        errno = EACCES;
        goto error;
    }
    pkey_t pkey = _vkey_to_pkey(source_did, vkey);

    if (flags & ~(PK_KEY_OWNER | PK_KEY_COPY)) {
        ERROR("_pk_domain_assign_pkey invalid flags");
        errno = EINVAL;
        goto error;
    }

    bool owner_key = (flags & PK_KEY_OWNER);
    if (owner_key && !current->keys[key_id].owner) {
        ERROR("_pk_domain_assign_pkey domain does not own vkey");
        errno = EACCES;
        goto error;
    }

    bool copy_key       = (flags & PK_KEY_COPY);

    if (access_rights & ~(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE)) {
        ERROR("_pk_domain_assign_pkey invalid access_rights");
        errno = EINVAL;
        goto error;
    }

    int current_perm = current->keys[key_id].perm;

    // determine target key slot to use
    size_t target_key_id;
    if (target_did == source_did) {
        // in case we assign the vkey to ourselves, use the original key_id
        target_key_id = key_id;
    } else {
        // allocate a new key_id
        for (target_key_id = 0; target_key_id < NUM_KEYS_PER_DOMAIN; target_key_id++) {
            if (!pk_data.domains[target_did].keys[target_key_id].used) {
                break;
            }
        }
        if (target_key_id >= NUM_KEYS_PER_DOMAIN) {
            ERROR("_pk_domain_assign_pkey could not allocate key slot for domain");
            errno = ENOMEM;
            goto error;
        }
    }

    // invalidate original key
    if (!copy_key) {
        current->keys[key_id].used = false;
    }

    // store new key in domain's key slot
    pk_data.domains[target_did].keys[target_key_id].vkey  = vkey;
    pk_data.domains[target_did].keys[target_key_id].pkey  = pkey;
    pk_data.domains[target_did].keys[target_key_id].owner = owner_key;
    pk_data.domains[target_did].keys[target_key_id].perm  = current_perm | access_rights;
    pk_data.domains[target_did].keys[target_key_id].used  = true;

    // load key for target domain
    int ret = _pk_domain_load_key_unlocked(target_did, vkey, PK_SLOT_ANY, 0);
    if (-1 == ret) {
      ERROR("_pk_domain_assign_pkey could not load newly assigned key");
      //errno set by _pk_domain_load_key_unlocked
      goto error;
    }
    return 0;

error:
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_assign_pkey(int did, vkey_t vkey, int flags, int access_rights){
    DEBUG_MPK("_pk_domain_assign_pkey(%d, %d, %d, %d)", did, vkey, flags, access_rights);
    assert(pk_data.initialized);

    _pk_acquire_lock();
    if (PK_DOMAIN_CURRENT == did) {
        did = CURRENT_DID;
    }

    int ret = _pk_domain_assign_pkey_unlocked(CURRENT_DID, did, vkey, flags, access_rights);

    _pk_release_lock();

    return ret;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_default_key(int did){
    DEBUG_MPK("_pk_domain_default_key(%d)", did);
    assert(pk_data.initialized);

    int vkey = -1;
    _pk_acquire_lock();
    if (PK_DOMAIN_CURRENT == did) {
        did = CURRENT_DID;
    }

    if(!_domain_is_current_or_child(did)){
        ERROR("_pk_domain_default_key: only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }

    vkey = _get_default_vkey(did);
    if (VKEY_INVALID == vkey) {
        ERROR("_pk_domain_default_key: could not retrieve default vkey");
        errno = EACCES;
        goto error;
    }

    _pk_release_lock();
    return vkey;

error:
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_pkey_mprotect(void *addr, size_t len, int prot, vkey_t vkey){
    DEBUG_MPK("_pk_pkey_mprotect(%p, %zu, %d, %d)", addr, len, prot, vkey);
    assert(pk_data.initialized);

    return _pk_pkey_mprotect2(PK_DOMAIN_CURRENT, addr, len, prot, vkey);
}
//------------------------------------------------------------------------------

int PK_CODE _pk_pkey_mprotect2(int did, void *addr, size_t len, int prot, vkey_t vkey){
    DEBUG_MPK("_pk_pkey_mprotect2(%d, %p, %zu, %d, %d)", did, addr, len, prot, vkey);
    assert(pk_data.initialized);

    _pk_acquire_lock();
    if (PK_DOMAIN_CURRENT == did) {
      did = CURRENT_DID;
    }
    int ret = _pk_pkey_mprotect_unlocked(did, addr, len, prot, vkey);

    //print_maps();
    //_pk_print_debug_info();

    _pk_release_lock();

    return ret;
}
//------------------------------------------------------------------------------

void* PK_CODE _pk_malloc(size_t size) {
    DEBUG_MPK("_pk_malloc");
    return malloc(size);
}
//------------------------------------------------------------------------------

void* PK_CODE _pk_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  return _pk_mmap2(CURRENT_DID, addr, length, prot, flags, fd, offset);
}
//------------------------------------------------------------------------------

void* PK_CODE _pk_mmap2(int did, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  DEBUG_MPK("_pk_mmap2(%d, %p, %zu, %d, %d, %d, %ld)", did, addr, length, prot, flags, fd, offset);
  return _pk_mmap_internal(did, PK_DEFAULT_KEY, addr, length, prot, flags, fd, offset);
}
//------------------------------------------------------------------------------

void* PK_CODE _pk_mmap3(vkey_t vkey, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  DEBUG_MPK("_pk_mmap3(%d, %p, %zu, %d, %d, %d, %ld)", vkey, addr, length, prot, flags, fd, offset);
  return _pk_mmap_internal(PK_DOMAIN_CURRENT, vkey, addr, length, prot, flags, fd, offset);
}
//------------------------------------------------------------------------------

void* PK_CODE _pk_mmap_internal(int did, vkey_t vkey, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    DEBUG_MPK("_pk_mmap_internal(%d, %d, %p, %zu, %d, %d, %d, %ld)", did, vkey, addr, length, prot, flags, fd, offset);
    assert(pk_data.initialized);

    _pk_acquire_lock();

    //print_maps();

    void* mem = MAP_FAILED;

    if (PK_DOMAIN_CURRENT == did) {
        did = CURRENT_DID;
    }

    // did must be current domain or child
    if(!_domain_is_current_or_child(did)){
        ERROR("_pk_mmap_internal: only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }

    // pad to page size
    length = ((length + PAGESIZE-1)) & ~(PAGESIZE-1);
    
    if ((uintptr_t)addr % PAGESIZE || length % PAGESIZE) {
        ERROR("_pk_mmap_internal: memory range is not page-aligned");
        errno = EINVAL;
        goto error;
    }

    mem = MMAP(addr, length, prot, flags, fd, offset);
    if (MAP_FAILED == mem) {
        ERROR("_pk_mmap_internal: failed to map memory");
        // errno is set by mmap
        goto error;
    }


    // set protection key
    int ret = _pk_pkey_mprotect_unlocked_nodid_check(did, mem, length, prot, vkey);
    if (-1 == ret) {
        ERROR("_pk_mmap_internal: failed to set protection key");
        // errno is set by _pk_pkey_mprotect_unlocked
        goto error;
    }

    _pk_release_lock();
    return mem;

error:
    if (MAP_FAILED != mem) {
        ret = MUNMAP(addr, length);
        if (ret) {
            ERROR("_pk_mmap_internal: Unable to unmap memory. We have a memory leak");
        }
    }
    _pk_release_lock();
    return MAP_FAILED;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_munmap(void* addr, size_t len){
  return _pk_munmap2(CURRENT_DID, addr, len);
}
//------------------------------------------------------------------------------

int PK_CODE _pk_munmap2(int did, void* addr, size_t len){
    DEBUG_MPK("_pk_munmap(%d, %p, %zu)",did, addr, len);
    assert(pk_data.initialized);

    _pk_acquire_lock();

    if (PK_DOMAIN_CURRENT == did) {
      did = CURRENT_DID;
    }

    // did must be current domain or child
    if(!_domain_is_current_or_child(did)){
        ERROR("_pk_munmap: only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }

    // pad to page size
    len = (len + (PAGESIZE-1)) & ~(PAGESIZE-1);

    if ((uintptr_t)addr % PAGESIZE || len % PAGESIZE) {
        ERROR("_pk_munmap: memory range is not page-aligned");
        errno = EINVAL;
        goto error;
    }

    if (!_domain_owns_memory(did, addr, len)) {
        ERROR("_pk_munmap: domain does not own memory range");
        errno = EACCES;
        goto error;
    }

    if (!_untrack_memory(addr, len)) {
        ERROR("_pk_munmap cannot untrack memory range");
        errno = ENOMEM;
        goto error;
    }

    int ret = MUNMAP(addr, len);
    if (ret) {
        ERROR("_pk_munmap unable to unmap memory");
        // errno is set by munmap
        goto error;
    }

    _pk_release_lock();
    return 0;

error:
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_mprotect(void *addr, size_t len, int prot) {
  return _pk_mprotect2(CURRENT_DID, addr, len, prot);
}
//------------------------------------------------------------------------------

int PK_CODE _pk_mprotect2(int did, void *addr, size_t len, int prot) {
    DEBUG_MPK("_pk_mprotect(%d, %p, %zu, %d)",did, addr, len, prot);
    assert(pk_data.initialized);

    _pk_acquire_lock();

    if (PK_DOMAIN_CURRENT == did) {
      did = CURRENT_DID;
    }

    // did must be current domain or child
    if(!_domain_is_current_or_child(did)){
        ERROR("_pk_mprotect: only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }

    if ((uintptr_t)addr % PAGESIZE || len % PAGESIZE) {
        ERROR("_pk_mprotect: memory range is not page-aligned");
        errno = EINVAL;
        goto error;
    }

    //_pk_print_debug_info();
    if (!_domain_owns_memory(did, addr, len)) {
            //_pk_print_debug_info();

        ERROR("_pk_mprotect: domain does not own memory range");
        errno = EACCES;
        goto error;
    }

    int ret = MPROTECT(addr, len, prot);
    if (-1 == ret) {
        ERROR("_pk_mprotect: failed to mprotect");
        // errno is set by mprotect
        goto error;
    }

    // Track newly protected memory
    // Note: since mprotect does not change protection keys
    // we need to iterate over all pages to also maintain protection keys
    // in our internal tracking system.
    vkey_t vkey = VKEY_INVALID;
    uintptr_t a;
    uintptr_t s;
    for (a = s = (uintptr_t)addr; a < (uintptr_t)addr + len; a += PAGESIZE) {
        // obtain vkey for current page
        // If page is not tracked yet, this returns VKEY_INVALID
        int pg_vkey = _vkey_for_address_nodidcheck(did, (void*)a);
        if (vkey == pg_vkey) {
            // determine the whole range which uses the same vkey
            continue;
        } else {
            // The key changed. Track this memory range
            if (VKEY_INVALID != vkey) {
                // Update this memory range only if it is already tracked (i.e. vkey!=VKEY_INVALID)
                if (!_track_memory((void*)s, a - s, prot, vkey, _vkey_to_pkey(did, vkey))) {
                    ERROR("_pk_mprotect cannot track memory");
                    errno = ENOMEM;
                    goto error;
                }
            }
            s = a;          // Track new range start
            vkey = pg_vkey; // Track new range's protection key
        }
    }
    if (VKEY_INVALID != vkey) {
        // Update final memory range only if already tracked
        // In the simplest case, this is the whole address range using the same single pkey
        if (!_track_memory((void*)s, a - s, prot, vkey, _vkey_to_pkey(did, vkey))) {
            ERROR("_pk_mprotect cannot track final memory");
            errno = ENOMEM;
            goto error;
        }
    }

    _pk_release_lock();
    return 0;

error:
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_register_ecall(int ecall_id, void* entry){
    DEBUG_MPK("_pk_domain_register_ecall(%d, %p)", ecall_id, entry);
    assert(pk_data.initialized);

    return _pk_domain_register_ecall2(PK_DOMAIN_CURRENT, ecall_id, entry);
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_register_ecall2(int did, int ecall_id, void* entry){
    DEBUG_MPK("_pk_domain_register_ecall2(%d, %d, %p)", did, ecall_id, entry);
    assert(pk_data.initialized);

    _pk_acquire_lock();

    if (PK_DOMAIN_CURRENT == did) {
        did = CURRENT_DID;
    }

    if(!_domain_exists(did)){
        ERROR("_pk_domain_register_ecall2: Domain does not exist");
        errno = EINVAL;
        goto error;
    }

    // did must be current domain or child
    if(!_domain_is_current_or_child(did)){
        ERROR("_pk_domain_register_ecall2: only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }

    // obtain next free ecall_id
    if (PK_ECALL_ANY == ecall_id) {
        for (ecall_id = 0; ecall_id < NUM_REGISTERED_ECALLS; ecall_id++) {
            if (!pk_registered_ecalls[ecall_id].entry) {
                // We found an empty ecall slot
                break;
            }
        }
    }

    // check for valid id
    if(ecall_id < 0 || ecall_id >= NUM_REGISTERED_ECALLS){
        ERROR("_pk_domain_register_ecall2: ecall_id is out of range");
        errno = EACCES;
        goto error;
    }

    if(pk_registered_ecalls[ecall_id].entry != 0){
        ERROR("_pk_domain_register_ecall2: ecall_id already used");
        errno = EACCES;
        goto error;
    }

    // register ecall
    pk_registered_ecalls[ecall_id].did   = did;
    pk_registered_ecalls[ecall_id].entry = entry;
    _pk_release_lock();
    return ecall_id;

error:
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_allow_caller(int caller_did, unsigned int flags){
    DEBUG_MPK("_pk_domain_allow_caller(%d, %u)", caller_did, flags);
    assert(pk_data.initialized);

    return _pk_domain_allow_caller2(PK_DOMAIN_CURRENT, caller_did, flags);
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_allow_caller2(int did, int caller_did, unsigned int flags){
    DEBUG_MPK("_pk_domain_allow_caller2(%d, %d, %u)", did, caller_did, flags);
    assert(pk_data.initialized);

    _pk_acquire_lock();

    if (PK_DOMAIN_CURRENT == did) {
      did = CURRENT_DID;
    }

    if(!_domain_exists(did)){
        ERROR("_pk_domain_allow_caller2: domain does not exist");
        errno = EINVAL;
        goto error;
    }

    if(!_domain_exists(caller_did)){
        ERROR("_pk_domain_allow_caller2: Caller domain does not exist");
        errno = EINVAL;
        goto error;
    }

    // only allowed if we're the target or its parent
    if(!_domain_is_current_or_child(did)){
        ERROR("_pk_domain_allow_caller2 only allowed on self or children");
        errno = EACCES;
        goto error;
    }

    if (_is_allowed_source_nodidcheck(caller_did, did)) {
        DEBUG_MPK("_pk_domain_allow_caller2 already allowed, doing nothing.");
    } else {
        size_t * count = &(pk_data.domains[did].allowed_source_domains_count);
        if(*count >= NUM_SOURCE_DOMAINS){
            ERROR("_pk_domain_allow_caller2: no more slots available");
            errno = ENOMEM;
            goto error;
        }
        pk_data.domains[did].allowed_source_domains[*count] = caller_did;
        (*count)++;
    }

    _pk_release_lock();
    return 0;

error:
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE  _pk_domain_load_key(vkey_t vkey, int slot, unsigned int flags){
    DEBUG_MPK("_pk_domain_load_key(%d, %d, %u)", vkey, slot, flags);
    assert(pk_data.initialized);
    _pk_acquire_lock();
    int ret = _pk_domain_load_key_unlocked(CURRENT_DID, vkey, slot, flags);
    _pk_release_lock();
    return ret;
}
//------------------------------------------------------------------------------

int PK_CODE  _pk_domain_load_key_unlocked(int did, vkey_t vkey, int slot, unsigned int flags){
    DEBUG_MPK("_pk_domain_load_key_unlocked(%d, %d, %d, %u)", did, vkey, slot, flags);

    if (0 != flags) {
        ERROR("_pk_domain_load_key invalid flags");
        errno = EINVAL;
        return -1;
    }

    if(PK_DEFAULT_KEY == vkey){
        vkey = _get_default_vkey(did);
        if (VKEY_INVALID == vkey) {
            ERROR("_pk_domain_load_key domain has no default key");
            errno = EACCES;
            return -1;
        }
    }

    int kid = _domain_get_vkey_id(did, vkey);
    if (-1 == kid){
        ERROR("_pk_domain_load_key domain does not have pkey");
        errno = EACCES;
        return -1;
    }

    int perm = pk_data.domains[did].keys[kid].perm;
    pkey_t pkey = pk_data.domains[did].keys[kid].pkey;

    if (0 != _pk_domain_load_key_arch(did, pkey, slot, perm)){
        return -1;
    }

    if (did == CURRENT_DID) {
        // update current_pkru in TLS to reflect pkru modifications
        pk_trusted_tls.current_pkru = _read_pkru();
    }

    return 0;
}
//------------------------------------------------------------------------------

PK_DATA int _pthread_child_has_signalled = 0;

void PK_CODE _pthread_init_function_c(void * start_routine, void * current_user_stack) {
  DEBUG_MPK("_pthread_init_function_c(%p, %p)", pk_data.pthread_arg.start_routine, pk_data.pthread_arg.arg);
  // initialize thread
  int ret = _pk_init_thread(pk_data.pthread_arg.current_did, pk_data.pthread_arg.exception_stack);
  if (ret) {
    ERROR("_pthread_init_function_c: unable to initialize thread");
    // errno is set by _pk_init_thread
    goto error;
  }

  // we're finished accessing the global pk_data.pthread_arg struct
  // signal the parent pthread that it can now release the lock
  _pthread_child_has_signalled = 1;
  _pk_signal_cond();

  // we acquire the lock for ourselves
  _pk_acquire_lock();

  // enable thread for startup
  pkru_config_t current_config = _read_pkru();
  _pk_domain_switch_arch(TYPE_CALL, CURRENT_DID, current_config, start_routine, current_user_stack);
  _pk_release_lock();
  return;

error:
  // enable thread for self-destruction
  current_config = _read_pkru();
  // TODO: Untested. Also, pass return value correctly to pthread_exit
  _pk_domain_switch_arch(TYPE_CALL, CURRENT_DID, current_config, pthread_exit, current_user_stack);
  _pk_release_lock();
}
//------------------------------------------------------------------------------

int PK_CODE _pk_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg)
{
  DEBUG_MPK("_pk_pthread_create(%p, %p, %p, %p)", thread, attr, start_routine, arg);
  int ret;
  assert(pk_data.initialized);
  _pk_acquire_lock();

  assert(0 == _pthread_child_has_signalled);
  if (!thread || !start_routine) {
    ERROR("_pk_pthread_create: thread or start_routine is NULL");
    ret = EINVAL;
    goto error;
  }

  if(!_domain_owns_memory(CURRENT_DID, thread, sizeof(thread))) {
    ERROR("_pk_pthread_create: *thread is not owned by current domain");
    ret = EINVAL;
    goto error;
  }

  // TODO: If we want to support attr properly, we need to check whether
  // _domain_owns_memory(*attr) and _domain_owns_memory(internal stack of *attr)
//   if (attr) {
//     ERROR("_pk_pthread_create does not support attributes");
//     ret = EINVAL;
//     goto error;
//   }

  // *start_routine needs no check since it is only interpreted by user code

  // *arg needs no check since it is only interpreted by user code

  // setup exception stack
  void* exception_stack_base = _pk_setup_thread_exception_stack();
  if (!exception_stack_base) {
    ERROR("_pk_pthread_create: failed to setup exception stack");
    ret = EAGAIN;
    goto error;
  }

  pk_data.pthread_arg.exception_stack = (uintptr_t*)exception_stack_base; 
  pk_data.pthread_arg.exception_stack_top = (uintptr_t*)exception_stack_base + EXCEPTION_STACK_WORDS - 2; // TODO: outsource to arch-specific code
  pk_data.pthread_arg.arg = arg;
  pk_data.pthread_arg.start_routine = start_routine;
  pk_data.pthread_arg.current_did = CURRENT_DID;

  ret = PTHREAD_CREATE(thread, attr, _pthread_init_function_asm, arg);
  if (ret) {
    goto error;
  }

  DEBUG_MPK("pthread parent");
  if (!_pthread_child_has_signalled) {
    // Wait for the child finishing initial setup
    // There's still a tiny window for a deadlock situation if
    // interrupted exactly here
    _pk_wait_cond();
  }

  assert(1 == _pthread_child_has_signalled);
  _pthread_child_has_signalled = 0;

  _pk_release_lock();
  return 0;

error:
  // TODO: correct error handling
  _pk_release_lock();
  return ret;
}
//------------------------------------------------------------------------------

void PK_CODE _pk_pthread_exit(void* retval) {
  // Currently, by calling pthread_exit directly, threads can exit
  // However, the exception stack is not free'd.

  // TODO: We probably don't need to wrap pthread_exit

  // Prepare thread for continuing at pthread_exit
  // TODO: backup_user_stack is misaligned
  _pk_acquire_lock();
    pkru_config_t current_config = _read_pkru();
  _pk_domain_switch_arch(TYPE_CALL, CURRENT_DID, current_config, pthread_exit, pk_trusted_tls.backup_user_stack);
  assert(false);
  _pk_release_lock();

  // Delete dormant exception stack in subsequent pthread_join by a call to pk_pthread_clean
}
//------------------------------------------------------------------------------

int PK_CODE _pk_register_exception_handler(void (*handler)(void*)) {
  DEBUG_MPK("_pk_register_exception_handler(%p)", handler);
  assert(pk_data.initialized);

  _pk_acquire_lock();

  if (!handler) {
    ERROR("_pk_register_exception_handler: empty handler");
    errno = EINVAL;
    goto error;
  }

  if (!_domain_owns_memory(CURRENT_DID, handler, WORDSIZE)) {
    ERROR("_pk_register_exception_handler: domain does not own handler %p", handler);
    errno = EACCES;
    goto error;
  }

  if (pk_data.user_exception_handler) {
    ERROR("_pk_register_exception_handler: already configured");
    errno = EPERM;
    goto error;
  }

  pk_data.user_exception_handler = handler;

  _pk_release_lock();
  return 0;

error:
  _pk_release_lock();
  return -1;
}
//------------------------------------------------------------------------------
// Debug-only API functions
//------------------------------------------------------------------------------
void PK_CODE _pk_print_debug_info(){
    fprintf(stderr, "\n");
    //printf(COLOR_INFO);
    if (pk_trusted_tls.init) {
        // This requires access to CURRENT_DID
        fprintf(stderr, "[INFO] current config reg: ");
        pk_print_reg_arch(_read_pkru());
    }


    for (size_t tid = 0; tid < NUM_THREADS; tid++) {
        if (NULL == pk_data.threads[tid]) {
          continue;
        }
        _pk_tls* thread_data = pk_data.threads[tid];

        fprintf(stderr, "[INFO] Thread %zu: exception_stack_base: %p, exception_stack: %p, backup_user_stack: %p\n", 
            tid,
            thread_data->exception_stack_base,
            thread_data->exception_stack,
            thread_data->backup_user_stack
        );

        for (size_t did = 0; did < NUM_DOMAINS; did++) {
            if (!pk_data.domains[did].used) {
                continue;
            }
            _pk_thread_domain threaddomaindata = thread_data->thread_dom_data[did];
            if(!threaddomaindata.user_stack_base){
                continue;
            }
            fprintf(stderr, "\t└ Domain %zu: user_stack_base/size: %p -- %p\n", 
                did, threaddomaindata.user_stack_base, threaddomaindata.user_stack_base + threaddomaindata.user_stack_size);

            _expected_return * expected_return = threaddomaindata.expected_return;
            //fprintf(stderr, "\t\t└ expected_return:\n");
            while(expected_return){
                fprintf(stderr, "\t\t└ expected_return (current thread): did=%d, reentry=%p, previous=%14p",
                    expected_return->did,
                    expected_return->reentry,
                    expected_return->previous
                );
                #ifdef ADDITIONAL_DEBUG_CHECKS
                    fprintf(stderr, ", sp=%14p", expected_return->sp);
                #endif
                fprintf(stderr, "\n");
                expected_return = expected_return->previous;
            }
        }
    }

    for (size_t did = 0; did < NUM_DOMAINS; did++) {
        if (!pk_data.domains[did].used) {
            continue;
        }
        fprintf(stderr, "[INFO] Domain %zu:\n", did);
        _pk_domain dom = pk_data.domains[did];

        fprintf(stderr, "\t└ parent_did = %d\n", dom.parent_did);

        fprintf(stderr, "\t└ default_config:  ");
        pk_print_reg_arch(dom.default_config);

        fprintf(stderr, "\t└ keys: [");
        for (size_t key_id = 0; key_id < NUM_KEYS_PER_DOMAIN; key_id++) {
            if (dom.keys[key_id].used) {
              fprintf(stderr, "%d-%d(%s), ",
                  dom.keys[key_id].pkey, dom.keys[key_id].vkey,
                  dom.keys[key_id].owner ? "owner" : "copy"
              );
          }
        }
        fprintf(stderr, "]\n");

        fprintf(stderr, "\t└ allowed_source_domains: [");
        for (size_t i = 0; i < dom.allowed_source_domains_count; i++) {
            fprintf(stderr, "%d, ", dom.allowed_source_domains[i]);
        }
        fprintf(stderr, "]\n");
    }


    fprintf(stderr, "[INFO] Memory ranges:\n");
    for (size_t range_id = 0; range_id < NUM_MPROTECT_RANGES; range_id++) {
        mprotect_t range = pk_data.ranges[range_id];
        if (range.used) {
            fprintf(stderr, "\t└ mprotect-range %zu: addr=%16p -- %16p, len=0x%8zx, prot=%2d, key=%2d-%2d\n", 
            range_id, range.addr, 
            (void*)((uintptr_t)range.addr + range.len), range.len, range.prot, range.pkey, range.vkey);
        }
    }

    //fprintf(stderr, COLOR_RESET);
    fprintf(stderr, "\n");
}
//------------------------------------------------------------------------------

int PK_CODE _pk_current_did(){
    return CURRENT_DID;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_simple_api_call(int a, int b, int c, int d, int e, int f){
    int ret = a+b+c+d+e+f;
    DEBUG_MPK("_pk_simple_api_call(a=%d, b=%d, c=%d, d=%d, e=%d, f=%d). returning %d", a,b,c,d,e,f, ret);
    return ret;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_unused(){
    ERROR("This API call is not implemented");
    errno = ENOSYS;
    return -1;
}
//------------------------------------------------------------------------------

PK_DATA void (*_pk_api_table[API_TABLE_SIZE]) = {
    [_API_unused0]                       = _pk_unused,
    [_API_pk_deinit]                     = _pk_deinit,
    [_API_pk_current_did]                = _pk_current_did,
    [_API_pk_register_exception_handler] = _pk_register_exception_handler,
    [_API_unused4]                       = _pk_unused,
    [_API_pk_domain_create]              = _pk_domain_create,
    [_API_pk_domain_free]                = _pk_domain_free,
    [_API_pk_domain_release_child]       = _pk_domain_release_child,
    [_API_unused8]                       = _pk_unused,
    [_API_unused9]                       = _pk_unused,
    [_API_pk_pkey_alloc]                 = _pk_pkey_alloc,
    [_API_pk_pkey_free]                  = _pk_pkey_free,
    [_API_pk_pkey_mprotect]              = _pk_pkey_mprotect,
    [_API_pk_pkey_mprotect2]             = _pk_pkey_mprotect2,
    [_API_unused14]                      = _pk_unused,
    [_API_unused15]                      = _pk_unused,
    [_API_unused16]                      = _pk_unused,
    [_API_unused17]                      = _pk_unused,
    [_API_unused18]                      = _pk_unused,
    [_API_unused19]                      = _pk_unused,
    [_API_pk_mmap]                       = _pk_mmap,
    [_API_pk_mmap2]                      = _pk_mmap2,
    [_API_pk_mmap3]                      = _pk_mmap3,
    [_API_pk_munmap]                     = _pk_munmap,
    [_API_pk_munmap2]                    = _pk_munmap2,
    [_API_pk_mprotect]                   = _pk_mprotect,
    [_API_pk_mprotect2]                  = _pk_mprotect2,
    [_API_unused27]                      = _pk_unused,
    [_API_unused28]                      = _pk_unused,
    [_API_unused29]                      = _pk_unused,
    [_API_pk_domain_register_ecall]      = _pk_domain_register_ecall,
    [_API_pk_domain_register_ecall2]     = _pk_domain_register_ecall2,
    [_API_pk_domain_allow_caller]        = _pk_domain_allow_caller,
    [_API_pk_domain_allow_caller2]       = _pk_domain_allow_caller2,
    [_API_pk_domain_assign_pkey]         = _pk_domain_assign_pkey,
    [_API_pk_domain_default_key]         = _pk_domain_default_key,
    [_API_pk_domain_load_key]            = _pk_domain_load_key,
    [_API_unused37]                      = _pk_unused,
    [_API_unused38]                      = _pk_unused,
    [_API_unused39]                      = _pk_unused,
    [_API_pk_pthread_create]             = _pk_pthread_create,
    [_API_pk_pthread_exit]               = _pk_pthread_exit,
    [_API_pk_print_debug_info]           = _pk_print_debug_info,
    [_API_pk_simple_api_call]            = _pk_simple_api_call,
    [_API_pk_malloc]                     = _pk_malloc,
};
//------------------------------------------------------------------------------
