#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <unistd.h>
#include <sys/syscall.h>
#include "pk_internal.h"
#include "mprotect.h"
#include "pk.h"

#ifdef FAKE_PKEY_SYSCALLS

// The first protection key is reserved
unsigned char pkey_alloced[PK_NUM_KEYS] = {1,0,};

int PK_API pkey_alloc(unsigned int flags, unsigned int access_rights) {
    WARNING("Syscall: Fake pkey_alloc(%u, %u)", flags, access_rights);
    if (flags || access_rights & ~(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE)) {
      errno = EINVAL;
      return -1;
    }
    for (size_t i = 0; i < PK_NUM_KEYS; i++) {
    if (!pkey_alloced[i]) {
      pkey_alloced[i] = 1;
      return i;
    }
  }
  WARNING("Syscall: Fake pkey_alloc ran out of keys");
  errno = ENOSPC;
  return -1;
}

int PK_API pkey_free(int pkey) {
    WARNING("Syscall: Fake pkey_free(%d)", pkey);
    if (pkey <= 0 || pkey >= PK_NUM_KEYS) {
        // key 0 cannot be free'd
        WARNING("pkey_free: invalid key");
        errno = EINVAL;
        return -1;
    }
    pkey_alloced[pkey] = 0;
    return 0;
}

int PK_API pkey_mprotect(void *addr, size_t len, int prot, int pkey) {
    WARNING("Syscall:  Fake pkey_mprotect(%p, %zu, %d, %d)", addr, len, prot, pkey);
    if (pkey >= 0 && pkey < PK_NUM_KEYS && pkey_alloced[pkey]) {
      return syscall(SYS_mprotect, addr, len, prot);
    } else {
      WARNING("pkey_mprotect: invalid key");
      errno = EINVAL;
      return -1;
    }
}

#else // FAKE_PKEY_SYSCALLS

int PK_API pkey_mprotect(void *ptr, size_t len, int prot, int pkey)
{
    DEBUG_MPK("Syscall: pkey_mprotect(%p, %zu, %d, %d)", ptr, len, prot, pkey);
    return syscall(SYS_pkey_mprotect, ptr, len, prot, pkey);
}

int PK_API pkey_alloc(unsigned int flags, unsigned int access_rights)
{
    DEBUG_MPK("Syscall: pkey_alloc(%u, %u)", flags, access_rights);
    int ret = syscall(SYS_pkey_alloc, flags, access_rights);
    if (-1 == ret) {
      errno = ENOSPC; // just guessing
    }
    DEBUG_MPK("Syscall: pkey_alloc(%u, %u). ret = %d", flags, access_rights, ret);
    return ret;
}

int PK_API pkey_free(int pkey)
{
    DEBUG_MPK("Syscall: pkey_free(%d)", pkey);
    int ret = syscall(SYS_pkey_free, pkey);
    if (-1 == ret) {
      errno = EINVAL;
    }
    return ret;
}

#endif // FAKE_PKEY_SYSCALLS

