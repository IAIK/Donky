#pragma once

/**********************************************************************/
// For C only
#ifndef __ASSEMBLY__
/**********************************************************************/

#include <sys/mman.h> // pkey_alloc, pkey_free, mprotect, pkey_mprotect

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <unistd.h>
#include <sys/syscall.h>

int pkey_alloc(unsigned int flags, unsigned int access_rights);
int pkey_free(int pkey);
int pkey_mprotect(void *addr, size_t len, int prot, int pkey);

#ifndef PKEY_DISABLE_ACCESS
#define PKEY_DISABLE_ACCESS (0x1)
#endif

#ifndef PKEY_DISABLE_WRITE
#define PKEY_DISABLE_WRITE (0x2)
#endif

#ifndef SYS_pkey_mprotect
#if __x86_64__
#define SYS_pkey_mprotect 329
#else
#define SYS_pkey_mprotect 288
#endif
#endif

#ifndef SYS_pkey_alloc

#if __x86_64__
#define SYS_pkey_alloc 330
#else
#define SYS_pkey_alloc 289
#endif
#endif


#ifndef SYS_pkey_free
#if __x86_64__
#define SYS_pkey_free 331
#else
#define SYS_pkey_free 290
#endif
#endif

#endif // __ASSEMBLY__
