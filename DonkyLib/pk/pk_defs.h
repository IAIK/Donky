#pragma once

// Max. number of foreign domains that can invoke current domain
#define NUM_SOURCE_DOMAINS 16

// Max. number of keys a domain can hold
#define NUM_KEYS_PER_DOMAIN 2048

// Max. number of domains
#define NUM_DOMAINS 256
#define NUM_THREADS 256

// Max. number of distinct contiguous memory regions pk can track
#define NUM_MPROTECT_RANGES 4096

#ifndef __ASSEMBLY__

// Internal PK code
#define PK_CODE __attribute__((section(".pk"),used))
// Internal PK data
#define PK_DATA __attribute__((section(".pk_data"),used))
// PK code/data that is exported via shared library
#define PK_API  __attribute__ ((visibility ("default")))

// Some functions are used in both, trusted and untrusted code.
// FORCE_INLINE will inline them in the corresponding sections.
//
// If the compiler for some reason decides not to inline, the function
// will be placed in a dead section, and the linker will fail
#define FORCE_INLINE __attribute__((always_inline)) __attribute__((section(".deadcode"))) static inline

#endif /* __ASSEMBLY__ */

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

