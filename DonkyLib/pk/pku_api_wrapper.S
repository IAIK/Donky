#define __ASSEMBLY__
#include "pk_internal.h"

.section .text
.global pk_exception_handler              # Externally visible
.type   pk_exception_handler, @function

// Auto-generate wrappers for PK API calls
// NOTE: CODE BELOW is not protected! (outside of the pk section)
// Functions that override (e.g., preload) libc/pthread are generated via
// GEN_CALL_WRAPPER_API_FALLBACK. This creates a fallback to the native library
// function in case pk is not initialized yet

GEN_CALL_WRAPPER_API          pk_domain_create               _API_pk_domain_create
GEN_CALL_WRAPPER_API          pk_domain_free                 _API_pk_domain_free
GEN_CALL_WRAPPER_API          pk_domain_release_child        _API_pk_domain_release_child
GEN_CALL_WRAPPER_API_FALLBACK pkey_alloc                     _API_pk_pkey_alloc
GEN_CALL_WRAPPER_API_FALLBACK pkey_free                      _API_pk_pkey_free
GEN_CALL_WRAPPER_API_FALLBACK pkey_mprotect                  _API_pk_pkey_mprotect
GEN_CALL_WRAPPER_API          pk_pkey_mprotect2              _API_pk_pkey_mprotect2
GEN_CALL_WRAPPER_API_FALLBACK malloc                         _API_pk_malloc
GEN_CALL_WRAPPER_API_FALLBACK mmap                           _API_pk_mmap
GEN_CALL_WRAPPER_API          pk_mmap2                       _API_pk_mmap2
GEN_CALL_WRAPPER_API          pk_mmap3                       _API_pk_mmap3
GEN_CALL_WRAPPER_API_FALLBACK munmap                         _API_pk_munmap
GEN_CALL_WRAPPER_API          pk_munmap2                     _API_pk_munmap2
GEN_CALL_WRAPPER_API_FALLBACK mprotect                       _API_pk_mprotect
GEN_CALL_WRAPPER_API          pk_mprotect2                   _API_pk_mprotect2
GEN_CALL_WRAPPER_API          pk_domain_register_ecall       _API_pk_domain_register_ecall
GEN_CALL_WRAPPER_API          pk_domain_register_ecall2      _API_pk_domain_register_ecall2
GEN_CALL_WRAPPER_API          pk_domain_allow_caller         _API_pk_domain_allow_caller
GEN_CALL_WRAPPER_API          pk_domain_allow_caller2        _API_pk_domain_allow_caller2
GEN_CALL_WRAPPER_API          pk_domain_assign_pkey          _API_pk_domain_assign_pkey
GEN_CALL_WRAPPER_API          pk_domain_default_key          _API_pk_domain_default_key
GEN_CALL_WRAPPER_API          pk_simple_api_call             _API_pk_simple_api_call
GEN_CALL_WRAPPER_API          pk_print_debug_info            _API_pk_print_debug_info
GEN_CALL_WRAPPER_API          pk_current_did                 _API_pk_current_did
GEN_CALL_WRAPPER_API          pk_domain_load_key             _API_pk_domain_load_key
GEN_CALL_WRAPPER_API          pk_deinit                      _API_pk_deinit
GEN_CALL_WRAPPER_API_FALLBACK pthread_create                 _API_pk_pthread_create
GEN_CALL_WRAPPER_API_FALLBACK pthread_exit                   _API_pk_pthread_exit
GEN_CALL_WRAPPER_API          pk_register_exception_handler  _API_pk_register_exception_handler
