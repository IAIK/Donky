#pragma once

#if __x86_64__
#else
#error "Unsupported platform"
#endif //__x86_64__

#include "pk_arch.h"


/**********************************************************************/
// For C only
#ifndef __ASSEMBLY__
/**********************************************************************/

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#include "pk_debug.h"

#ifdef __cplusplus
extern "C" {
#endif

//extern uint64_t _pk_scratch;
extern uint64_t _pk_ttls_offset;

//------------------------------------------------------------------------------
// Internal definitions
//------------------------------------------------------------------------------

// internal pku functions
void _pk_sa_sigaction_asm(/*sig, info, ucontext*/);

// internal functions
void     PK_CODE _pk_exception_handler(void);
void     PK_CODE _pk_exception_syscall(void);
void     PK_CODE _pk_exception_handler_end(void);
uint64_t PK_CODE _pk_exception_handler_arch_c(uint64_t id, uint64_t type);
int      PK_CODE _pk_init_arch();
void     PK_CODE _pk_setup_exception_stack_arch(void* exception_handler_stack);
void     PK_CODE _pk_setup_exception_handler_arch();
void     PK_CODE _pk_setup_domain_arch(int did, pkey_t pkey);
void     PK_CODE _pk_domain_switch_arch(int type, int target_did, pkru_config_t config, void* entry_point, uint64_t* target_stack);
bool     PK_CODE _pk_is_key_loaded_arch(pkey_t pkey);
int      PK_CODE _pk_domain_load_key_arch(int did, pkey_t pkey, int slot, int perm);
void*    PK_CODE _pthread_init_function_asm(void *arg);
void     PK_CODE _pk_assert_c(uintptr_t * assert_stack);

pkru_config_t PK_CODE _read_pkru();
void PK_CODE _write_pkru(pkru_config_t new_config);
  
#define CURRENT_DID ({assert_ifdebug(DID_INVALID != pk_trusted_tls.current_did); assert_ifdebug(pk_trusted_tls.init); pk_trusted_tls.current_did;})

#ifdef __cplusplus
}
#endif

/**********************************************************************/
// For ASM only
#elif defined __ASSEMBLY__
/**********************************************************************/


#ifdef FAKE_MPK_EXCEPTION

.macro trigger_exception_local
    // TODO: differentiate between API wrappers (which are part of shared lib and do not need GOT indirection)
    // and ecalls (which are in different library/main)
    call PLT(pk_exception_handler)
.endm

.macro return_from_exception
    ret
.endm

#else // FAKE_MPK_EXCEPTION

#error "trigger_exception: implement me"

#endif // FAKE_MPK_EXCEPTION

/**
 * Macro for generating call wrappers
 * @param name Name of the generated wrapper function
 * @param id   Unique integer of the wrapped function
 * @param type TYPE_ECALL or TYPE_API
 */
.macro GEN_CALL_WRAPPER_API name id
.global \name
.type \name @function
\name:
    // Unlike GEN_CALL_WRAPPER, we do not need to save callee registers
    // since we assume that the trusted handler follows calling convention

    // Save first two argument registers on stack since we replace them
    // with type and call id
    push rdi_type
    push rsi_id

    mov $(TYPE_API),    rdi_type
    mov $(\id),         rsi_id

    trigger_exception_local

_reentry_\name:
    // Cleanup stack
    add $16, %rsp
    ret
.endm

/**
 * Macro for generating call wrappers that fall back to the libc function
 * if not initialized yet (i.e. pk_initialized is false)
 * 
 * @param name points to the original libc function. The generated wrapper
 *             function gets a pk_ prefix.
 * @param id   Unique integer of the wrapped function
 * @param type TYPE_ECALL or TYPE_API
 */
.macro GEN_CALL_WRAPPER_API_FALLBACK name id
.global pk_\name
.type pk_\name @function
pk_\name:
    // If pk is not initialized yet, call the native function
    movzb PIC(pk_initialized), %r10
    test %r10, %r10
    jz PLT(\name)
    GEN_CALL_WRAPPER_API pk2_\name \id
.endm

#endif // defined __ASSEMBLY__
