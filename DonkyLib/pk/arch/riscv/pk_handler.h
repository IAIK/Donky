#pragma once

#if __riscv && __riscv_xlen == 64 && __riscv_atomic
#else
#error "Unsupported platform"
#endif //__riscv ...

#include "pk_debug.h"
#include "pk_arch.h"

/**********************************************************************/
// For C only
#ifndef __ASSEMBLY__
/**********************************************************************/

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif
extern void (*pk_utvec_table)(void);

// internal pku functions
void _pk_sa_sigaction_asm(/*sig, info, ucontext*/);

// internal arch-specific functions
void     PK_CODE _pk_exception_handler(void);
void     PK_CODE _pk_exception_handler_end(void);
uint64_t PK_CODE _pk_exception_handler_arch_c(uint64_t data, uint64_t id, uint64_t type);
int      PK_CODE _pk_init_arch();
void     PK_CODE _pk_setup_exception_stack_arch(void* exception_handler_stack);
void     PK_CODE _pk_setup_exception_handler_arch();
void     PK_CODE _pk_setup_domain_arch(int did, pkey_t pkey);
void     PK_CODE _pk_domain_switch_arch(int type, int target_did, pkru_config_t config, void* entry_point, uint64_t* target_stack);
int      PK_CODE _pk_domain_load_key_arch(int did, pkey_t pkey, int slot, int perm);
bool     PK_CODE _pk_is_key_loaded_arch(pkey_t pkey);
void*    PK_CODE _pthread_init_function_asm(void *arg);


//debug helpers
void FORCE_INLINE PRINT_UREGS(){
    DEBUG_MPK("uie      = %zx", CSRR(CSR_UIE));
    DEBUG_MPK("ustatus  = %zx", CSRR(CSR_USTATUS));
    DEBUG_MPK("uepc     = %zx", CSRR(CSR_UEPC));
    DEBUG_MPK("ucause   = %zx", CSRR(CSR_UCAUSE));
    DEBUG_MPK("utval    = %zx", CSRR(CSR_UTVAL));
    DEBUG_MPK("uip      = %zx", CSRR(CSR_UIP));
    DEBUG_MPK("uscratch = %zx", CSRR(CSR_USCRATCH));
}

#ifdef __cplusplus
}
#endif

/**********************************************************************/
// For ASM only
#elif defined __ASSEMBLY__
/**********************************************************************/


#endif // defined __ASSEMBLY__
