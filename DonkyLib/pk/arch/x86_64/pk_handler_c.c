#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "pk_internal.h"

#ifdef FAKE_MPK_REGISTER

// should be thread-local, but since this is for emulation only, we don't care
pkru_config_t PK_API emulated_mpk_reg = {0,};

#endif

/**
 * Per-thread trusted storage
 *
 * It has the following properties
 * - placed inside TLS at a fixed offset
 * - the offset is computed during initialization, and stored in tls_trusted_offset
 * - protected dynamically in the same way as PK_DATA for static variables
 *   Thus, it needs to be aligned on a page boundary, and be multiples of a page size
 * - Access only via TLS macro
 */


//------------------------------------------------------------------------------
// Public API functions
//------------------------------------------------------------------------------
int PK_CODE _pk_init_arch() {
    DEBUG_MPK("_pk_init_arch");

    //DEBUG_MPK("Original pkru-reg   = 0x%lx", _read_pkru_reg());
    // needed for sysfilter
    _write_pkru_reg(0x0);
    DEBUG_MPK("Handler pkru-reg = 0x%lx", _read_pkru_reg());
    DEBUG_MPK("User pkru-reg (will be set when leaving pk handler) = 0x%lx", _read_pkru());

    assert(pk_trusted_tls.current_did == DID_FOR_ROOT_DOMAIN);

    return 0;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
// Internal functions
//------------------------------------------------------------------------------

pkru_config_t PK_CODE _read_pkru() {
    return pk_data.domains[CURRENT_DID].default_config;
}
//------------------------------------------------------------------------------

void PK_CODE _prepare_pkru_for_swap() {
    pk_trusted_tls.current_pkru = pk_data.domains[CURRENT_DID].default_config;
}
//------------------------------------------------------------------------------

void PK_CODE _write_pkru(pkru_config_t new_config) {
    pk_data.domains[CURRENT_DID].default_config = new_config;
}
//------------------------------------------------------------------------------

void PK_CODE _pk_setup_exception_stack_arch(void* exception_stack) {
    // -2 because (in x86_64) the stack must be 16-byte aligned for psabi
    pk_trusted_tls.exception_stack_base = exception_stack;
    pk_trusted_tls.exception_stack = pk_trusted_tls.exception_stack_base + EXCEPTION_STACK_WORDS - 2;
    DEBUG_MPK("_pk_setup_exception_stack(%p)", exception_stack);

    if (pk_data.initialized) {
      assert(_pk_ttls_offset == (uint64_t)&pk_trusted_tls.backup_user_stack - (uint64_t)_get_fsbase());
    }

    DEBUG_MPK("backup_user_stack    = %p", pk_trusted_tls.backup_user_stack);
    DEBUG_MPK("exception_stack_top  = %p", pk_trusted_tls.exception_stack);
    DEBUG_MPK("exception_stack_base = %p", pk_trusted_tls.exception_stack_base);
}
//------------------------------------------------------------------------------

void PK_CODE _pk_setup_exception_handler_arch() {
}
//------------------------------------------------------------------------------

void PK_CODE _pk_setup_domain_arch(int did, pkey_t pkey) {

  assert(pkey >= 0 && pkey < PK_NUM_KEYS);
  pk_data.domains[did].default_config = ((pkru_config_t)-1) << 2; // Deny all access except for KEY_FOR_UNPROTECTED
  pkru_config_t mask = (pkru_config_t)(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE) << (pkey * 2);
  pk_data.domains[did].default_config &= ~mask; // Allow only specified pkey
  DEBUG_MPK("Domain %d: pkru config is 0x%lx", did, pk_data.domains[did].default_config);
}
//------------------------------------------------------------------------------

bool PK_CODE _pk_is_key_loaded_arch(pkey_t pkey) {

    assert(pkey >= 0 && pkey < PK_NUM_KEYS);
    const pkru_config_t mask = (pkru_config_t)(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE) << (pkey*2);
    DEBUG_MPK("_pk_is_key_loaded_arch: mask = %zx", mask);

    for (size_t tid = 0; tid <  NUM_THREADS; tid++) {
        if (NULL == pk_data.threads[tid]) {
            continue;
        }
        assert(pk_data.threads[tid]->init);
        pkru_config_t pkru = pk_data.threads[tid]->current_pkru;
        if ((pkru & mask) != mask) {
            WARNING("_pk_is_key_loaded_arch: thread[%zu] has key %d loaded", tid, pkey);
            WARNING("_pk_is_key_loaded_arch: pkru = %lx", pkru);
            WARNING("_pk_is_key_loaded_arch: mask = %lx", mask);
            errno = EPERM;
            return -1;
        }
    }
    return 0;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_load_key_arch(int did, pkey_t pkey, int slot, int perm) {
    if (slot != PK_SLOT_ANY && slot != PK_SLOT_NONE) {
        ERROR("Invalid slots");
        errno = EINVAL;
        return -1;
    }

    if (pkey < 0 || pkey >= PK_NUM_KEYS) {
        ERROR("Invalid pkey %d. Must be between 0 and 15", pkey);
        errno = EINVAL;
        return -1;
    }

    if (PK_SLOT_NONE == slot) {
        // By disabling access, key is unloaded in x86
        perm = PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE;
    }

    if (perm & ~(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE)) {
        ERROR("Invalid permissions. Only supports PKEY_DISABLE_ACCESS and PKEY_DISABLE_WRITE");
        errno = EINVAL;
        return -1;
    }

    // PKRU layout:
    // AD: access (read+write) disabled
    // WD: write disabled
    // 31                       1 0  bit position
    // |W|A|W|A|...|W|A|W|A|W|A|W|A|
    // |D|D|D|D|...|D|D|D|D|D|D|D|D|
    // |f|f|e|e|...|3|3|2|2|1|1|0|0|
    
    pkru_config_t pkru = pk_data.domains[did].default_config;
    DEBUG_MPK("Old config: 0x%lx", pkru);
    pkru_config_t nkey       =                                       (pkru_config_t)perm << (pkey*2);
    const pkru_config_t mask = (pkru_config_t)(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE) << (pkey*2);
    DEBUG_MPK("Old register: 0x%lx", pkru);

    // apply new key to corresponding slots
    DEBUG_MPK("Mask          0x%lx", mask);
    DEBUG_MPK("Nkey          0x%lx", nkey);
    pkru &= ~mask;
    pkru |= nkey;

    DEBUG_MPK("New register: 0x%lx", pkru);
    
    //update config
    pk_data.domains[did].default_config = pkru;
    return 0;
}
//------------------------------------------------------------------------------

// Ensure that _expected_return stack is not 16-byte but 8-byte aligned
// This ensures that user stack gets 16-byte aligned for psabi
// See _pk_exception_handler_arch_c
C_STATIC_ASSERT((sizeof(_expected_return) % 16) == 8);
C_STATIC_ASSERT((sizeof(_return_did)      % 16) == 8);


uint64_t PK_CODE _pk_exception_handler_arch_c(uint64_t type, uint64_t id){
#ifdef TIMING
    TIME_START(TIMING_HANDLER_C);
#endif
    _pk_acquire_lock();

    void * reentry = 0;
    // user stack is still misaligned by 8 bytes. _pk_exception_handler_c
    // pushes _expected_return struct on user stack s.t. it becomes
    // 16-byte aligned
    DEBUG_MPK("_pk_exception_handler_arch_c: stack=%p", pk_trusted_tls.backup_user_stack);

    if (type == TYPE_CALL) {
        assert_ifdebug(((uintptr_t)pk_trusted_tls.backup_user_stack % 16) == 8); // check stack misaligned
        reentry = (void*)*(pk_trusted_tls.backup_user_stack); // get original reentry point
    }else{
        assert_ifdebug(((uintptr_t)pk_trusted_tls.backup_user_stack % 16) == 0); // check stack misaligned
    }

    uint64_t ret = _pk_exception_handler_unlocked(0, id, type, pk_trusted_tls.backup_user_stack, reentry);

    _pk_release_lock();
#ifdef TIMING
    TIME_STOP(TIMING_HANDLER_C);
#endif
    return ret;
}
//------------------------------------------------------------------------------

void PK_CODE _pk_domain_switch_arch(int type, int target_did, pkru_config_t config, void* entry_point, uint64_t* target_stack) {
    DEBUG_MPK("_pk_domain_switch_arch(%d, %d, 0x%lx, %p, %p)", type, target_did, config, entry_point, target_stack);

    // config is switched in Assembler code via asm wrpkru(_read_pkru())

    // Switch to target stack
    pk_trusted_tls.backup_user_stack = target_stack;

    // Switch to target did
    pk_trusted_tls.current_did = target_did;

    // For TYPE_RET, the original reentry point is already pushed on the
    // original caller's stack (target stack). For TYPE_CALL, we need to
    // push the entry point on the target stack manually.
    // This allows to use the 'ret' instruction
    if (type == TYPE_CALL) {
      assert_ifdebug(((uintptr_t)pk_trusted_tls.backup_user_stack % 16) == 8);

      pk_trusted_tls.backup_user_stack--;
      *(pk_trusted_tls.backup_user_stack) = (uint64_t)entry_point;

      // sp must be 16-b misaligned s.t. 'ret' aligns it for psabi
      assert_ifdebug(((uintptr_t)pk_trusted_tls.backup_user_stack % 16) == 0);
    }

    assert_ifdebug(_pk_current_did() == target_did);
}
//------------------------------------------------------------------------------

void* PK_CODE __attribute__((naked)) _pthread_init_function_asm(void * arg) {
  // We're entering here with the new user stack but in trusted mode
  // switch to trusted exception stack and call into C wrapper
  __asm__ volatile(
    "mov %0,    %%rdi\n"               // save start_routine as first argument
    "mov %%rsp, %%rsi\n"               // save current_user_stack as second argument
    "mov %1,    %%rsp\n"               // load exception stack
    "mov %2,    %%rbx\n"               // load *arg for start_routine in callee-saved register (rbx)
    "call _pthread_init_function_c\n"
    "mov %%rbx, %%rdi\n"               // load *arg as first argument for start_routine
    "jmp " S_PIC(_pk_exception_handler_end) "\n"
    : // no output operands
    : "m"(pk_data.pthread_arg.start_routine),
      "m"(pk_data.pthread_arg.exception_stack_top),
      "m"(pk_data.pthread_arg.arg) // Ensure we're using callee-saved register since GCC resolves %2 before the call.
  );
}
//------------------------------------------------------------------------------

enum {
  rsp=0,
  rbp,
  rax,
  rbx,
  rcx,
  rdx,
  rsi,
  rdi,
  r8,
  r9,
  r10,
  r11,
  r12,
  r13,
  r14,
  r15,
  rend
};

#define PRINT_REG(r, stack) ERROR("%4s: 0x%016lx", #r, stack[rend-1-r])

void PK_CODE __attribute__((noreturn)) _pk_assert_c(uintptr_t * assert_stack) {
    ERROR("_pk_assert_c DYING");
    PRINT_REG(rsp, assert_stack);
    PRINT_REG(rbp, assert_stack);
    PRINT_REG(rax, assert_stack);
    PRINT_REG(rbx, assert_stack);
    PRINT_REG(rcx, assert_stack);
    PRINT_REG(rdx, assert_stack);
    PRINT_REG(rsi, assert_stack);
    PRINT_REG(rdi, assert_stack);
    PRINT_REG(r8 , assert_stack);
    PRINT_REG(r9 , assert_stack);
    PRINT_REG(r10, assert_stack);
    PRINT_REG(r11, assert_stack);
    PRINT_REG(r12, assert_stack);
    PRINT_REG(r13, assert_stack);
    PRINT_REG(r14, assert_stack);
    PRINT_REG(r15, assert_stack);
    assert(false);
}
//------------------------------------------------------------------------------

