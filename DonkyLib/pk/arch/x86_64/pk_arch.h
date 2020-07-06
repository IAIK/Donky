#pragma once
#include "pk_defs.h"

//------------------------------------------------------------------------------
// Arch-specific API definitions
//------------------------------------------------------------------------------

#define WORDSIZE 8
#define PAGESIZE 4096
#define PAGEMASK (PAGESIZE-1)
#define PK_NUM_KEYS 16

// PK handler types
// Do not change these values, as asm code would break!
#define TYPE_RET  0
#define TYPE_CALL 1
#define TYPE_API  2
#define TYPE_EXCEPTION 3

// Type distinguishes dcalls, returns and API calls
#define rdi_type %rdi
// Holds the ID of a dcall
#define rsi_id   %rsi

#ifdef SHARED

// To access global variables directly from assembler code,
// they must be marked __attribute__((visibility("hidden"))). 
// Otherwise, they are globally exported and require GOT.
// We avoid this via CFLAGS=-fvisibility=hidden

// Intra-lib data access
#define PIC(x) x(%rip)
// Cross-library function calls
#define PLT(x) x@plt
// Intra-lib function calls
#define PCREL(x) x
// String-representation of PIC, for C-inline assembler
// We did not manage to make _pk_exception_handler_end "hidden", so
// use plt indirection instead
#define S_PIC(x) #x"@plt"

#else // SHARED=0 (STATIC)

#define PIC(x) x
#define PLT(x) x
#define PCREL(x) x
#define S_PIC(x) #x

#endif // SHARED

/**********************************************************************/
// For C only
#ifndef __ASSEMBLY__
/**********************************************************************/

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint16_t pkey_t;
typedef uint64_t pkru_config_t;

#define GET_TLS_POINTER ((uintptr_t)_get_fsbase())

FORCE_INLINE uint64_t _get_fsbase() {
    uint64_t ret;
    __asm__ volatile ("mov %%fs:0x0, %0" : "=r" (ret));
    return ret;
}

#define PKRU_TO_INT(x) (x)
#define INT_TO_PKRU(x) (x)

#ifdef FAKE_MPK_REGISTER

extern pkru_config_t emulated_mpk_reg;

FORCE_INLINE pkru_config_t _read_pkru_reg() {
    pkru_config_t copy = emulated_mpk_reg;
    return copy;
}

FORCE_INLINE void _write_pkru_reg(pkru_config_t new_config) {
    emulated_mpk_reg = new_config;
}

#else /* FAKE_MPK_REGISTER */

FORCE_INLINE pkru_config_t _read_pkru_reg() {
    pkru_config_t ret;
    // https://www.felixcloutier.com/x86/rdpkru
    __asm__ volatile(
      "xor %%ecx, %%ecx\n"
      "rdpkru"
      : "=a"(ret)
      : /* no inputs */
      : "rdx"
    );
    return ret;
}

FORCE_INLINE void _write_pkru_reg(pkru_config_t new_val) {
    // https://www.felixcloutier.com/x86/wrpkru
    __asm__ volatile(
      "xor %%ecx, %%ecx\n" // clear ecx
      "xor %%edx, %%edx\n" // clear edx
      "wrpkru"
      : /* no outputs */
      : "a"(new_val)
      : "rcx", "rdx"
    );
}

#endif /* FAKE_MPK_REGISTER */

FORCE_INLINE void pk_debug_usercheck_arch() {
}
//------------------------------------------------------------------------------

#include <stdio.h>
FORCE_INLINE void pk_print_reg_arch(pkru_config_t reg){
    fprintf(stderr,"raw = 0x%lx, ", reg);
    fprintf(stderr,"\n");
}
//------------------------------------------------------------------------------

#ifdef __cplusplus
}
#endif

/**********************************************************************/
// For ASM only
#elif defined __ASSEMBLY__
/**********************************************************************/

#ifdef FAKE_MPK_EXCEPTION

.macro trigger_exception
    call PLT(pk_exception_handler) // Since first call invokes the dynamic linker, which manipulates r10, we use LD_BIND_NOW=1
.endm

#else // FAKE_MPK_EXCEPTION
#error "x86 can only emulate MPK exception"
#endif // FAKE_MPK_EXCEPTION

.macro DIE
    jmp .
.endm

.macro SAVE_CALLEE_REGS
    push %rbp
    push %r15
    push %r14
    push %r13
    push %r12
    push %rbx
    add $-0x8, %rsp // to avoid psabi misalignment, we need an odd number
                    // of pushes
    //Note that RSP is also callee-saved, but the exception handler handles its preservation
.endm

.macro RESTORE_CALLEE_REGS
    add $0x8, %rsp // to avoid psabi misalignment
    pop %rbx
    pop %r12
    pop %r13
    pop %r14
    pop %r15
    pop %rbp
.endm

/**
 * Macro for generating call wrappers
 * @param name Name of the generated wrapper function
 * @param id   Unique integer of the wrapped function
 * @param type TYPE_ECALL or TYPE_API
 */
.macro GEN_CALL_WRAPPER name id
.global ecall_\name
.type ecall_\name @function
ecall_\name:

    // Save callee regs since we cannot rely on potentially untrusted
    // ecall target to behave properly
    SAVE_CALLEE_REGS

    // Save first two argument registers on stack since we replace them
    // with type and call id
    push rdi_type
    push rsi_id

    mov $(TYPE_CALL),   rdi_type
    mov $(\id),         rsi_id

    trigger_exception
_reentry_\name:

    // Cleanup stack
    add $16, %rsp

    RESTORE_CALLEE_REGS
    ret
.endm

/**
 * Macro for generating return wrappers
 * @param name Name of the function. The wrapper will invoke _name
 * @param id   Unique integer of the wrapped function
 */
.macro GEN_CALLEE_WRAPPER name id
.global _ecall_receive_\name
_ecall_receive_\name:

    add $-0x8, %rsp      // to avoid psabi misalignment
    call \name

    mov $(TYPE_RET), rdi_type
    mov $(\id),      rsi_id

    add $0x8, %rsp      // to avoid psabi misalignment
    trigger_exception
    DIE
.endm


.macro GEN_REGISTER name id
.global ecall_register_\name
.type ecall_register_\name @function
ecall_register_\name:

    // _pk_domain_register_ecall2(int did, uint id, void * entry_point)
    // rdi = did
    // rsi = id
    // rdx = entry_point
    //mov      %rdi, %rdi
    mov      $(\id), %rsi
    lea      PIC(_ecall_receive_\name), %rdx

    jmp pk_domain_register_ecall2
    DIE
ret
.endm

.macro GEN_ALL_SIMPLE name id
    GEN_REGISTER       \name \id
    GEN_CALL_WRAPPER   \name \id
    GEN_CALLEE_WRAPPER \name \id
.endm

#endif // __ASSEMBLY__
