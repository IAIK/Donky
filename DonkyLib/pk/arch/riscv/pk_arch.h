#pragma once
#include "pk_defs.h"

//------------------------------------------------------------------------------
// Arch-specific API definitions
//------------------------------------------------------------------------------

#define WORDSIZE 8 //sizeof(uint64_t)
#define PAGESIZE 4096
#define PAGEMASK (PAGESIZE-1)
#define PK_NUM_KEYS 1023 // NOTE: 1023 is an invalid key. the kernel should never give this key away.

// PK handler types
// Do not change these values, as asm code would break!
#define TYPE_RET  0
#define TYPE_CALL 1
#define TYPE_API  2
#define TYPE_EXCEPTION 3

// Distinguishes ECALLs and returns
#define reg_a2_type a2
// Holds the CALL ID
#define reg_a1_id   a1
// Holds ms data (TODO: needed?)
#define reg_a0_data a0

// defines for PK API

// CSR defines for interrupt handling
#define CSR_USTATUS 0x000
#define CSR_UIE 0x004
#define CSR_UTVEC 0x005
#define CSR_USCRATCH 0x040
#define CSR_UEPC 0x041
#define CSR_UCAUSE 0x042
#define CSR_UTVAL 0x043
#define CSR_UIP 0x044

// CSR defines for arch ISA
#define CSR_MISA 0x301
#define CSR_UMISA 0x047

// defines for MPK
#define CSR_MPK 0x046
#define CAUSE_MPKEY_MISMATCH_FAULT 0xe

#ifdef SHARED
// shared lib
// To access global variables from assembler code,
// they must be marked __attribute__((visibility("hidden"))). 
// Otherwise, they are globally exported.
// We avoid this via CFLAGS=-fvisibility=hidden

// Relocation types
// http://www.mindfruit.co.uk/2012/06/relocations-relocations.html
    
// TODO https://github.com/riscv/riscv-elf-psabi-doc/blob/master/riscv-elf.md#pc-relative-symbol-addresses

// Data accesses are done rip-relative
#define PIC(x) x(pc) /* TODO */
// For cross-library calls
#define PLT(x) x@plt
//#define PCREL(x) x@pcrel
// Intra-lib calls can be done directly (pc-relative), since they are
// not exported (i.e. "hidden")
#define PCREL(x) x
// We did not manage to make _pk_exception_handler_end "hidden", so
// use plt indirection instead
#define S_PIC(x) #x"@plt"
#else // SHARED
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

typedef struct __attribute__((__packed__)) {
    uint slot_0_mpkey : 10;
    uint slot_0_wd    :  1;
    uint slot_1_mpkey : 10;
    uint slot_1_wd    :  1;
    uint slot_2_mpkey : 10;
    uint slot_2_wd    :  1;
    uint slot_3_mpkey : 10;
    uint slot_3_wd    :  1;
    uint sw_did       :  8;
    uint sw_unused    : 11;
    uint mode         :  1;
} pkru_config_t;


#define GET_TLS_POINTER ((uintptr_t)_get_tp())

FORCE_INLINE uint64_t _get_tp() {
    register uint64_t ret asm("tp");
    return ret;
}

#define CSRR(csr_id) ({uint64_t ret; asm volatile ("csrr %0, %1" : "=r"(ret) : "i"(csr_id)); ret;}) // GCC statement expression
//~ __attribute__((always_inline)) static inline uint64_t CSRR(const uint64_t csr_id){
    //~ uint64_t ret;
    //~ asm volatile ("csrr %0, %1" : "=r"(ret) : "i"(csr_id));
    //~ return ret;
//~ }

FORCE_INLINE void CSRW(const uint64_t csr_id, const uint64_t val){
    IFDEBUG_CSR({
        char * s;
        switch (csr_id)
        {
        case CSR_USTATUS:  s = "USTATUS";  break;
        case CSR_UIE:      s = "UIE";      break;
        case CSR_UTVEC:    s = "UTVEC";    break;
        case CSR_USCRATCH: s = "USCRATCH"; break;
        case CSR_UEPC:     s = "UEPC";     break;
        case CSR_UCAUSE:   s = "UCAUSE";   break;
        case CSR_UTVAL:    s = "UTVAL";    break;
        case CSR_UIP:      s = "UIP";      break;
        case CSR_MISA:     s = "MISA";     break;
        case CSR_UMISA:    s = "UMISA";    break;
        case CSR_MPK:      s = "MPK";      break;
        default:           s = "???";      break;
        }
        DEBUG_CSR("Setting CSR %s to 0x%zx", s, val);
    });

    asm volatile ("csrw %0, %1" : : "i"(csr_id), "r"(val));
    #ifdef ADDITIONAL_DEBUG_CHECKS
        uint64_t read = CSRR(csr_id);
        if(read != val){
            ERROR_FAIL("Could not set CSR 0x%lx to 0x%lx. (its value is 0x%lx)", csr_id, val, read);
        }
    #endif
}

#define CSRW(x,y) CSRW((x), (uint64_t)(y))

typedef union{
    pkru_config_t pkru;
    uint64_t pkru_as_int;
} union_pkru_config_t;

FORCE_INLINE uint64_t PKRU_TO_INT(pkru_config_t pkru) {
    union_pkru_config_t u;
    u.pkru = pkru;
    return u.pkru_as_int;
}

FORCE_INLINE pkru_config_t INT_TO_PKRU(uint64_t reg) {
    union_pkru_config_t u;
    u.pkru_as_int = reg;
    return u.pkru;
}

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
    uint64_t copy = CSRR(CSR_MPK);
    return INT_TO_PKRU(copy);
}

FORCE_INLINE void _write_pkru_reg(pkru_config_t new_config) {
    uint64_t reg = PKRU_TO_INT(new_config);
    CSRW(CSR_MPK, reg);
    // In theory we need an instruction-fence here, 
    // unless we can guarantee that we execute more instructions before uret
    // such that the pipeline never contains invalid instructions?
    #ifdef ADDITIONAL_DEBUG_CHECKS
        if(CSRR(CSR_MPK) != reg){
            ERROR_FAIL("Failed to set CSR_MPK to 0x%lx. Its value is  0x%lx", reg, CSRR(CSR_MPK));
        }
    #endif
    assert_ifdebug(CSRR(CSR_MPK) == reg);
}
#endif /* FAKE_MPK_REGISTER */


// read/write pkru directly goes to the mpk register
#define _read_pkru()     _read_pkru_reg()
#define _write_pkru(new_config) _write_pkru_reg(new_config)

#define CURRENT_DID ({ assert_ifdebug(pk_trusted_tls.init); _read_pkru().sw_did;})

FORCE_INLINE void pk_print_reg_arch(pkru_config_t reg){
    fprintf(stderr,"raw = 0x%zx, ", PKRU_TO_INT(reg));
    fprintf(stderr,"(mode=%d), did = %4u, ", reg.mode, reg.sw_did);
    fprintf(stderr,"keys = [%4u](wd=%1u) [%4u](wd=%1u) [%4u](wd=%1u) [%4u](wd=%1u)", 
        reg.slot_3_mpkey, reg.slot_3_wd,
        reg.slot_2_mpkey, reg.slot_2_wd,
        reg.slot_1_mpkey, reg.slot_1_wd,
        reg.slot_0_mpkey, reg.slot_0_wd
    );
    printf("\n");
}

FORCE_INLINE void pk_debug_usercheck_arch() {
  // If called from main, expected mode is 0
  pkru_config_t reg = _read_pkru();
  assert_warn(reg.mode == 0);
}
//------------------------------------------------------------------------------

void     PK_CODE _pk_exception_syscall(void);

#ifdef __cplusplus
}
#endif

/**********************************************************************/
// For ASM only
#elif defined __ASSEMBLY__
/**********************************************************************/

.macro loadword reg label
    la   \reg, \label
    ld   \reg, 0(\reg)
.endm

.macro DIE
    ld t0, 0(zero)
    //j .
.endm

.macro SLOW_PUSH reg
addi    sp, sp, -8
sd      \reg,  0(sp)
.endm

.macro SLOW_POP reg
ld      \reg,  0(sp)
addi    sp, sp, 8
.endm

/*
.macro simulate_exception
    // For now we have to simulate the exception, so we set ucause, uepc, mpk.mode
    // set ucause
    csrw CSR_UCAUSE, CAUSE_MPKEY_MISMATCH_FAULT

    // store return address (label 1) at uepc to simulate an exception?
    SLOW_PUSH ra
    la ra, 1f
    csrrw zero, CSR_UEPC, ra
    SLOW_POP ra
.align 2 // uepc needs to be 2-byte aligned
1:
.endm

.macro trigger_exception_jump_simple
    j _pk_exception_handler
.align 2
.endm

.macro trigger_exception_call
    SLOW_PUSH ra
    call _pk_exception_handler
.align 2 // uepc needs to be 2-byte aligned
    SLOW_POP ra
.endm
*/

.macro trigger_exception_jump
    SLOW_PUSH ra
    la ra, 1f //store return address in ra (will be in uepc later)
    j _pk_exception_handler
.align 2 // uepc needs to be 2-byte aligned
1:  SLOW_POP ra
.endm

.macro trigger_exception_load
    SLOW_PUSH ra
    la ra, 1f
    //Trigger exception by loading a word from the handler
    //Note: using unused caller-saved register.
    loadword t5 _pk_exception_handler
    //loadword t5 pk_initialized
.align 2 // uepc needs to be 2-byte aligned
1:  SLOW_POP ra
.endm

.macro trigger_exception
    //trigger_exception_jump
    trigger_exception_load
.endm

.macro goto_exception_handler id type
    // For now we have to simulate the exception, so we set ucause, uepc, mpk.mode
    // set ucause
    // csrw CSR_UCAUSE, CAUSE_MPKEY_MISMATCH_FAULT
    // store label 1 at uepc to simulate an exception
    // note temporarily mis-using reg_a1_id because we overwrite it later anyway
    //la reg_a1_id, 1f
    //la reg_a1_id, _pk_exception_handler
    //csrrw zero, CSR_UEPC, reg_a1_id

    // exception data to regs
    li       reg_a1_id, \id
    li       reg_a2_type, \type

    //go to exception handler
    trigger_exception
.endm

.macro CLEAR_CALLER_SAVED_TEMP_REGS
mv      t0,  x0
mv      t1,  x0
mv      t2,  x0
mv      t3,  x0
mv      t4,  x0
mv      t5,  x0
mv      t6,  x0
.endm

.macro CLEAR_CALLEE_SAVED_REGS
mv      s0,  x0
mv      s1,  x0
mv      s2,  x0
mv      s3,  x0
mv      s4,  x0
mv      s5,  x0
mv      s6,  x0
mv      s7,  x0
mv      s8,  x0
mv      s9,  x0
mv      s10, x0
mv      s11, x0
.endm

.macro SAVE_CALLEE_REGS
addi    sp, sp, -12*8
sd      s0,  11*8(sp)
sd      s1,  10*8(sp)
sd      s2,   9*8(sp)
sd      s3,   8*8(sp)
sd      s4,   7*8(sp)
sd      s5,   6*8(sp)
sd      s6,   5*8(sp)
sd      s7,   4*8(sp)
sd      s8,   3*8(sp)
sd      s9,   2*8(sp)
sd      s10,  1*8(sp)
sd      s11,  0*8(sp)
.endm

.macro RESTORE_CALLEE_REGS
ld      s0,  11*8(sp)
ld      s1,  10*8(sp)
ld      s2,   9*8(sp)
ld      s3,   8*8(sp)
ld      s4,   7*8(sp)
ld      s5,   6*8(sp)
ld      s6,   5*8(sp)
ld      s7,   4*8(sp)
ld      s8,   3*8(sp)
ld      s9,   2*8(sp)
ld      s10,  1*8(sp)
ld      s11,  0*8(sp)
addi    sp, sp, 12*8
.endm


//NOTE: Using t* registers, because they're caller saved.
//      So we do not have to backup&restore them.
//      Also we avoid PLT issues this way.
.macro ECALL_REGS_TO_TMP
    mv t0, reg_a0_data
    mv t1, reg_a1_id
    mv t2, reg_a2_type
.endm

.macro TMP_REGS_TO_ECALL
    mv reg_a0_data, t0
    mv reg_a1_id,   t1
    mv reg_a2_type, t2
.endm


.macro GEN_CALL_WRAPPER_API name id
.global \name
\name:
    ECALL_REGS_TO_TMP
    goto_exception_handler \id TYPE_API
_reentry_\name:
    // NOTE: exception preserves RA reg, so we safely return
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
pk_\name:
    # If pk is not initialized yet, call the native function
    lb   t0, PIC(pk_initialized)
    beqz t0, \name
    GEN_CALL_WRAPPER_API pk2_\name \id
.endm

.macro GEN_CALL_WRAPPER name id
.global ecall_\name
ecall_\name:
    //NOTE we save s* regs because they're callee-saved, but we can't trust our callee to do that
    //NOTE reg_ecall_* (a0..a2) are not required to be preserved across calls
    SAVE_CALLEE_REGS



    //NOTE: if argument registers are also callee-saved (in other architectures)
    //      we could also save them here instead of doing that in the exception handler code
    //      just make sure that we don't do it twice!

    // Save ecall argument regs to temp registers because we use them in goto_exception_handler
    ECALL_REGS_TO_TMP

    goto_exception_handler \id TYPE_CALL
_reentry_\name: //label just for debugging
    TMP_REGS_TO_ECALL //TODO do we need to restore all or just a0,a1?

    RESTORE_CALLEE_REGS
    // NOTE: exception preserves RA reg, so we safely return
    ret
.endm


.macro GEN_CALLEE_WRAPPER name id
.global _ecall_receive_\name
_ecall_receive_\name:

    //Restore (previously saved) function arguments from tmp-regs
    TMP_REGS_TO_ECALL


    call \name

    //move return values (if any), to t0..t2.
    //(so that we can restore them later at _reentry_\name)
    //TODO technically we probably only need to do a0,a1
    ECALL_REGS_TO_TMP



    // Callee-saved regs are already restored by \name due to ABI

    goto_exception_handler \id TYPE_RET
    DIE
.endm


.macro GEN_REGISTER name id
.global ecall_register_\name
ecall_register_\name:
    // note: a0 = did = function argument
    //       a1 will be the id of the ecall
    //
    //loadword a1, ECALL_TEST2_ID
    li       a1, \id
    la       a2, _ecall_receive_\name
    //
    addi     sp,sp,-8
    sd       ra,0(sp)
    call     pk_domain_register_ecall2
    ld       ra,0(sp)
    addi     sp,sp,8
    ret
.endm

//generate all 3 wrappers for functions with simple arguments (args fit into regs)
.macro GEN_ALL_SIMPLE name id
    GEN_REGISTER       \name \id
    GEN_CALL_WRAPPER   \name \id
    GEN_CALLEE_WRAPPER \name \id
.endm


#endif // __ASSEMBLY__
