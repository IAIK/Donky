#define __ASSEMBLY__
#include "pk_internal.h"

#include "pku_api_wrapper.S"

# ------------------------------------------------------------------------------

#define FRAMESIZE 136
#define OFFSET_ra 128
#define OFFSET_ra 128
#define OFFSET_t0 120
#define OFFSET_t1 112
#define OFFSET_t2 104
#define OFFSET_s0  96
#define OFFSET_a0  88
#define OFFSET_a1  80
#define OFFSET_a2  72
#define OFFSET_a3  64
#define OFFSET_a4  56
#define OFFSET_a5  48
#define OFFSET_a6  40
#define OFFSET_a7  32
#define OFFSET_t3  24
#define OFFSET_t4  16
#define OFFSET_t5   8
#define OFFSET_t6   0
#define OFFSET_reg_a2_type  OFFSET_a2

#define SAVE(reg) sd reg, OFFSET_##reg (sp)
#define RESTORE(reg) ld reg, OFFSET_##reg (sp)
#define ALLOCATE_FRAME() addi  sp, sp, -FRAMESIZE
#define DELETE_FRAME() addi  sp, sp, FRAMESIZE

.macro CALL_C_HANDLER
    //csrrw zero, CSR_UEPC, ra
    call _pk_exception_handler_arch_c # returns the type in a0
.endm
# ------------------------------------------------------------------------------
.section .text

//.section .pk_utvec_table,"ax",@progbits
.section .pk_utvec_table,"a",@progbits
//.section .pk,"a",@progbits
.global pk_utvec_table
.align 4 # must be aligned on a 4-byte boundary according to RISC-V priv spec
pk_utvec_table:
    j fail                   //  0
    j fail                   //  1
    j fail                   //  2
    j fail                   //  3
    j fail                   //  4
    j fail                   //  5
    j fail                   //  6
    j fail                   //  7
    j _pk_handle_syscall     //  8
    j fail                   //  9
    j fail                   // 10
    j fail                   // 11
    j fail                   // 12
    j fail                   // 13
    j _pk_exception_handler  // 14
    j fail                   // 15
.section .text

# ------------------------------------------------------------------------------

.section .pk,"a",@progbits
.global fail
fail:
    DIE
.section .text

# ------------------------------------------------------------------------------

.section .pk,"a",@progbits
.global _pk_exception_syscall
.align 4
_pk_exception_syscall:
.skip  4

.global _pk_exception_handler
.align 4
_pk_exception_handler:
    // load secure exception handler stack from uscratch:
    // we have to do this before saving any registers because otherwise we'd
    // write to an arbitrary memory location with higher priviledges
    // since the pkeys aren't checked in the exception handler mode
    csrrw sp, CSR_USCRATCH, sp

    //allocate frame and save the essential registers
    ALLOCATE_FRAME()
    SAVE(ra)
    //


    /*
    if utval != _pk_exception_handler
        set type to something invalid
    */
    //Save registers which we're using for calculations.
    //Especially important for non-deliberate calls (=exceptions)
    SAVE(t5)
    SAVE(t6)
    SAVE(reg_a2_type)
    csrr t6, CSR_UTVAL
    la   t5, _pk_exception_handler
    sub  t6, t6, t5
    beqz t6, _pk_deliberate_call
    //not a deliberate call: set type
    li reg_a2_type, 0xFFFFFFFF //set type to something invalid (for the dispatching/comparison below)
    j _pk_normal // skip setting uepc, because it was a normal missing-key-exception and not a deliberate call
_pk_deliberate_call:
    csrrw zero, CSR_UEPC, ra
_pk_normal:
    //Restore registers used for earlier calculations.
    //NOTE: reg_a2_type is restored later in _pk_other_end
    //(because we still need its now-different value within the C handler)
    //TODO: we could simplify this by calling a different C handler since we do the dispatching in assembly anyways.
    RESTORE(t6)
    RESTORE(t5)

    // once we know if it's a a real exception (which means that reg_* are wrong)
    // we can do things more efficiently without saving all the regs

    //dispatch based on reg_a2_type
    // 0 = eret, 1 = ecall, 2 = api
    beqz reg_a2_type, _pk_handle_eret
    addi reg_a2_type, reg_a2_type, -1
    beqz reg_a2_type, _pk_handle_ecall
    addi reg_a2_type, reg_a2_type, -1
    beqz reg_a2_type, _pk_handle_api
    j _pk_handle_other

_pk_handle_eret:
    RESTORE(reg_a2_type)
    //save necessary registers: return values
    //which are in t0..t2 because of GEN_CALLEE_WRAPPER
    SAVE(t0)
    SAVE(t1)
    //SAVE(t2)
    //
    CALL_C_HANDLER
    //
    j _pk_eret_end
_pk_handle_ecall:
    RESTORE(reg_a2_type)

    //Save all arguments to the ecall function
    //because they will be overwritten by our C handler before we get to the call
    //Note a0..a2 arguments are actually in t0..t2
    SAVE(t0)
    SAVE(t1)
    SAVE(t2)

    SAVE(a3)
    SAVE(a4)
    SAVE(a5)
    SAVE(a6)
    SAVE(a7)

    //Note: No need to save callee-saved regs since they're handled by GEN_CALL_WRAPPER
    CALL_C_HANDLER
    j _pk_ecall_end
_pk_handle_api:
    //RESTORE(reg_a2_type) // we don't need the type anymore
    //Note we could also use reg_a2_type instead of t5, but t5 is caller-saved anyway
    //
    //check if API id is valid (if id < api table size)
    li  t5, API_TABLE_SIZE
    bge reg_a1_id, t5, fail // or _pk_handle_other for semi-graceful error handling?
    //look up API address in api table and store address in t5
    slli reg_a1_id, reg_a1_id, 3 // multiply id with wordsize so that we can use the result as an offset to the api table
    la   t5, _pk_api_table             // t5 = address of api table
    add  t5, t5, reg_a1_id          // t5 = address of _pk_api_table[reg_a1_id]
    ld t5, 0(t5)                       // t5 = address of API function
    //
    // restore api-function arguments from tmp-regs
    // Note: they were stored in tmp-regs in GEN_CALL_WRAPPER_API
    TMP_REGS_TO_ECALL
    //call API function
    jalr ra, t5, 0 // store return address in ra and jump to API function

    // at this point a0,a1 should contain the return value
    j clear_stack_and_end
_pk_handle_other:
    li reg_a2_type, TYPE_EXCEPTION //NOTE: we could remove this if we swap out 0xFFFFFF above with TYPE_EXCEPTION
    //save all registers
    SAVE(t0)
    SAVE(t1)
    SAVE(t2)
    SAVE(s0)
    SAVE(a0)
    SAVE(a1)
    //NOTE: a2 (=reg_a2_type) is not being saved, because we did so earlier and by now it contains a different value.
    SAVE(a3)
    SAVE(a4)
    SAVE(a5)
    SAVE(a6)
    SAVE(a7)
    SAVE(t3)
    SAVE(t4)
    SAVE(t5)
    SAVE(t6)
    //
    CALL_C_HANDLER
    beqz a0, _pk_other_end // If _pk_exception_handler_arch_c returned non-zero, we want to call user_exception_handler(badaddr)
    csrr a0, utval         // Load badaddr into a0
    SAVE(a0)
    j _pk_other_end

_pk_eret_end:
    //
    // Returning from ECALL
    // discard all registers except return values
    RESTORE(t0)
    RESTORE(t1)
    //RESTORE(t2)
    // clear one stack frame from the exception handler, because this was the frame from the RET
    // but now we need to restore RA from the previous frame (where we had a CALL)
    DELETE_FRAME()
    // callee-saved regs are handled by GEN_CALL_WRAPPER, caller-saved by the caller
    // no other registers (apart form RA) have to be restored
    RESTORE(ra)
    //
    j clear_stack_and_end


_pk_ecall_end:
    // just restore the arguments (or just all the a* regs)
    // also some t-regs because they may contain arguments
    // Note: we restore the arguments, because they were probably overwritten in
    // the C handler. but they're needed now that we actually call the ECALL function

    //Note a0..a2 arguments are actually in t0..t2
    RESTORE(t0)
    RESTORE(t1)
    RESTORE(t2)

    RESTORE(a3)
    RESTORE(a4)
    RESTORE(a5)
    RESTORE(a6)
    RESTORE(a7)
    // NOTE: we jump straight to the end, without deleting the stack frame,
    //       because we need it later when we return from the ecall!
    j _pk_exception_handler_end

_pk_other_end:
    // return from normal (missing-key-)exception and restore all the registers
    RESTORE(ra)
    RESTORE(t0)
    RESTORE(t1)
    RESTORE(t2)
    RESTORE(s0)
    RESTORE(a0)
    RESTORE(a1)
    RESTORE(a2)
    RESTORE(a3)
    RESTORE(a4)
    RESTORE(a5)
    RESTORE(a6)
    RESTORE(a7)
    RESTORE(t3)
    RESTORE(t4)
    RESTORE(t5)
    RESTORE(t6)

clear_stack_and_end:
    DELETE_FRAME()

.global _pk_exception_handler_end
_pk_exception_handler_end:
    csrrw sp, CSR_USCRATCH, sp
    uret
# ------------------------------------------------------------------------------

_pk_handle_syscall:
    csrrw sp, CSR_USCRATCH, sp
    sd t6, 8(sp)
    csrr t6, CSR_UEPC   // Resume at instruction following ecall (UEPC+4)
    addi t6, t6, 4      
    csrw CSR_UEPC, t6
#ifdef SYSCALL_SANDBOXING
    // Check if current domain is root
    // If not, DIE
    csrr t6, CSR_MPK
    slli t6, t6, 1    // remove monitor bit
    srli t6, t6, 1+44 // remove four 11-bit slots
                      // we're left with software-defined bits = DID
    beqz t6, syscall_allowed // root domain has DID=0, and is granted access
    #DIE # To enforce sysfilter, uncomment
syscall_allowed:
#endif
    ld t6, 8(sp)
    ecall
    csrrw sp, CSR_USCRATCH, sp
    uret
# ------------------------------------------------------------------------------
.section .text
# ------------------------------------------------------------------------------
// WARNING CODE BELOW is not protected! (outside of the pk section)
