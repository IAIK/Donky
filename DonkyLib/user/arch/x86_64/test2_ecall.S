#define __ASSEMBLY__
#include "pk.h"
#include "test2_ecall.h"

GEN_ALL_SIMPLE test_args          ECALL_TEST_ARGS_ID
GEN_ALL_SIMPLE test_api_calls     ECALL_TEST_API_ID
GEN_ALL_SIMPLE test_kill_all_regs ECALL_TEST_KILL_ALL_REGS_ID
GEN_ALL_SIMPLE test2_nested       ECALL_TEST2_NESTED

# Save custom ecall stack into ecall_save_frame_stack_new
.global ecall_save_frame_prepare
.type ecall_save_frame_prepare @function
ecall_save_frame_prepare:
    lea PIC(ecall_save_frame_stack), %r10
    add $(1023*WORDSIZE), %r10
    mov %r10, PIC(ecall_save_frame_stack_new)
    ret

# Measure the overhead of callee-register-saving
.global ecall_save_frame_overhead
.type ecall_save_frame_overhead @function
ecall_save_frame_overhead:
    SAVE_CALLEE_REGS

    # Do stack switching
    mov %rsp, PIC(ecall_save_frame_stack_original)
    mov PIC(ecall_save_frame_stack_new), %rsp

    # We do not do an actual ecall but just call an empty dummy function
    call ecall_save_frame_dummy
    
    # Do stack switching
    mov %rsp, PIC(ecall_save_frame_stack_new)
    mov PIC(ecall_save_frame_stack_original), %rsp

    RESTORE_CALLEE_REGS
    ret

ecall_save_frame_dummy:
    ret

.bss
.align WORDSIZE

.type ecall_save_frame_stack_original, @object
.size ecall_save_frame_stack_original, 8
ecall_save_frame_stack_original:
.skip 8
.type ecall_save_frame_stack_new, @object
.size ecall_save_frame_stack_new, 8
ecall_save_frame_stack_new:
.skip 8

# bottom of stack
.type ecall_save_frame_stack, @object
.size ecall_save_frame_stack, 1024*WORDSIZE
ecall_save_frame_stack:
.skip 1024*WORDSIZE
