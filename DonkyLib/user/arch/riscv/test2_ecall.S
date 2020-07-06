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
    #la  t0, ecall_save_frame_stack
    #li  t1, 1023*WORDSIZE # 8184 # (1023*WORDSIZE)
    #add t0, t0, t1
    #la  t1, ecall_save_frame_stack_new
    #sd  t0, 0(t1)
    ret

# Measure the overhead of callee-register-saving
.global ecall_save_frame_overhead
.type ecall_save_frame_overhead @function
ecall_save_frame_overhead:
    SAVE_CALLEE_REGS

    # Do stack switching

    # # simulated csrrw sp, CSR_USCRATCH, sp
    mv t0, sp # t0 <- sp
    mv sp, t0 # sp <- t0

    csrrw zero, CSR_UEPC, ra # "backing up ra"

    # We do not do an actual ecall but just call an empty dummy function
    call ecall_save_frame_dummy

    # # simulated csrrw sp, CSR_USCRATCH, sp
    mv t0, sp # t0 <- sp
    mv sp, t0 # sp <- t0

    RESTORE_CALLEE_REGS
    #ret
    uret

.type ecall_save_frame_dummy @function
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
