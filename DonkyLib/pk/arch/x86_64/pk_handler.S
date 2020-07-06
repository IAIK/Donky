#define __ASSEMBLY__
#include "pk_internal.h"

#------------------------------------------------------------------------------
.section .pk,"a",@progbits

.global pk_exception_handler              # Externally visible
.type   pk_exception_handler, @function
pk_exception_handler:

.type   _pk_exception_handler, @function
_pk_exception_handler:                    # For internal rip-relative addressing

#clear status flags (see A Tale of Two Worlds)
cld # clear direction flag (for string operations)

#ifndef FAKE_MPK_REGISTER
    # We're currently still on the unprotected user stack
    # we need to save/restore rax,rcx,rdx because they're 
    # return values and arguments for ecalls/ocalls
    push %rax
    push %rcx
    push %rdx
    xor %ecx, %ecx  # must be 0 for wrpkru
    xor %edx, %edx  # must be 0 for wrpkru
    xor %eax, %eax  # eax holds pkru value, which is also 0 to give
    wrpkru          # full permissions to exception handler
                    # Now, trusted TLS can be accessed
    pop %rdx
    pop %rcx
    pop %rax
#endif
    # TODO: implement fs-swap in userspace
    # https://github.com/occlum/enable_rdfsbase

    # r10/r11 are caller-saved, so we can freely use them

    # save user stack pointer and switch to exception stack
    # both are located on trusted TLS

    mov PIC(_pk_ttls_offset), %r10
    # maybe this should only need to run in init?
    test %r10, %r10
    jz _pk_assert

    mov %rsp, %r11       # keep a copy of user stack in %r11
    mov %rsp, %fs:(%r10) # store user stack on %fs:(_pk_ttls_offset+0)
    add $8, %r10
    mov %fs:(%r10), %rsp # load exception stack from %fs:(_pk_ttls_offset+8)

    ####################################################################
    # From now on, we operate on the exception stack
    # Since our exception stack is always 16-byte aligned (psabi),
    # we need to push/pop an even number of times before doing C-calls
    #
    # The original user stack is available under %r11
    ####################################################################

    # Test type
    cmp $(TYPE_CALL), rdi_type
    je _pk_handle_ecall
    cmp $(TYPE_RET),  rdi_type
    je _pk_handle_eret
    cmp $(TYPE_API),  rdi_type
    je _pk_handle_apicall
    # TODO: handle normal exceptions with rdi_type=TYPE_EXCEPTION
    jmp _pk_assert

    #####################################
    # dispatch API calls
    #####################################
_pk_handle_apicall:

    cmp $(API_TABLE_SIZE), rsi_id
    jge _pk_assert

    # Load correct API function pointer into %r10
    shl $3, rsi_id                # Multiply id with WORDSIZE
    lea PIC(_pk_api_table), %r10  # Load API table
    add rsi_id, %r10              # Find correct entry

    # Restore original API arguments from user stack
    mov 16(%r11), %rdi # restore arg1
    mov  8(%r11), %rsi # restore arg2
                       # arg3 ... arg6 are unmodified

    # Do actual API call
    call *(%r10)

    # Preserve return value of API call
    push %rax          # store return register 1
    push %rdx          # store return register 2

    call PCREL(_prepare_pkru_for_swap)

    jmp _pk_exception_handler_end_with_pushed_rax_rdx
    #pop %rdx
    #pop %rax
    #jmp _pk_exception_handler_end

    #####################################
    # Dispatch ECALL
    #####################################
_pk_handle_ecall:

    # TODO: save and restore callee registers properly, since we cannot rely on the target
    # domain to properly preserve them.

    # Store caller-saved registers for c-function call
                       # arg1 is on user stack
                       # arg2 is on user stack
    push %rcx          # store arg3
    push %rdx          # store arg4
    push %r8           # store arg5
    push %r9           # store arg6
    push %r11          # store user stack of caller
    add $-0x8, %rsp    # to avoid psabi misalignment

    call PCREL(_pk_exception_handler_arch_c)
    call PCREL(_prepare_pkru_for_swap)

    add $0x8, %rsp     # to avoid psabi misalignment
    pop %r11           # restore user stack pointer of caller
    pop %r9            # restore arg6
    pop %r8            # restore arg5
    pop %rdx           # restore arg4
    pop %rcx           # restore arg3
    mov  8(%r11), %rsi # restore arg2
    mov 16(%r11), %rdi # restore arg1

    jmp _pk_exception_handler_end

    #####################################
    # Dispatch ERET (return from ECALL)
    #####################################
_pk_handle_eret:

    # Store caller-saved return registers for c-function call
    push %rax          # store return register 1
    push %rdx          # store return register 2

    call PCREL(_pk_exception_handler_arch_c)
    call PCREL(_prepare_pkru_for_swap)

    jmp _pk_exception_handler_end_with_pushed_rax_rdx
    #pop %rdx
    #pop %rax
    #jmp _pk_exception_handler_end

.global _pk_exception_handler_end
_pk_exception_handler_end:
    push %rax
    push %rdx 
_pk_exception_handler_end_with_pushed_rax_rdx:

    mov  %rsp, %rdx                  # keep our exception stack
    mov PIC(_pk_ttls_offset), %rax   # restore user stack pointer
    mov %fs:(%rax), %rsp             # restore user stack

    ####################################################################
    # We are back on the user stack
    # The exception stack is still accessible under %rdx
    ####################################################################

    # TODO: ensure that user stack has enough space for 4 slots!

    # Before doing the PKRU switch, push original %rax and %rdx
    # from exception stack to user stack
    # Since we still have access to user stack after updating PKRU, 
    # we can restore them afterwards

    push 8(%rdx)          # original %rax
    push 0(%rdx)          # original %rdx

#ifndef FAKE_MPK_REGISTER 
    push %rcx

    add $24, %rax         # Load current_pkru value into rax
    mov %fs:(%rax), %rax  # from the third slot of pk_trusted_tls
    xor %ecx, %ecx        # must be 0 for wrpkru
    xor %edx, %edx        # must be 0 for wrpkru
    wrpkru

    ####################################################################
    # now we don't have access to exception stack anymore
    ####################################################################

    pop %rcx
#endif
    pop %rdx
    pop %rax

    return_from_exception

_pk_assert:
    # Prepare an assert frame with all registers on the _pk_assert_stack
    mov %rsp, PIC(_pk_assert_stack_top-8)   # Save rsp before switching stack
    lea PIC(_pk_assert_stack_top-8), %rsp   # Switch to _pk_assert_stack
    push %rbp
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15
    mov %rsp, %rdi
    #add $-8, %rdi
    jmp _pk_assert_c
    DIE

.global pk_do_init
.type   pk_do_init, @function
pk_do_init:
    # Call _pk_init
    add $-0x8, %rsp       # to avoid psabi misalignment
    call PCREL(_pk_init)
    add $0x8, %rsp       # to avoid psabi misalignment

    test %rax, %rax
    jnz pk_do_init_end

    # Load current_pkru config
    call PCREL(_prepare_pkru_for_swap)

#ifndef FAKE_MPK_REGISTER
    # We are in a weird situation now: 
    # * _pk_init operated on the thread stack rather than the exception stack
    # * _pk_init directly returned to us instead of the pk_exception_handler
    # So, we must take care to configure pkru properly ourselves
    # We still have full pkru access to all allocated keys
    # This is no problem, as an attacker that tampers with this code
    # could also have tampered with the protection handler before it is
    # properly initialized

    mov PIC(_pk_ttls_offset), %rax
    add $24, %rax         # Load current_pkru value into rax
    mov %fs:(%rax), %rax  # from the third slot of pk_trusted_tls
    xor %ecx, %ecx        # must be 0 for wrpkru
    xor %edx, %edx        # must be 0 for wrpkru
    wrpkru

    ####################################################################
    # now we don't have access to protection handler anymore
    ####################################################################
    xor %rax, %rax        # return 0
#endif
pk_do_init_end:
    return_from_exception

.bss
.align WORDSIZE
# bottom of stack
.type _pk_assert_stack, @object
.size _pk_assert_stack, 1024*WORDSIZE
_pk_assert_stack:
.skip 1024*WORDSIZE

# end of stack (exclusive)
.type _pk_assert_stack_top, @object
.size _pk_assert_stack_top, 8
_pk_assert_stack_top:

