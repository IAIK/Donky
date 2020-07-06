#include "pk_internal.h"

#ifdef FAKE_MPK_REGISTER

// should be thread-local, but since this is for emulation only, we don't care
pkru_config_t PK_API emulated_mpk_reg = {0,};

#endif

void* _pk_sa_sigaction_c(int sig, siginfo_t *info, void *ucontext);
__thread unsigned char __attribute((tls_model("initial-exec"))) tls_pku_sigstack[PKU_SIGSTACK_SIZE_BYTES] = {0, };

void __attribute__((naked)) _pk_sa_sigaction_asm(/*sig, info, ucontext*/) {
  // We're entering here either with the caller stack or the sigaltstack
  // In either case, this stack might not be accessible yet since the
  // kernel resets pkru to 0x55555554 (only key 0) during signal handling
  // We need to switch to a special unprotected signal stack (key 0) before
  // calling into C wrapper
  __asm__ volatile(
                                       // use callee-saved registers to
    "mov %%rdi, %%r12\n"               //   save sig
    "mov %%rsi, %%r13\n"               //   save info
    "mov %%rdx, %%r14\n"               //   save ucontext
    "mov %%rsp, %%r15\n"               //   save user stack

    "xor %%rax, %%rax \n"
    "xor %%rcx, %%rcx \n"
    "xor %%rdx, %%rdx \n"
    "wrpkru           \n"               // Give full access rights
                                        // (quick-fix for making signal handlers work)
    ::
  );
  __asm__ volatile(
    "mov %0,    %%rsp\n"                // load signal stack. The tls access
                                        // destroys rdi, rsi, rdx, so

    "mov %%r12, %%rdi \n"               //  restore sig
    "mov %%r13, %%rsi \n"               //  restore info
    "mov %%r14, %%rdx \n"               //  restore ucontext
    "call _pk_sa_sigaction_c\n"         // call _pk_sa_sigaction_c(sig, info, ucontext)

    "mov %%r12, %%rdi \n"               // Again, restore sig
    "mov %%r13, %%rsi \n"               // restore info
    "mov %%r14, %%rdx \n"               // restore ucontext
    "mov %%r15, %%rsp \n"               // restore user stack
    "jmpq *%%rax\n"                     // call handler(sig, info, ucontext)
    : // no output operands
    : "X"(&tls_pku_sigstack[PKU_SIGSTACK_SIZE_BYTES-2*WORDSIZE])
  );
}
//------------------------------------------------------------------------------
