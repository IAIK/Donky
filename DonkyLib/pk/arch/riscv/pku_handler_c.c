#include "pk_internal.h"

void* _pk_sa_sigaction_c(int sig, siginfo_t *info, void *ucontext);
__thread unsigned char tls_pku_sigstack[PKU_SIGSTACK_SIZE_BYTES] = {0, };

void __attribute__((naked)) _pk_sa_sigaction_asm(/*sig, info, ucontext*/) {
  // We're entering here either with the caller stack or the sigaltstack
  // In either case, this stack might not be accessible yet since the
  // kernel resets pkru to 0x55555554 (only key 0) during signal handling
  // We need to switch to a special unprotected signal stack (key 0) before
  // calling into C wrapper
  __asm__ volatile(
                                       // use callee-saved registers to
    "mv  s0, a0\n"                     //   save sig
    "mv  s1, a1\n"                     //   save info
    "mv  s2, a2\n"                     //   save ucontext
    "mv  s3, sp\n"                     //   save user stack
    "ld  sp, %0\n"                     // load special signal stack
    "call _pk_sa_sigaction_c\n"
    "mv  a3, a0\n"                     // this is our handler address
    "mv  a0, s0\n"                     // restore sig
    "mv  a1, s1\n"                     // restore info
    "mv  a2, s2\n"                     // restore ucontext
    "mv  sp, s3\n"                     // restore user stack
    "jr  a3\n"                         // call handler(sig, info, ucontext)
    : // no output operands
    : "X"(&tls_pku_sigstack[PKU_SIGSTACK_SIZE_BYTES-2*WORDSIZE])
  );
}
//------------------------------------------------------------------------------
