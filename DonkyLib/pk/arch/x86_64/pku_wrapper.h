#pragma once

#include "pk.h"
#include <assert.h>

/**
 * C++ wrapper for ecalls
 */
template <class Tclass, class Tret, typename... Targs> class Ecall {
private:
  Tclass* self_;
  int ecall_id_;
  bool exception_;
  int did_;
  Tret (Tclass::*fptr_)(Targs...);

public:
  Ecall(Tclass* self, int did, Tret (Tclass::*fptr)(Targs...)) :
    self_(self),
    ecall_id_(-1),
    exception_(false),
    did_(did),
    fptr_(fptr)
  {
    ecall_id_ = pk_domain_register_ecall2(did_, PK_ECALL_ANY, (void*)&Ecall::ecall_recv);
    if (-1 == ecall_id_) {
      fprintf(stderr,"Error registering ecall");
    }
  }

  /**
   * rdi = this
   */
  Tret InvokeDomainSwitch(Targs... args) __attribute__((noinline)) {
    Tret ret;
    exception_ = false;
    // We hope the compiler did not use args register till now
    asm volatile(
      "push %%rbp       \n"
      "push %%r15       \n"
      "push %%r14       \n"
      "push %%r13       \n"
      "push %%r12       \n"
      "push %%rbx       \n"
      // Commented out since compiler ensures alignment (no naked function)
      //"add $-0x8, %%rsp \n" // to avoid psabi misalignment, we need an odd number of pushes

      // Save first two argument registers on stack since we replace them
      // with type and call id
      "push %%rdi       \n"
      "push %%rsi       \n"

      "mov  $%c1,  %%rdi \n" // TYPE_CALL
      "mov  %2,    %%rsi \n" // ecall_id_

      "call pk_exception_handler@plt \n" // handler will restore rdi/rsi from stack before calling into ecall_recv

      // Cleanup stack
      "add $16, %%rsp   \n"

      // Commented out since compiler ensures alignment (no naked function)
      //"add $0x8, %%rsp  \n" // to avoid psabi misalignment
      "pop %%rbx        \n"
      "pop %%r12        \n"
      "pop %%r13        \n"
      "pop %%r14        \n"
      "pop %%r15        \n"
      "pop %%rbp        \n"
      : "=A"(ret)
      : "i"(TYPE_CALL), "X"((long)ecall_id_)
      : "rdi", "rsi", "rdx", "rcx", "r8", "r9", "memory"
    );
    if (exception_) {
      DEBUG_MPK("Rethrowing exception");
      throw "Domain Exception";
    }
    return ret;
  }

private:

  static Tret ecall_recv_cpp(Ecall* obj, Targs... args) {
    try {
      return ((obj->self_)->*(obj->fptr_))(args...);
    } catch (...) { 
      DEBUG_MPK("Exception caught");
      obj->exception_ = true;
      return (Tret)0;
    }
  }

  static int ecall_get_id(Ecall* obj) {
    return obj->ecall_id_;
  }

  static void ecall_recv() __attribute__((noinline, noreturn)) {
    asm volatile(
      // Commented out since compiler ensures alignment (no naked function)
      //"add $-0x8, %%rsp    \n"  // to avoid psabi misalignment
      "mov %%rdi, %%r12    \n"  // save 'this' pointer
      "callq %P0           \n"  // call ecall_recv_cpp(this, args)
      "mov %%r12, %%rdi    \n"  // restore 'this' pointer
      "mov %%rax, %%r12    \n"  // save ecall_recv_cpp return value
      "mov %%rdx, %%r13    \n"  //
      "callq %P1           \n"  // call ecall_get_id(this)
      "movq $%c2, %%rdi    \n"  // TYPE_RET
      "mov %%rax, %%rsi    \n"  // ecall_id
      "mov %%r12, %%rax    \n"  // restore Ecall return value
      "mov %%r13, %%rdx    \n"  // 
      "add $0x8,  %%rsp    \n"  // to avoid psabi misalignment
      "call pk_exception_handler@plt \n"
      :
      : "X"(ecall_recv_cpp), "X"(ecall_get_id), "i"(TYPE_RET)
    );
    while(1);
  }
};
