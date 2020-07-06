#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <setjmp.h>
#include <mprotect.h>
#include "pk.h"
#include "pk_debug.h"
#include "test5.h"

pkru_config_t test6_pkru_config;

void test6_segfault_handler(int sig, siginfo_t *si, void *unused) {
  printf("test6_segfault_handler");
  assert(SIGSEGV == sig);

  pkru_config_t pkru_config = _read_pkru_reg();
  printf("PKRU segfault handler:  %lx\n", PKRU_TO_INT(pkru_config));
  if (PKRU_TO_INT(pkru_config) != PKRU_TO_INT(test6_pkru_config)) {
    printf("segfault handler running with wrong PKRU setting\n");
  }

  // Don't forget to unblock the signal
  sigset_t sigset;
  int ret;
  ret = sigemptyset(&sigset); assert(0 == ret);
  ret = sigaddset(&sigset, SIGSEGV); assert(0 == ret);
  ret = sigprocmask(SIG_UNBLOCK, &sigset, NULL); assert(0 == ret);
}

void test6_signals() {
#ifndef PROXYKERNEL
  // Register custom segfault handler
  int ret;
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = test6_segfault_handler;
#ifdef DLU_HOOKING
  // Pre-loading hooks sigaction to pk_sigaction
  ret = sigaction(SIGSEGV, &sa, NULL);
#else
  ret = pk_sigaction(SIGSEGV, &sa, NULL);
#endif
  assert(0 == ret);

  test6_pkru_config = _read_pkru_reg();
  printf("PKRU test6: %lx\n", PKRU_TO_INT(_read_pkru_reg()));
  raise(SIGSEGV);
  printf("PKRU test6: %lx\n", PKRU_TO_INT(_read_pkru_reg()));

  // Deregister handler
  sa.sa_flags = 0;
  sa.sa_handler = SIG_DFL;
  ret = pk_sigaction(SIGSEGV, &sa, NULL);
  assert(0 == ret);
#endif // PROXYKERNEL
}
