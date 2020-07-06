#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include <mprotect.h>
#include "pk.h"
#include "pk_debug.h"

#ifndef SHARED
extern unsigned char pk_initialized;
#endif

void test1_pkey_alloc() {
  #if __riscv && ! defined PROXYKERNEL
    //skip these tests on riscv-linux for now
    //because it's slow and freeing of keys has an issue
    return;
  #endif

#ifndef SHARED
  assert(pk_initialized);
#endif

  vkey_t keys[PK_NUM_KEYS];
  vkey_t start_offset = -1;
  vkey_t ret;

  //find id of first possible key (for this test)
  start_offset = pk_pkey_alloc(0, 0);
  DEBUG_MPK("start_offset = %d", start_offset);
  assert(VKEY_INVALID != start_offset);
  ret = pk_pkey_free(start_offset);
  DEBUG_MPK("ret = %d", ret);
  assert(0 == ret);
  //start_offset should be roughly 3. pkeys start with 1. pk_init allocates two more keys, one for the root domain and one for the exception handler
  assert(start_offset > 0 && start_offset < 5);
  //start_offset should be 3 if the proxykernel is being userd, otherwsie maybe 4(?) because kernel might allocate 1 key.
  //assert(start_offset == 3);

  // Try to allocate all keys. 
  // This must be the first test.
  for (size_t i = start_offset; i < PK_NUM_KEYS; i++) {
    keys[i] = pk_pkey_alloc(0, 0);
    DEBUG_MPK("Allocated %d\n", keys[i]);
    assert(VKEY_INVALID != keys[i]);
  }
  // The next call shall run out of pkeys
  ret = pk_pkey_alloc(0, 0);
  assert(VKEY_INVALID == ret && errno == ENOSPC);
  // This one should also fail, because all keys are allocated (and not shareable)
  ret = pk_pkey_alloc(PK_KEY_SHARED, 0);
  assert(VKEY_INVALID == ret && errno == ENOSPC);

  // Free all keys again (in reverse order because kernel implementation)
  for (size_t i = PK_NUM_KEYS - 1; i >= start_offset; i--) {
    assert(0 == pk_pkey_free(keys[i]));
    keys[i] = -1;
  }

  // Test sharing of keys
  #define NUM_SHARED_KEYS PK_NUM_KEYS

#if (NUM_SHARED_KEYS + PK_NUM_KEYS) > NUM_KEYS_PER_DOMAIN
#error "Too few keys per domain available to test"
#endif

  vkey_t shared[NUM_SHARED_KEYS];
  // Allocate all but one key
  for (size_t i = start_offset; i < PK_NUM_KEYS-1; i++) {
    keys[i] = pk_pkey_alloc(0, 0);
    DEBUG_MPK("Allocated %d\n", keys[i]);
    assert(VKEY_INVALID != keys[i]);
  }
  // Allocate shared key, which is the last real key
  keys[PK_NUM_KEYS-1] = pk_pkey_alloc(PK_KEY_SHARED, 0);
  assert(VKEY_INVALID != keys[PK_NUM_KEYS-1]);
  // Allocation of an unshared key must fail
  ret = pk_pkey_alloc(0, 0);
  assert(VKEY_INVALID == ret && errno == ENOSPC);
  // Shared keys can still be allocated
  for (size_t i = 0; i < NUM_SHARED_KEYS; i++) {
    shared[i] = pk_pkey_alloc(PK_KEY_SHARED, 0);
    DEBUG_MPK("Allocated shared key %d\n", shared[i]);
    assert(VKEY_INVALID != shared[i]);
  }

  // Free all keys again (in reverse order because kernel implementation)
  //for (size_t i = 0; i < NUM_SHARED_KEYS; i++) {
  for (size_t i = NUM_SHARED_KEYS - 1; i >= 0 && i != (size_t)-1; i--) {
    DEBUG_MPK("Freeing shared key %d\n", shared[i]);
    if(shared[i] == -1) continue;
    assert(0 == pk_pkey_free(shared[i]));
    shared[i] = -1;
  }

  // Free all keys again (in reverse order because kernel implementation)
  //for (size_t i = start_offset; i < PK_NUM_KEYS; i++) {
  for (size_t i = PK_NUM_KEYS - 1; i >= start_offset; i--) {
    DEBUG_MPK("Freeing key %d\n", keys[i]);
    if(keys[i] == -1) continue;
    assert(0 == pk_pkey_free(keys[i]));
    keys[i] = -1;
    //TODO there might be a double-free (which doesnt matter)
  }

  // Keys smaller than the start_offset should not be free-able (unless this test runs in the root domain)
  //for (size_t i = 0; i < start_offset; i++) {
  //  assert(-1 == pk_pkey_free(i));
  //}

  #undef NUM_SHARED_KEYS
}

void test1_api() {
  int did1, did2, did3;
  int pkey1, pkey2, pkey3, pkey4;
  int ret;

  test1_pkey_alloc();

  //--------------------------------------------------------------------
  // test pk_domain_create
  //--------------------------------------------------------------------
  
  // invalid flags
  ret = pk_domain_create(-1);
  assert(ret == -1 && errno == EINVAL);
  ret = pk_domain_create(PK_KEY_OWNER);
  assert(ret == -1 && errno == EINVAL);
  ret = pk_domain_create(PK_KEY_COPY);
  assert(ret == -1 && errno == EINVAL);

  did1 = pk_domain_create(0);
  assert(did1 > 0);

  did2 = pk_domain_create(0);
  assert(did2 > 0 && did1 != did2);

  did3 = pk_domain_create(0);
  assert(did3 > 0 && did2 != did3);

  //--------------------------------------------------------------------
  // test pk_pkey_alloc
  //--------------------------------------------------------------------

  // invalid flags
  ret = pkey_alloc(-1, 0);
  assert(ret == -1 && errno == EINVAL);

  // invalid access_rights
  ret = pkey_alloc(0, 0x8);
  assert(ret == -1 && errno == EINVAL);

  // allocate four pkeys
  pkey1 = pkey_alloc(0, PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE);
  assert(pkey1 > 0);
  // an allocated key belongs to the current domain and can be loaded
  // infinitely often
  ret = pk_domain_load_key(pkey1, PK_SLOT_ANY, 0);
  assert(ret == 0);
  ret = pk_domain_load_key(pkey1, PK_SLOT_ANY, 0);
  assert(ret == 0);
  ret = pk_domain_load_key(pkey1, PK_SLOT_ANY, 0);
  assert(ret == 0);
  ret = pk_domain_load_key(pkey1, PK_SLOT_ANY, 0);
  assert(ret == 0);

  pkey2 = pkey_alloc(0, 0);
  assert(pkey2 > 0 && pkey1 != pkey2);
  ret = pk_domain_load_key(pkey2, PK_SLOT_ANY, 0);
  assert(ret == 0);

  pkey3 = pkey_alloc(0, 0);
  assert(pkey3 > 0 && pkey2 != pkey3);
  ret = pk_domain_load_key(pkey3, PK_SLOT_ANY, 0);
  assert(ret == 0);

  pkey4 = pkey_alloc(0, 0);
  assert(pkey4 > 0 && pkey3 != pkey4);
  ret = pk_domain_load_key(pkey4, PK_SLOT_ANY, 0);
  assert(ret == 0);

  //--------------------------------------------------------------------
  // test pk_domain_load_key
  //--------------------------------------------------------------------
  // test invalid pkey
  ret = pk_domain_load_key(0x7FFFFFFF, PK_SLOT_ANY, 0);
  assert(ret == -1 && errno == EACCES);
  
  // test permission flags
  // key can be loaded multiple times
  ret = pk_domain_load_key(pkey4, PK_SLOT_ANY, 0);
  assert(ret == 0);
  ret = pk_domain_load_key(pkey4, PK_SLOT_ANY, 0);
  assert(ret == 0);
  ret = pk_domain_load_key(pkey4, PK_SLOT_ANY, 0);
  assert(ret == 0);
  ret = pk_domain_load_key(pkey4, PK_SLOT_ANY, 0);
  assert(ret == 0);
  ret = pk_domain_load_key(pkey4, PK_SLOT_ANY, 0);
  assert(ret == 0);
  // invalid flags
  ret = pk_domain_load_key(pkey4, PK_SLOT_ANY, 1);
  assert(ret == -1 && errno == EINVAL);
  ret = pk_domain_load_key(pkey4, PK_SLOT_ANY, -1);
  assert(ret == -1 && errno == EINVAL);

  //--------------------------------------------------------------------
  // test pk_domain_assign_pkey(int did, int pkey, int flags, int access_rights)
  //--------------------------------------------------------------------

  // invalid did
  ret = pk_domain_assign_pkey(100, pkey1, 0, 0);
  assert(ret == -1 && errno == EINVAL);

  // invalid pkey
  ret = pk_domain_assign_pkey(did1, -1, 0, 0);
  assert(ret == -1 && errno == EACCES);

  // invalid flags
  ret = pk_domain_assign_pkey(did1, pkey1, -1, 0);
  assert(ret == -1 && errno == EINVAL);

  // invalid access rights
  ret = pk_domain_assign_pkey(did1, pkey1, 0, -1);
  assert(ret == -1 && errno == EINVAL);

  // assign key to self. Should succeed an arbitrary number of times
  ret = pk_domain_assign_pkey(PK_DOMAIN_CURRENT, pkey1, PK_KEY_OWNER | PK_KEY_COPY, 0);
  assert(ret == 0);
  ret = pk_domain_assign_pkey(PK_DOMAIN_CURRENT, pkey1, PK_KEY_OWNER | PK_KEY_COPY, 0);
  assert(ret == 0);
  // PK_KEY_COPY is redundant when assigning to key to self.
  ret = pk_domain_assign_pkey(PK_DOMAIN_CURRENT, pkey1, PK_KEY_OWNER, 0);
  assert(ret == 0);
  ret = pk_domain_assign_pkey(PK_DOMAIN_CURRENT, pkey1, PK_KEY_OWNER, 0);
  assert(ret == 0);
  // we still have pkey
  ret = pk_domain_load_key(pkey1, PK_SLOT_ANY, 0);
  assert(ret == 0);

  // assign key to self without ownership transfer. Makes the key immutable
  ret = pk_domain_assign_pkey(PK_DOMAIN_CURRENT, pkey1, 0, 0);
  assert(ret == 0);
  // no ownership
  ret = pk_domain_assign_pkey(PK_DOMAIN_CURRENT, pkey1, PK_KEY_OWNER, 0);
  assert(ret == -1 && errno == EACCES);
  // we still have pkey, although without owner permission
  ret = pk_domain_load_key(pkey1, PK_SLOT_ANY, 0);
  assert(ret == 0);

  // copy key to other domains but keep ownership
  ret = pk_domain_assign_pkey(did2, pkey2, PK_KEY_COPY, 0);
  assert(ret == 0);
  ret = pk_domain_assign_pkey(did3, pkey3, PK_KEY_COPY, 0);
  assert(ret == 0);
  // we still have pkey
  ret = pk_domain_load_key(pkey2, PK_SLOT_ANY, 0);
  assert(ret == 0);
  // we still have pkey
  ret = pk_domain_load_key(pkey3, PK_SLOT_ANY, 0);
  assert(ret == 0);

  // migrate key to others
  ret = pk_domain_assign_pkey(did2, pkey4, PK_KEY_OWNER, 0);
  assert(ret == 0);
  // no ownership
  ret = pk_domain_assign_pkey(did3, pkey4, PK_KEY_OWNER, 0);
  assert(ret == -1 && errno == EACCES);
  // we lost access to pkey4
  ret = pk_domain_load_key(pkey4, PK_SLOT_ANY, 0);
  assert(ret == -1 && errno == EACCES);

  //--------------------------------------------------------------------
  // test pk_pkey_free
  //--------------------------------------------------------------------

  // invalid pkey
  ret = pkey_free(-1);
  assert(ret == -1 && errno == EACCES);

  // missing ownership
  ret = pkey_free(pkey1);
  assert(ret == -1 && errno == EACCES);
  ret = pkey_free(pkey4);
  assert(ret == -1 && errno == EACCES);

  #if __riscv && ! defined PROXYKERNEL
    //skip key-freeing, because kernel implementation can only free most recently allocated key for now.
    return;
  #endif

  // key is still in use, but unloaded within free
  ret = pkey_free(pkey2);
  assert(ret == 0);

  // free keys
  //ret = pk_domain_load_key(pkey2, PK_SLOT_NONE, 0);
  //assert(ret == 0);
  //ret = pkey_free(pkey2);
  //assert(ret == 0);
  ret = pk_domain_load_key(pkey3, PK_SLOT_NONE, 0);
  assert(ret == 0);
  ret = pkey_free(pkey3);
  assert(ret == 0);
  // we lost access to pkeys
  ret = pk_domain_load_key(pkey2, PK_SLOT_ANY, 0);
  assert(ret == -1 && errno == EACCES);
  ret = pk_domain_load_key(pkey3, PK_SLOT_ANY, 0);
  assert(ret == -1 && errno == EACCES);

  // double free
  ret = pkey_free(pkey3);
  assert(ret == -1 && errno == EACCES);
  
  // parent can act in place of child
  ret = pk_domain_register_ecall2(did1, PK_ECALL_ANY, test1_api);
  assert(ret >= 0);
  ret = pk_domain_register_ecall2(did1, PK_ECALL_ANY, test1_api);
  assert(ret >= 0);
  // until we release it
  ret = pk_domain_release_child(did1);
  assert(0 == ret);
  ret = pk_domain_release_child(did1);
  assert(-1 == ret && errno == EINVAL);
  ret = pk_domain_register_ecall2(did1, PK_ECALL_ANY, test1_api);
  assert(-1 == ret && errno == EACCES);
}
