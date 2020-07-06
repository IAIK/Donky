#include "pk_internal.h"
#include "mprotect.h"

//------------------------------------------------------------------------------
#ifdef FAKE_MPK_REGISTER
pkru_config_t emulated_mpk_reg;
#endif /* FAKE_MPK_REGISTER */
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
// Public API functions
//------------------------------------------------------------------------------
extern unsigned char pk_initialized; //TODO move pk_init to pku_...
int __attribute__((naked)) pk_do_init(){
    asm volatile (
        // call _pk_init, remember old ra
        "addi     sp,sp,-8;"
        "sd       ra,0(sp);" //save ra
        "call     _pk_init;"

        //set pk_initialized to 1
        "la       ra, %[initialized];" //temporarily misuse ra register for address of pk_initialized
        "li       a0, 1;"
        "sb       a0, 0(ra);" //pk_initialized = 1;


        "ld       ra,0(sp);" //restore ra
        "addi     sp,sp,8;"  //remove stack frame


        //set return value to 0
        "li       a0,0;"
        //Set uepc to ra (previous return address)
        //and do a uret, such that we lock ourselves out.
        //"csrrw zero, %1, ra;"
        "csrrw zero, %[uepc], ra;"
        "uret;"

        :  : [initialized] "X"(&pk_initialized), [uepc] "i"(CSR_UEPC)
    );
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Internal untrusted functions
//------------------------------------------------------------------------------
int _pk_halt() {
  ERROR("_pk_halt: No exception handler installed. Do not know how to proceed!");
  _pk_print_debug_info();
  print_maps();
  assert(false);
}

//------------------------------------------------------------------------------
// Internal trusted functions
//------------------------------------------------------------------------------
int PK_CODE _pk_init_arch() {

    uint64_t misa = CSRR(CSR_UMISA);
    char misa_str[27] = {0, };
    char* str_p = misa_str;
    for (size_t i = 0; i < 26; i++) {
        if ( misa & (1 << i) ) {
            *str_p++ = 'a' + i;
        }
    }
    DEBUG_MPK("misa = %zx = %s", misa, misa_str);
    assert( misa & (1 << ('u' - 'a')) );
    assert( misa & (1 << ('s' - 'a')) );
    assert( misa & (1 << ('i' - 'a')) );
    assert( misa & (1 << ('m' - 'a')) );
    assert( misa & (1 << ('a' - 'a')) );
    assert( misa & (1 << ('c' - 'a')) );
    assert( misa & (1 << ('n' - 'a')) );

    //check if utvec table is protected
#ifndef SHARED
    DEBUG_MPK("pk_utvec_table  = %p", ((char*)&pk_utvec_table));
    assert( ((uintptr_t*)&pk_utvec_table) >= __start_pk_all);
    assert( ((uintptr_t*)&pk_utvec_table) < __stop_pk_all);
    assert( ((uintptr_t*)&pk_utvec_table) >= __start_pk_code);
    assert( ((uintptr_t*)&pk_utvec_table) < __stop_pk_code);
#endif

    // check pkru register
    pkru_config_t reg = _read_pkru();
    //_print_reg(reg);
    //assert_warn(reg.mode == 1);
    //if(reg.mode != 1){
    //    reg.mode = 1;
    //    _write_pkru(reg);
    //    reg = _read_pkru();
    //}

#ifndef FAKE_MPK_REGISTER
    assert(reg.mode == 1);
#endif

    //reset pkru
    reg = pk_data.domains[_pk_current_did()].default_config;
    assert(reg.sw_did == DID_FOR_ROOT_DOMAIN);
    assert(reg.mode == 1);
    _write_pkru(reg);
    DEBUG_MPK("_pk_init_arch end");
    return 0;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
// Internal functions
//------------------------------------------------------------------------------

void PK_CODE _pk_setup_exception_stack_arch(void* exception_stack) {
    pk_trusted_tls.exception_stack_base = exception_stack;
    pk_trusted_tls.exception_stack = (uint64_t*)exception_stack + EXCEPTION_STACK_WORDS - 2;
    //-2 because the stack must be aligned by 128-bit according to the RISC-V psABI spec
    assert_warn(CSRR(CSR_USCRATCH) == 0);
    CSRW(CSR_USCRATCH, pk_trusted_tls.exception_stack);
}
//------------------------------------------------------------------------------

void PK_CODE _pk_setup_exception_handler_arch() {
    // lowest bit must be set to use vectored exceptions
    uint64_t utvec = (uint64_t)&pk_utvec_table | 1;
    assert_warn(CSRR(CSR_UTVEC) == 0);
    CSRW(CSR_UTVEC, utvec);
}
//------------------------------------------------------------------------------

void PK_CODE _pk_setup_domain_arch(int did, pkey_t pkey) {
    assert_ifdebug(pkey > 0 && pkey < PK_NUM_KEYS);

    // set default reg value
    // Note: setting mode to 1, otherwise we'd lock ourselves out
    // when we write the register. Mode will be set to zero with the
    // uret instruction
    pk_data.domains[did].default_config.mode         = 1;
    pk_data.domains[did].default_config.sw_did       = did;
    if (did != DID_FOR_EXCEPTION_HANDLER){
        //the key only gets set for normal domains
        //otherwise we'd still have the exception handler's key loaded when
        //returning to "the root" where the exception handler was registered
        pk_data.domains[did].default_config.slot_0_mpkey = pkey;
    }
}
//------------------------------------------------------------------------------

bool PK_CODE _pk_is_key_loaded_arch(pkey_t pkey) {

    assert_ifdebug(pkey > 0 && pkey < PK_NUM_KEYS);

    for (size_t tid = 0; tid <  NUM_THREADS; tid++) {
        if (NULL == pk_data.threads[tid]) {
            continue;
        }
        assert(pk_data.threads[tid]->init);
        pkru_config_t pkru = pk_data.threads[tid]->current_pkru;
        if (pkru.slot_0_mpkey == pkey ||
            pkru.slot_1_mpkey == pkey ||
            pkru.slot_2_mpkey == pkey ||
            pkru.slot_3_mpkey == pkey) {

            WARNING("_pk_domain_is_key_loaded_arch: thread[%zu] has key %d loaded", tid, pkey);
            errno = EPERM;
            return -1;
        }
    }
    return 0;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_load_key_arch(int did, pkey_t pkey, int slot, int perm) {
    DEBUG_MPK("_pk_domain_load_key_arch(%u, %d, %d)", pkey, slot, perm);

    assert_ifdebug(pkey > 0 && pkey < PK_NUM_KEYS);

    if (slot != PK_SLOT_ANY && slot != PK_SLOT_NONE) {
        ERROR("Invalid slots");
        errno = EINVAL;
        return -1;
    }

    if ( perm & ~(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE) ) {
        ERROR("Invalid permissions. Only supports PKEY_DISABLE_ACCESS and PKEY_DISABLE_WRITE");
        errno = EINVAL;
        return -1;
    }

    if (PK_SLOT_NONE == slot) {
        // By disabling access, key is unloaded
        perm = PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE;
    }

    pkru_config_t pkru_old;
    if (did == CURRENT_DID) {
      pkru_old = _read_pkru();
    } else {
      pkru_old = pk_data.domains[did].default_config;
    }

    // try to reuse existing pkey
    if (pkru_old.slot_0_mpkey == pkey) {
      slot = 0;
    } else if (pkru_old.slot_1_mpkey == pkey) {
      slot = 1;
    } else if (pkru_old.slot_2_mpkey == pkey) {
      slot = 2;
    } else if (pkru_old.slot_3_mpkey == pkey) {
      slot = 3;
    }

    if (slot == PK_SLOT_NONE){
        DEBUG_MPK("Key not loaded. Nothing to do");
        return 0;
    }

    if (PK_SLOT_ANY == slot) {
      //get actual slot number
      int * previous_slot = &(pk_data.domains[CURRENT_DID].previous_slot);
      slot = (*previous_slot % 3) + 1; //0th slot is always the default key
      //DEBUG_MPK("_pk_domain_load_key_arch: previous_slot = %d new = %d", *previous_slot, slot);
      *previous_slot = slot;
      DEBUG_MPK("Updating slot %d", slot);
    } else {
      DEBUG_MPK("Reusing slot %d", slot);
    }

    // prepare new pkru value
    int wd = (perm & PKEY_DISABLE_WRITE) ? 1 : 0;
    uint64_t key_mask = (uint64_t)0b11111111111ULL << (slot * 11);
    uint64_t key_val  = (uint64_t)((uint64_t)pkey | ((uint64_t)wd << 10)) << (slot * 11);

    //0th slot is always the default key. 
    assert_ifdebug((slot > 0 && slot < 4) || (slot == 0 && pkru_old.slot_0_wd == wd));
    // slot 0 is (only) allowed if nothing would change
    //Because for some reason assign_key is called (by our tests) with the key that's already in slot 0


    // erase key slot
    uint64_t      tmp = PKRU_TO_INT(pkru_old) & ~key_mask;

    if (!(perm & PKEY_DISABLE_ACCESS)) {
      // set new protection key
      tmp |= key_val;
    }
    pkru_config_t pkru_new = INT_TO_PKRU(tmp);

    assert_ifdebug(pkru_new.mode      == pkru_old.mode);
    assert_ifdebug(pkru_new.sw_did    == pkru_old.sw_did);
    assert_ifdebug(pkru_new.sw_unused == pkru_old.sw_unused);

    #ifndef RELEASE
    DEBUG_MPK("Updating PKRU from");
    pk_print_reg_arch(pkru_old);
    DEBUG_MPK("to");
    pk_print_reg_arch(pkru_new);
    #endif

    if (perm & PKEY_DISABLE_ACCESS) {
      assert_ifdebug(pkru_new.slot_0_mpkey != pkey);
      assert_ifdebug(pkru_new.slot_1_mpkey != pkey);
      assert_ifdebug(pkru_new.slot_2_mpkey != pkey);
      assert_ifdebug(pkru_new.slot_3_mpkey != pkey);
    } else {
      //checking bit-mask magic
      assert_ifdebug((slot == 0 && pkru_new.slot_0_mpkey == pkey && pkru_new.slot_0_wd == wd) || pkru_new.slot_0_mpkey == pkru_old.slot_0_mpkey);
      assert_ifdebug((slot == 0 && pkru_new.slot_0_mpkey == pkey && pkru_new.slot_0_wd == wd) || pkru_new.slot_0_wd    == pkru_old.slot_0_wd);
      assert_ifdebug((slot == 1 && pkru_new.slot_1_mpkey == pkey && pkru_new.slot_1_wd == wd) || pkru_new.slot_1_mpkey == pkru_old.slot_1_mpkey);
      assert_ifdebug((slot == 1 && pkru_new.slot_1_mpkey == pkey && pkru_new.slot_1_wd == wd) || pkru_new.slot_1_wd    == pkru_old.slot_1_wd);
      assert_ifdebug((slot == 2 && pkru_new.slot_2_mpkey == pkey && pkru_new.slot_2_wd == wd) || pkru_new.slot_2_mpkey == pkru_old.slot_2_mpkey);
      assert_ifdebug((slot == 2 && pkru_new.slot_2_mpkey == pkey && pkru_new.slot_2_wd == wd) || pkru_new.slot_2_wd    == pkru_old.slot_2_wd);
      assert_ifdebug((slot == 3 && pkru_new.slot_3_mpkey == pkey && pkru_new.slot_3_wd == wd) || pkru_new.slot_3_mpkey == pkru_old.slot_3_mpkey);
      assert_ifdebug((slot == 3 && pkru_new.slot_3_mpkey == pkey && pkru_new.slot_3_wd == wd) || pkru_new.slot_3_wd    == pkru_old.slot_3_wd);
      // pkey is loaded exactly once
      assert_ifdebug((pkru_new.slot_0_mpkey == pkey) + (pkru_new.slot_1_mpkey == pkey) + (pkru_new.slot_2_mpkey == pkey) + (pkru_new.slot_3_mpkey == pkey) == 1);
    }

    //update register
    if (did == CURRENT_DID) {
      _write_pkru(pkru_new);
    } else {
      pk_data.domains[did].default_config = pkru_new;
    }
    return 0;
}
//------------------------------------------------------------------------------

// Ensure that _expected_return stack is not 16-byte but 8-byte aligned
// This ensures that user stack gets 16-byte aligned for psabi
// See _pk_exception_handler_arch_c
C_STATIC_ASSERT((sizeof(_expected_return) % 16) == 8);
C_STATIC_ASSERT((sizeof(_return_did)      % 16) == 8);

uint64_t PK_CODE _pk_exception_handler_arch_c(uint64_t data, uint64_t id, uint64_t type){
#if defined(TIMING) && TIMING_HANDLER_C != 0
    if(type == TIMING_HANDLER_C_TYPE)
        TIME_START(TIMING_HANDLER_C);
#endif

    int ret = type; //TODO this may no longer be necessary

    _pk_acquire_lock();

    DEBUG_MPK("_pk_exception_handler_arch_c(data=%zu, id=%zu, type=%zu=%s) uepc=0x%lx, utval=0x%lx, ucause=0x%lx, uscratch=0x%lx", 
        data, id, type, type_str(type),
        CSRR(CSR_UEPC), CSRR(CSR_UTVAL), CSRR(CSR_UCAUSE), CSRR(CSR_USCRATCH));

    #ifdef ADDITIONAL_DEBUG_CHECKS
        //register uint64_t* sp asm("sp");
        //assert(sp >= pk_data.exception_stack && sp < EXCEPTION_STACK_TOP);
        assert_warn(CSRR(CSR_UCAUSE) == CAUSE_MPKEY_MISMATCH_FAULT);
        assert_warn(_read_pkru().mode == 1);

        //this is already asserted in assembly
        assert(type == TYPE_EXCEPTION || (void*)CSRR(CSR_UTVAL) == &_pk_exception_handler);

        //if(type != TYPE_CALL && type != TYPE_RET){
        //    PRINT_UREGS();
        //}
    #endif

    uint64_t * stack_of_caller = (uint64_t*)CSRR(CSR_USCRATCH);
    void * reentry = (void*)CSRR(CSR_UEPC);

    /*
    #ifdef ADDITIONAL_DEBUG_CHECKS
	//check for correct stack alignment
        if (type == TYPE_CALL) {
            assert((reentry % 16) == 8); // check stack misaligned
        }else{
            assert(((uintptr_t)stack_of_caller % 16) == 0); // check stack misaligned
        }
    #endif
    */


    if(unlikely(type == TYPE_EXCEPTION)){
        void * target_code = _pk_halt;
        void * bad_addr = (void*)CSRR(CSR_UTVAL);
        ret = 0;

        // Try to resolve key mismatch
        if (0 == _pk_exception_key_mismatch_unlocked(bad_addr)) {
            // key exception resolved
            ret = 0;
            goto end;
        }

        //Instead of halting, invoker user exception handler if it was registered.
        if (pk_data.user_exception_handler) {
            DEBUG_MPK("Invoking user exception handler");
            target_code = pk_data.user_exception_handler;
            //Call target code (without changing the current domain)
            pkru_config_t config = _read_pkru();
            _pk_domain_switch_arch(TYPE_EXCEPTION, CURRENT_DID, config, target_code, stack_of_caller);
            // By returning a non-zero value, the assembler wrapper will
            // pass CSR_UTVAL in a0 to target_code
            ret = 1;
        }else{
            //(target_code == _pk_halt)
            //in this case the below code with _pk_domain_switch_arch does not work
            //it would throw exceptions in an infinite loop because the current domain doesn't have access to the code of _pk_halt.
            //we could handle it like an API call, or simply call it directly
            _pk_halt();
            assert(false);
        }

    }else{
        _pk_exception_handler_unlocked(data, id, type, stack_of_caller, reentry);
    }

end:
    _pk_release_lock();

#if defined(TIMING) && TIMING_HANDLER_C != 0
    if(type == TIMING_HANDLER_C_TYPE)
        TIME_STOP(TIMING_HANDLER_C);
#endif

    return ret;
}
//------------------------------------------------------------------------------

void PK_CODE _pk_domain_switch_arch(int type, int target_did, pkru_config_t config, void* entry_point, uint64_t* target_stack) {
    DEBUG_MPK("_pk_domain_switch_arch(%d, %d, %p, %p)", type, target_did, entry_point, target_stack);

    //actual switch: write pkru,uepc,uscratch
    _write_pkru(config);
    CSRW(CSR_UEPC,     entry_point);
    CSRW(CSR_USCRATCH, target_stack);

    //check if the domain-transition was successful
    assert_ifdebug(_pk_current_did() == target_did);
    //When returning to the root-domain, there should not be any old keys loaded
    //assert_ifdebug(target_did != 0 || CSRR(CSR_MPK) == 0x8000000000000000LL);
    //Default key for target domain should be loaded
    assert_ifdebug(_read_pkru().slot_0_mpkey == pk_data.domains[target_did].default_config.slot_0_mpkey);
}
//------------------------------------------------------------------------------

void* PK_CODE __attribute__((naked)) _pthread_init_function_asm(void *arg) {
  // We're entering here with the new user stack but in trusted mode
  // switch to trusted exception stack and call into C wrapper
  // Note: Using s0 as arg for start_routine because it's preserved across calls
  asm volatile(
    "mv  s3, a1\n"                    // save a1

    "ld  a0, %0\n"                    // save start_routine as first argument in a0
    "mv  a1, sp\n"                    // save current_user_stack as second argument a1
    "ld  sp, %1\n"                    // load exception stack
    "ld  s0, %2\n"                    // load *arg for start_routine into callee-saved register (s0)
    //"mv  s1, ra\n"                    // save ra to s1 (which is callee-saved)
    "call _pthread_init_function_c\n" // _pthread_init_function_c(start_routine, current_user_stack)
    "mv  a0, s0\n"                    // load *arg as first argument for start_routine
    //"mv  ra, s1\n"                    // restore ra which was previously saved to s1. it should probably point to pthread_exit or similar
    "la ra, pthread_exit\n"           // For some reason the old ra doesnt work here, so we just set it to pthread_exit instead
    "mv  a1, s3\n"                    // restore a1
    "j _pk_exception_handler_end\n"
    : // no output operands
    : "m"(pk_data.pthread_arg.start_routine),
      "m"(pk_data.pthread_arg.exception_stack_top),
      "m"(pk_data.pthread_arg.arg)
  );
}
//------------------------------------------------------------------------------
