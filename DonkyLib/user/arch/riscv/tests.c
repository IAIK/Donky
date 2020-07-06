#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "test2_ecall.h"
#include "pk.h"

//TODO ecall_register_test2 and test2 must be unprotected

void ecall_register_test2(int dom) {
    ecall_register_test_args(dom);
    ecall_register_test_api_calls(dom);
    ecall_register_test_kill_all_regs(dom);
}

void test2() {
    //----------------------------------------------------------------------------
    // Test if function arguments / return values are passed correctly
    printf("Calling ecall_test_args\n");
    uint64_t ret;

    ret = ecall_test_args(0x10, 0x11, 0x12, 0x13, 0x14, 0x15);

    printf("ecall_test_args returned %lx\n", ret);
    assert(ret == 0xAABBCCDD00112233ULL);

    //----------------------------------------------------------------------------
    // Test if callee-saved registers are preserved by wrapper in case a
    // malicious ecall target does not preserve them
    printf("Calling ecall_test_kill_all_regs\n");
    ret = (uint64_t)ecall_test_kill_all_regs();
    assert(ret == 0xF0);


    //----------------------------------------------------------------------------
    // Test API calls within an ecall
    printf("Calling ecall_test_api_calls\n");
    ecall_test_api_calls();
}
