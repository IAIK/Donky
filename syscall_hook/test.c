#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include "sysfilter.h"

char __attribute__((aligned(4096))) dummy[4096];
int sysfilter_fd = -1;

void test() {
    char res = 0;
    *(char volatile*)dummy;
    printf("[~] Executing mincore(%p, 4096, %p)\n", dummy, &res);
    int ret = mincore(dummy, 4096, &res);
//     printf("PID: %d\nResult: %d, Cache: %d\n", getpid(), ret, res);
    if(res) printf("[+] Mincore not blocked\n");
    else printf("[-] Mincore blocked\n");
}

void write_pkru(int key) {
    if (1) {
        printf("[~] Writing protection key 0x%x\n", key);
        __asm__ volatile(
          "xor %%ecx, %%ecx\n" // clear ecx
          "xor %%edx, %%edx\n" // clear edx
          "wrpkru"
          : /* no outputs */
          : "a"(key)
          : "rcx", "rdx"
        );
    } else {
        printf("[~] Simluate writing protection key 0x%x\n", key);
        ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_WRITEKEY, key);
    }
}

int main() {
    memset(dummy, 1, sizeof(dummy));

    sysfilter_fd = open(SYSFILTER_DEVICE_PATH, O_RDONLY);
    if (sysfilter_fd < 0) {
        fprintf(stderr, "[-] Error: Could not open Sysfilter device: %s\n", SYSFILTER_DEVICE_PATH);
        return -1;
    }

    printf("[~] Apply filter to current PID: %d\n", getpid());
    ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_PID, getpid());

    printf("[~] Block mincore syscall (syscall number 27)\n");
    ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_BLOCK, 27);

    test();

    write_pkru(0xF0000000);

    printf("[~] Syscall should be blocked, nothing more happens\n");
    test();

    printf("[~] Resetting protection key\n");
    write_pkru(0);
    test();

    printf("[~] Simluate writing protection key 1 and kill on violation\n");
    write_pkru(0xF0000000);
    ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_KILL_ON_VIOLATION, 1);
    test();

    printf("[~] Unblock mincore syscall\n");
    ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_UNBLOCK, 27);
    printf("[~] Remove PID filter\n");
    ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_PID, 0);

    close(sysfilter_fd);
}
