#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include <asm/syscall.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>

#include "sysfilter.h"

MODULE_AUTHOR("Michael Schwarz");
MODULE_DESCRIPTION("Filter syscalls");
MODULE_LICENSE("GPL");

static inline void write_cr0_direct(unsigned long val)
{
  asm volatile("mov %0,%%cr0": "+r" (val), "+m" (__force_order));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && CONFIG_X86_64
#define REGS_DEFINES const struct pt_regs* regs
#define REGS regs
#define SYSNO regs->orig_ax
#else
#define REGS_DEFINES long unsigned int a, long unsigned int b, long unsigned int c, long unsigned int d, long unsigned int e, long unsigned int f
#define REGS a, b, c, d, e, f
#define SYSNO ???
#error "Old linux does not provide us with syscall number"
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define from_user raw_copy_from_user
#define to_user raw_copy_to_user
#else
#define from_user copy_from_user
#define to_user copy_to_user
#endif

static bool device_busy = false;
static int pid_filter = 0;
static int has_pke = 0;
static int pkey = 0;
static uint32_t pkru_init_value = 0;
static int kill_on_violation = 0;

// ---------------------------------------------------------------------------
static int device_open(struct inode *inode, struct file *file) {
  /* Check if device is busy */
  if (device_busy == true) {
    return -EBUSY;
  }

  /* Lock module */
  try_module_get(THIS_MODULE);

  device_busy = true;

  return 0;
}

// ---------------------------------------------------------------------------
static int device_release(struct inode *inode, struct file *file) {
  /* Unlock module */
  device_busy = false;

  module_put(THIS_MODULE);

  return 0;
}

// ---------------------------------------------------------------------------
static sys_call_ptr_t old_sys_call_table[__NR_syscall_max];
static sys_call_ptr_t* syscall_tbl;

// ---------------------------------------------------------------------------
static int readkey(void) {
    size_t key = 0;
    if(has_pke) {
        asm volatile(
            "RDPKRU\n"
            "mov %%rax, %0\n"
            : "=r"(key) : "a"(0), "c"(0), "d"(0) : "memory");
    } else {
        key = pkey;
    }
    return (key & 0xffffffff);
}

// ---------------------------------------------------------------------------
static long hook_generic(REGS_DEFINES) {
    int pid = task_pid_nr(current);
    int sys_nr = SYSNO;

    if(pid_filter && pid == pid_filter) {
        int k = readkey();
        if(k != pkru_init_value && k != 0) {
            printk("Blocked syscall %d (PID: %d) (k: 0x%x)\n", sys_nr, pid, k);
            if(kill_on_violation) kill_pid(find_vpid(pid_filter), 2, 1);
            return 0;
        }
    }
    return old_sys_call_table[sys_nr](REGS);
}

// ---------------------------------------------------------------------------
static void hook_syscall(int nr, sys_call_ptr_t hook) {
    // unprotect syscall table
    write_cr0_direct(read_cr0() & ~0x10000);
    printk("[sysfilter-module] Hooking syscall %d\n", nr);
    syscall_tbl[nr] = hook;
    write_cr0_direct(read_cr0() | 0x10000);
}

// ---------------------------------------------------------------------------
static void unhook_syscall(int nr) {
    // unprotect syscall table
    write_cr0_direct(read_cr0() & ~0x10000);
    printk("[sysfilter-module] Unhooking syscall %d\n", nr);
    syscall_tbl[nr] = old_sys_call_table[nr];
    write_cr0_direct(read_cr0() | 0x10000);
}

// ---------------------------------------------------------------------------
static long device_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param) {
  switch (ioctl_num) {
    case SYSFILTER_IOCTL_CMD_BLOCK:
    {
        hook_syscall(ioctl_param, hook_generic);
        return 0;
    }
    case SYSFILTER_IOCTL_CMD_UNBLOCK:
    {
        unhook_syscall(ioctl_param);
        return 0;
    }
    case SYSFILTER_IOCTL_CMD_PID:
    {
        pid_filter = ioctl_param;
        return 0;
    }
    case SYSFILTER_IOCTL_CMD_WRITEKEY:
    {
        pkey = ioctl_param;
        return 0;
    }
    case SYSFILTER_IOCTL_CMD_KILL_ON_VIOLATION:
    {
        kill_on_violation = ioctl_param;
        return 0;
    }
    default:
        return -1;
  }

  return 0;
}

// ---------------------------------------------------------------------------
static struct file_operations f_ops = {.unlocked_ioctl = device_ioctl,
                                       .open = device_open,
                                       .release = device_release};

// ---------------------------------------------------------------------------
static struct miscdevice misc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = SYSFILTER_DEVICE_NAME,
    .fops = &f_ops,
    .mode = S_IRWXUGO,
};

// ---------------------------------------------------------------------------
int init_module(void) {
  int r, i;

  // check for PKE
  has_pke = !!(native_read_cr4() & (1ull << 22));
  printk(KERN_INFO "[sysfilter-module] PKE: %d\n", has_pke);

  if(has_pke) {
    // get initial pkru
      uint32_t* pkru_init = (uint32_t*)kallsyms_lookup_name("init_pkru_value");
      if(pkru_init) {
        pkru_init_value = *pkru_init;
      }
  }

  // register device
  r = misc_register(&misc_dev);
  if (r != 0) {
    printk(KERN_ALERT "[sysfilter-module] Failed registering device with %d\n", r);
    return 1;
  }

  syscall_tbl = (sys_call_ptr_t*)kallsyms_lookup_name("sys_call_table");
  printk("[sysfilter-module] Syscall table @ %zx\n", (size_t)syscall_tbl);

  // backup old sys call table
  for(i = 0; i < __NR_syscall_max; i++) {
      old_sys_call_table[i] = syscall_tbl[i];
  }

  printk(KERN_INFO "[sysfilter-module] Loaded.\n");

  return 0;
}

// ---------------------------------------------------------------------------
void cleanup_module(void) {
  int i;
  misc_deregister(&misc_dev);

  // restore old syscall table
  write_cr0_direct(read_cr0() & ~0x10000);
  for(i = 0; i < __NR_syscall_max; i++) {
      syscall_tbl[i] = old_sys_call_table[i];
  }
  write_cr0_direct(read_cr0() | 0x10000);

  printk(KERN_INFO "[sysfilter-module] Removed.\n");
}
