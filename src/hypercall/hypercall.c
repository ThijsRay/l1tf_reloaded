// You can only do hypercalls from ring 0, so this has to be a kernel module

#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/types.h>

#include <linux/kvm_para.h>

#include "hypercall.h"

#define procfs_name "ipi_hypercall"
static struct proc_dir_entry *proc_entry;

// Up to four arguments may be passed in rbx, rcx, rdx, and rsi respectively.
// The hypercall number should be placed in rax and the return value will be
// placed in rax. No other registers will be clobbered unless explicitly
// stated by the particular hypercall.
uint64_t inline hypercall(int type, uint64_t a0, uint64_t a1, uint64_t a2,
                          uint64_t a3) {
  uint64_t rax = type;
  asm volatile("movq $0, %%rcx\n"
               "cmpq $0, %%rcx\n"
               ".rept 300\n" // TODO: optimize this, maybe 300 is to much?
               "je 1f\n"
               "1:\n"
               ".endr\n" ::
                   : "rcx");

  asm volatile("vmcall" : "+a"(rax), "+b"(a0), "+c"(a1), "+d"(a2), "+S"(a3));
  return rax;
}

// a0: lower part of the bitmap of destination APIC IDs
// a1: higher part of the bitmap of destination APIC IDs
// a2: the lowest APIC ID in bitmap
// a3: APIC ICR
int send_ipi(unsigned long ipi_bitmap_low, unsigned long ipi_bitmap_high,
             uint32_t min, unsigned long icr) {
  return hypercall(KVM_HC_SEND_IPI, ipi_bitmap_low, ipi_bitmap_high, min, icr);
}

static ssize_t procfile_write(struct file *file, const char __user *buff,
                              size_t len, loff_t *off) {
  // kvm_sched_yield(len);
  // return len;
  int count = 0;
  struct hypercall_opts opts = {0};

  // Make sure that only the size of the struct is written
  if (len != sizeof(opts)) {
    return -EINVAL;
  }

  // Copy the buffer from the user
  if (copy_from_user(&opts, buff, sizeof(opts))) {
    return -EFAULT;
  }

  count = send_ipi(opts.mask_low, opts.mask_high, opts.min, opts.icr.raw_icr);
  return count;
}

static const struct proc_ops proc_file_fops = {
    .proc_write = procfile_write,
};

static int __init hypercall_main(void) {
  proc_entry = proc_create(procfs_name, 0666, NULL, &proc_file_fops);
  if (NULL == proc_entry) {
    proc_remove(proc_entry);
    pr_alert("Error:Could not initialize /proc/%s\n", procfs_name);
    return -ENOMEM;
  }

  pr_info("/proc/%s created\n", procfs_name);
  return 0;
}

static void __exit hypercall_exit(void) {
  proc_remove(proc_entry);
  pr_info("/proc/%s removed\n", procfs_name);
}

module_init(hypercall_main);
module_exit(hypercall_exit);
MODULE_LICENSE("GPL");
